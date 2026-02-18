"""浏览器管理 v3.1 - 持久化上下文 + VNC登录 + Headless刷新"""
import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
from playwright.async_api import async_playwright, BrowserContext, Playwright
import pyotp
from .config import config
from .database import profile_db
from .proxy_utils import parse_proxy, format_proxy_for_playwright
from .logger import logger


# 内存优化 + 反自动化检测参数
BROWSER_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--disable-features=TranslateUI",
    "--no-first-run",
    "--no-default-browser-check",
    "--renderer-process-limit=1",  # 限制渲染进程数（比 --single-process 更隐蔽）
    "--max_old_space_size=128",
    "--js-flags=--max-old-space-size=128",
]

# VNC 登录专用参数（更少限制，更像真人浏览器）
VNC_BROWSER_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
]

# 更新到最新 Chrome 版本
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# 常见 viewport 尺寸池（按 profile_id 确定性选取）
VIEWPORT_POOL = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
    {"width": 1280, "height": 720},
    {"width": 1600, "height": 900},
    {"width": 1280, "height": 800},
    {"width": 1024, "height": 768},
]

# Stealth 脚本：隐藏 Playwright/自动化痕迹
STEALTH_JS = """
// 隐藏 navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
});

// 补全 window.chrome（Headless 模式下缺失）
if (!window.chrome) {
    window.chrome = {};
}
if (!window.chrome.runtime) {
    window.chrome.runtime = {};
}

// 伪造 plugins（Headless 默认为空）
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        return [
            {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
            {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
            {name: 'Native Client', filename: 'internal-nacl-plugin'},
        ];
    },
});

// 伪造 languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
});

// 覆盖 permissions.query 对 notifications 的响应
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications'
        ? Promise.resolve({state: Notification.permission})
        : originalQuery(parameters)
);

// 隐藏 Playwright 注入的 __playwright 等全局变量
delete window.__playwright;
delete window.__pw_manual;
"""

BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

SUPERVISOR_CONF = "/etc/supervisor/conf.d/supervisord.conf"
VNC_START_ORDER = ("xvfb", "fluxbox", "x11vnc", "novnc")
VNC_STOP_ORDER = ("novnc", "x11vnc", "fluxbox", "xvfb")


class BrowserManager:
    """浏览器管理器 - 持久化上下文"""

    def __init__(self):
        self._playwright: Optional[Playwright] = None
        self._active_context: Optional[BrowserContext] = None
        self._active_profile_id: Optional[int] = None
        self._lock = asyncio.Lock()

    async def start(self):
        """启动 Playwright"""
        if self._playwright:
            return
        logger.info("启动 Playwright...")
        self._playwright = await async_playwright().start()
        os.makedirs(config.profiles_dir, exist_ok=True)
        logger.info("Playwright 已启动")

    def _get_viewport(self, profile_id: int) -> Dict[str, int]:
        """按 profile_id 确定性选取 viewport（同一 profile 每次一致）"""
        return VIEWPORT_POOL[profile_id % len(VIEWPORT_POOL)]

    async def _inject_stealth(self, context: BrowserContext) -> None:
        """注入反自动化检测脚本"""
        try:
            await context.add_init_script(STEALTH_JS)
        except Exception as e:
            logger.warning(f"注入 stealth 脚本失败: {e}")

    @staticmethod
    async def auto_google_login(page, profile: Dict[str, Any], timeout: float = 30.0) -> bool:
        """在 Google 登录/2FA 页面自动填写凭据

        通用方法，供 Flow2API token 刷新和 gcli2api OAuth 流程共用。
        在循环中调用，每次处理一个步骤（邮箱/密码/TOTP），返回是否有操作。

        Args:
            page: Playwright page 对象
            profile: 包含 google_email, google_password, totp_secret 的 profile dict
            timeout: 不使用，保留兼容

        Returns:
            True 如果执行了某个操作，False 如果没有匹配的页面
        """
        cur_url = page.url
        if "accounts.google.com" not in cur_url:
            return False

        # 邮箱填写
        if profile.get("google_email"):
            for email_sel in ['input[type="email"]', '#identifierId']:
                el = page.locator(email_sel)
                if await el.count() > 0 and await el.first.is_visible():
                    await el.first.fill(profile["google_email"])
                    logger.info(f"[{profile['name']}] 自动填入 Google 邮箱")
                    for next_sel in ['#identifierNext', 'button:has-text("Next")', 'button:has-text("下一步")']:
                        nb = page.locator(next_sel)
                        if await nb.count() > 0 and await nb.first.is_visible():
                            await nb.first.click()
                            break
                    await asyncio.sleep(3)
                    return True

        # 密码填写
        if profile.get("google_password"):
            for pwd_sel in ['input[type="password"]', 'input[name="Passwd"]']:
                el = page.locator(pwd_sel)
                if await el.count() > 0 and await el.first.is_visible():
                    await el.first.fill(profile["google_password"])
                    logger.info(f"[{profile['name']}] 自动填入 Google 密码")
                    for next_sel in ['#passwordNext', 'button:has-text("Next")', 'button:has-text("下一步")']:
                        nb = page.locator(next_sel)
                        if await nb.count() > 0 and await nb.first.is_visible():
                            await nb.first.click()
                            break
                    await asyncio.sleep(3)
                    return True

        # TOTP 验证码填写
        if profile.get("totp_secret"):
            for totp_sel in ['input[type="tel"]', 'input[name="totpPin"]', 'input[id="totpPin"]']:
                el = page.locator(totp_sel)
                if await el.count() > 0 and await el.first.is_visible():
                    try:
                        code = pyotp.TOTP(profile["totp_secret"]).now()
                        await el.first.fill(code)
                        logger.info(f"[{profile['name']}] 自动填入 TOTP 验证码")
                        for next_sel in ['#totpNext', 'button:has-text("Next")', 'button:has-text("下一步")']:
                            nb = page.locator(next_sel)
                            if await nb.count() > 0 and await nb.first.is_visible():
                                await nb.first.click()
                                break
                        await asyncio.sleep(3)
                        return True
                    except Exception as e:
                        logger.warning(f"[{profile['name']}] TOTP 生成失败: {e}")
                    break

        return False

    async def stop(self):
        """停止"""
        await self._close_active()
        await self._stop_vnc_stack()
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    def _supervisorctl(self, *args: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
        exe = shutil.which("supervisorctl")
        if not exe:
            raise RuntimeError("supervisorctl not found")
        cmd = [exe, "-c", SUPERVISOR_CONF, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

    def _get_supervisor_status(self) -> Dict[str, str]:
        try:
            cp = self._supervisorctl("status", timeout=8.0)
        except Exception:
            return {}

        status: Dict[str, str] = {}
        for line in (cp.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                status[parts[0]] = parts[1]
        return status

    async def _ensure_vnc_stack(self) -> bool:
        if not config.enable_vnc:
            return False

        status = self._get_supervisor_status()
        for prog in VNC_START_ORDER:
            if status.get(prog) == "RUNNING":
                continue
            try:
                cp = self._supervisorctl("start", prog, timeout=20.0)
                if cp.returncode != 0:
                    logger.warning(f"启动 {prog} 失败: {(cp.stdout or '').strip()} {(cp.stderr or '').strip()}")
                    return False
            except Exception as e:
                logger.warning(f"启动 {prog} 异常: {e}")
                return False

            if prog == "xvfb":
                await asyncio.sleep(0.4)

        return True

    async def _stop_vnc_stack(self) -> None:
        if not config.enable_vnc:
            return

        for prog in VNC_STOP_ORDER:
            try:
                self._supervisorctl("stop", prog, timeout=10.0)
            except Exception:
                pass

    async def _close_active(self):
        """关闭当前浏览器"""
        if self._active_context:
            try:
                await self._persist_cookies_before_close(self._active_context)
            except Exception:
                pass
            try:
                await self._active_context.close()
            except Exception:
                pass
            self._active_context = None
            self._active_profile_id = None
            logger.info("浏览器已关闭")

    def _get_profile_dir(self, profile_id: int) -> str:
        """获取 Profile 持久化目录"""
        return os.path.join(os.path.abspath(config.profiles_dir), f"profile_{profile_id}")

    def _clean_locks(self, profile_dir: str):
        """清理 Chromium 锁文件"""
        lock_files = ["SingletonLock", "SingletonCookie", "SingletonSocket"]
        for lock in lock_files:
            lock_path = os.path.join(profile_dir, lock)
            if os.path.exists(lock_path):
                try:
                    os.remove(lock_path)
                    logger.info(f"已清理锁文件: {lock}")
                except Exception:
                    pass

    def _mask_token(self, token: str) -> str:
        if not token or len(token) <= 8:
            return token or ""
        return f"{token[:4]}...{token[-4:]}"

    async def _persist_cookies_before_close(self, context: BrowserContext) -> None:
        """在 context.close() 前，把 session cookie 转为 persistent cookie。
        
        Chromium 不会把没有 expires 的 session cookie 写入磁盘 SQLite，
        导致 close 后 cookie 丢失。这里给所有 session cookie 加上 7 天过期时间，
        让 Chromium 把它们当 persistent cookie 持久化。
        """
        try:
            all_cookies = await context.cookies()
            session_cookies = []
            expires_future = time.time() + 7 * 86400  # 7 天后

            for c in all_cookies:
                # expires == -1 或 0 或不存在 → session cookie
                exp = c.get("expires", -1)
                if exp <= 0:
                    cookie: Dict[str, Any] = {
                        "name": c["name"],
                        "value": c["value"],
                        "path": c.get("path", "/"),
                        "expires": expires_future,
                    }
                    if c.get("domain"):
                        cookie["domain"] = c["domain"]
                    if c.get("httpOnly") is not None:
                        cookie["httpOnly"] = c["httpOnly"]
                    if c.get("secure") is not None:
                        cookie["secure"] = c["secure"]
                    if c.get("sameSite"):
                        cookie["sameSite"] = c["sameSite"]
                    session_cookies.append(cookie)

            if session_cookies:
                await context.add_cookies(session_cookies)
                logger.info(f"已将 {len(session_cookies)} 个 session cookie 转为 persistent（expires +7d）")
        except Exception as e:
            logger.warning(f"持久化 session cookie 失败: {e}")

    def _read_cookies_from_sqlite(self, profile_id: int) -> Dict[str, Any]:
        """直接从 Chromium Cookie SQLite 文件读取 cookie，不启动浏览器。
        
        Linux Docker 容器里没有 keyring，Chromium 用固定 key 或不加密。
        返回 {"flow2api_token": str|None, "gemini_cookies": {"psid": ..., "psidts": ...}}
        """
        result: Dict[str, Any] = {"flow2api_token": None, "gemini_cookies": {}}
        profile_dir = self._get_profile_dir(profile_id)
        cookies_db = os.path.join(profile_dir, "Default", "Cookies")

        if not os.path.isfile(cookies_db):
            return result

        conn = None
        try:
            # 用 immutable 模式打开，避免锁冲突
            conn = sqlite3.connect(f"file:{cookies_db}?mode=ro&immutable=1", uri=True)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT host_key, name, value, encrypted_value FROM cookies "
                "WHERE (host_key LIKE '%labs.google%' OR host_key LIKE '%google.com%') "
                "AND name IN (?, '__Secure-1PSID', '__Secure-1PSIDTS')",
                (config.session_cookie_name,)
            )
            for host_key, name, value, encrypted_value in cursor.fetchall():
                # 优先用明文 value，如果为空尝试 encrypted_value
                cookie_val = value
                if not cookie_val and encrypted_value:
                    cookie_val = self._try_decrypt_cookie(encrypted_value)
                if not cookie_val:
                    continue

                if name == config.session_cookie_name and "labs.google" in host_key:
                    result["flow2api_token"] = cookie_val
                elif name == "__Secure-1PSID":
                    result["gemini_cookies"]["psid"] = cookie_val
                elif name == "__Secure-1PSIDTS":
                    result["gemini_cookies"]["psidts"] = cookie_val

        except Exception as e:
            logger.debug(f"SQLite 直读 cookie 失败: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        return result

    @staticmethod
    def _try_decrypt_cookie(encrypted_value: bytes) -> str:
        """尝试解密 Linux Chromium cookie（固定 key 'peanuts'，PBKDF2 + AES-CBC）"""
        if not encrypted_value or len(encrypted_value) < 4:
            return ""
        # v10/v11 前缀表示加密
        if encrypted_value[:3] == b"v10" or encrypted_value[:3] == b"v11":
            try:
                from hashlib import pbkdf2_hmac
                from Crypto.Cipher import AES
                key = pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, dklen=16)
                iv = b" " * 16
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_value[3:])
                # 去 PKCS7 padding
                pad_len = decrypted[-1]
                if isinstance(pad_len, int) and 0 < pad_len <= 16:
                    decrypted = decrypted[:-pad_len]
                return decrypted.decode("utf-8", errors="ignore")
            except Exception:
                return ""
        # 无前缀 → 可能是明文
        try:
            return encrypted_value.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    async def _get_proxy(self, profile: Dict[str, Any]) -> Optional[Dict]:
        """获取代理配置"""
        if profile.get("proxy_enabled") and profile.get("proxy_url"):
            proxy_config = parse_proxy(profile["proxy_url"])
            if proxy_config:
                proxy = format_proxy_for_playwright(proxy_config)
                logger.info(f"[{profile['name']}] 使用代理: {proxy['server']}")
                return proxy
        return None

    def _parse_cookies_payload(self, cookies_json: str) -> List[Dict[str, Any]]:
        data = json.loads(cookies_json)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            cookies = data.get("cookies")
            if isinstance(cookies, list):
                return cookies
        return []

    def _to_playwright_cookies(self, cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for c in cookies:
            if not isinstance(c, dict):
                continue

            name = c.get("name")
            value = c.get("value")
            if not name or value is None:
                continue

            domain = c.get("domain") or c.get("host")
            url = c.get("url")
            path = c.get("path") or "/"

            if isinstance(domain, str) and "://" in domain:
                domain = None

            cookie: Dict[str, Any] = {"name": str(name), "value": str(value)}

            if c.get("httpOnly") is not None:
                cookie["httpOnly"] = bool(c.get("httpOnly"))
            if c.get("secure") is not None:
                cookie["secure"] = bool(c.get("secure"))

            expires = c.get("expires")
            if expires is None:
                expires = c.get("expirationDate") or c.get("expiry")
            if expires is not None:
                try:
                    cookie["expires"] = float(expires)
                except (TypeError, ValueError):
                    pass

            same_site = c.get("sameSite")
            if isinstance(same_site, str):
                m = same_site.strip().lower()
                if m in {"lax"}:
                    cookie["sameSite"] = "Lax"
                elif m in {"strict"}:
                    cookie["sameSite"] = "Strict"
                elif m in {"none", "no_restriction"}:
                    cookie["sameSite"] = "None"

            if isinstance(url, str) and url.startswith("http"):
                cookie["url"] = url
            elif isinstance(domain, str) and domain:
                cookie["domain"] = domain
                cookie["path"] = str(path)
            else:
                continue

            out.append(cookie)
        return out

    async def _get_session_cookie(self, context: BrowserContext) -> Optional[str]:
        try:
            cookies = await context.cookies("https://labs.google")
        except Exception:
            cookies = await context.cookies()

        for cookie in cookies:
            if cookie.get("name") == config.session_cookie_name:
                return cookie.get("value")
        return None

    async def _get_gemini_cookies(self, context: BrowserContext) -> Dict[str, str]:
        """从浏览器上下文提取 Gemini cookie（__Secure-1PSID / __Secure-1PSIDTS）"""
        result = {}
        try:
            cookies = await context.cookies("https://gemini.google.com")
        except Exception:
            try:
                cookies = await context.cookies()
            except Exception:
                return result

        for cookie in cookies:
            name = cookie.get("name", "")
            if name == "__Secure-1PSID":
                result["psid"] = cookie.get("value", "")
            elif name == "__Secure-1PSIDTS":
                result["psidts"] = cookie.get("value", "")
        return result

    async def import_cookies(self, profile_id: int, cookies_json: str) -> Dict[str, Any]:
        """导入 Cookie（JSON），写入到持久化 profile 中"""
        if len(cookies_json) > 300_000:
            return {"success": False, "error": "Cookie 内容过大（建议只导出 labs.google 域名的 Cookie）"}

        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return {"success": False, "error": "Profile 不存在"}

            try:
                raw = self._parse_cookies_payload(cookies_json)
            except Exception as e:
                return {"success": False, "error": f"Cookie JSON 解析失败: {e}"}

            if not raw:
                return {"success": False, "error": "未识别到 Cookie 列表（请粘贴 JSON 数组或包含 cookies 字段的对象）"}

            cookies = self._to_playwright_cookies(raw)
            if not cookies:
                return {"success": False, "error": "Cookie 列表为空或格式不支持（至少需要 name/value/domain+path 或 url）"}

            context = None
            try:
                if not self._playwright:
                    await self.start()

                profile_dir = self._get_profile_dir(profile_id)
                os.makedirs(profile_dir, exist_ok=True)
                self._clean_locks(profile_dir)
                proxy = await self._get_proxy(profile)

                context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,
                    viewport=self._get_viewport(profile_id),
                    locale="en-US",
                    timezone_id="America/New_York",
                    user_agent=USER_AGENT,
                    proxy=proxy,
                    args=BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )
                await self._inject_stealth(context)

                await context.add_cookies(cookies)
                token = await self._get_session_cookie(context)

                await profile_db.update_profile(
                    profile_id,
                    is_logged_in=1 if token else 0,
                    last_token=self._mask_token(token) if token else None,
                    last_token_time=datetime.now().isoformat() if token else None,
                )

                return {
                    "success": True,
                    "imported": len(cookies),
                    "raw_count": len(raw),
                    "has_token": bool(token),
                }

            except Exception as e:
                logger.error(f"[{profile['name']}] Cookie 导入失败: {e}")
                return {"success": False, "error": str(e)}
            finally:
                if context:
                    try:
                        await self._persist_cookies_before_close(context)
                    except Exception:
                        pass
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def launch_for_login(self, profile_id: int) -> bool:
        """启动浏览器用于 VNC 登录（非 headless）"""
        if not config.enable_vnc:
            logger.warning("已禁用 VNC 登录（设置 ENABLE_VNC=1 可启用）")
            return False
        async with self._lock:
            await self._close_active()

            profile = await profile_db.get_profile(profile_id)
            if not profile:
                logger.error(f"Profile {profile_id} 不存在")
                return False

            try:
                if not self._playwright:
                    await self.start()

                ok = await self._ensure_vnc_stack()
                if not ok:
                    logger.error(f"[{profile['name']}] VNC 服务启动失败")
                    return False

                profile_dir = self._get_profile_dir(profile_id)
                os.makedirs(profile_dir, exist_ok=True)
                self._clean_locks(profile_dir)  # 清理锁文件
                proxy = await self._get_proxy(profile)

                # 非 headless，用于 VNC 登录（更少限制，更像真人浏览器）
                self._active_context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=False,  # VNC 可见
                    viewport=self._get_viewport(profile_id),
                    locale="en-US",
                    timezone_id="America/New_York",
                    user_agent=USER_AGENT,
                    proxy=proxy,
                    args=VNC_BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )
                await self._inject_stealth(self._active_context)
                self._active_profile_id = profile_id

                page = self._active_context.pages[0] if self._active_context.pages else await self._active_context.new_page()
                await page.goto(config.login_url, wait_until="networkidle")

                # 如果配置了 Gemini API，也打开 gemini.google.com 让用户顺便登录
                if config.gemini_api_url:
                    try:
                        gemini_page = await self._active_context.new_page()
                        await gemini_page.goto(config.gemini_login_url, wait_until="domcontentloaded", timeout=30000)
                        logger.info(f"[{profile['name']}] 已打开 Gemini 页面，请在 VNC 中同时完成登录")
                    except Exception as e:
                        logger.warning(f"[{profile['name']}] 打开 Gemini 页面失败: {e}")

                logger.info(f"[{profile['name']}] 浏览器已启动，请通过 VNC 登录")
                return True

            except Exception as e:
                logger.error(f"[{profile['name']}] 启动失败: {e}")
                return False

    async def close_browser(self, profile_id: int) -> Dict[str, Any]:
        """关闭浏览器并保存状态"""
        async with self._lock:
            if self._active_profile_id != profile_id:
                return {"success": False, "error": "该 Profile 浏览器未运行"}

            if self._active_context:
                # 检查 labs.google 登录状态
                is_logged_in = False
                try:
                    cookies = await self._active_context.cookies("https://labs.google")
                    is_logged_in = any(c["name"] == config.session_cookie_name for c in cookies)
                except Exception:
                    pass

                # 检查 gemini 登录状态
                gemini_logged_in = False
                try:
                    gemini_cookies = await self._get_gemini_cookies(self._active_context)
                    gemini_logged_in = bool(gemini_cookies.get("psid"))
                except Exception:
                    pass

                await profile_db.update_profile(profile_id, is_logged_in=int(is_logged_in or gemini_logged_in))
                await self._close_active()
                await self._stop_vnc_stack()

                status_parts = []
                if is_logged_in:
                    status_parts.append("Labs 已登录")
                if gemini_logged_in:
                    status_parts.append("Gemini 已登录")
                status = ", ".join(status_parts) if status_parts else "未登录"
                logger.info(f"Profile {profile_id} 浏览器已关闭，状态: {status}")
                return {"success": True, "is_logged_in": is_logged_in or gemini_logged_in}

            return {"success": True}

    async def extract_token(self, profile_id: int) -> Dict[str, Any]:
        """提取 Token（Headless 模式，使用持久化上下文）
        
        优先尝试直接读取 SQLite cookie 文件（不启动浏览器），
        失败时 fallback 到 headless 浏览器提取。
        
        Returns:
            {"flow2api_token": str|None, "gemini_cookies": {"psid": str, "psidts": str}|{}}
        """
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return {"flow2api_token": None, "gemini_cookies": {}}

            profile_dir = self._get_profile_dir(profile_id)

            # 检查是否有持久化数据
            if not os.path.exists(profile_dir):
                logger.warning(f"[{profile['name']}] 无持久化数据，请先登录")
                return {"flow2api_token": None, "gemini_cookies": {}}

            # 如果当前 profile 浏览器正在运行（VNC 登录中），直接提取
            if self._active_profile_id == profile_id and self._active_context:
                return await self._extract_from_context(profile, self._active_context)

            # 第一层：尝试直接读 SQLite cookie 文件（不启动浏览器，零风险）
            sqlite_result = self._read_cookies_from_sqlite(profile_id)
            has_flow2api = bool(sqlite_result.get("flow2api_token"))
            has_gemini = bool(
                sqlite_result.get("gemini_cookies", {}).get("psid")
                and sqlite_result.get("gemini_cookies", {}).get("psidts")
            )
            if has_flow2api or has_gemini:
                logger.info(f"[{profile['name']}] SQLite 直读成功 (flow2api={has_flow2api}, gemini={has_gemini})")
                if has_flow2api:
                    await profile_db.update_profile(
                        profile_id,
                        is_logged_in=1,
                        last_token=self._mask_token(sqlite_result["flow2api_token"]),
                        last_token_time=datetime.now().isoformat(),
                    )
                return sqlite_result

            logger.info(f"[{profile['name']}] SQLite 直读无结果，fallback 到 headless 浏览器...")

            # 第二层：fallback 到 headless 浏览器提取
            context = None
            try:
                if not self._playwright:
                    await self.start()

                profile_dir = self._get_profile_dir(profile_id)
                self._clean_locks(profile_dir)  # 清理锁文件
                proxy = await self._get_proxy(profile)

                logger.info(f"[{profile['name']}] Headless 模式提取 Token...")

                # Headless + 持久化上下文
                context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,  # Headless 省资源
                    viewport=self._get_viewport(profile_id),
                    locale="en-US",
                    timezone_id="America/New_York",
                    user_agent=USER_AGENT,
                    proxy=proxy,
                    args=BROWSER_ARGS,  # 完整内存优化 + 反检测参数
                    ignore_default_args=["--enable-automation"],
                )
                await self._inject_stealth(context)

                result = await self._extract_from_context(profile, context)
                return result

            except Exception as e:
                logger.error(f"[{profile['name']}] 提取失败: {e}")
                return {"flow2api_token": None, "gemini_cookies": {}}
            finally:
                if context:
                    try:
                        await self._persist_cookies_before_close(context)
                    except Exception:
                        pass
                    try:
                        await context.close()
                    except Exception:
                        pass
                    logger.info(f"[{profile['name']}] Headless 浏览器已关闭")

    async def _extract_from_context(self, profile: Dict[str, Any], context: BrowserContext) -> Dict[str, Any]:
        """从上下文提取 Token（通过 signin 页面刷新 session）+ Gemini Cookie"""
        page = None
        result = {"flow2api_token": None, "gemini_cookies": {}}
        try:
            page = await context.new_page()

            async def _route(route, request):
                try:
                    if request.resource_type in BLOCKED_RESOURCE_TYPES:
                        await route.abort()
                    else:
                        await route.continue_()
                except Exception:
                    try:
                        await route.continue_()
                    except Exception:
                        pass

            try:
                await page.route("**/*", _route)
            except Exception:
                pass

            # 访问 signin 页面并点击 Sign in with Google 按钮刷新 session
            logger.info(f"[{profile['name']}] 访问 {config.login_url} 刷新 session...")
            await page.goto(config.login_url, wait_until="domcontentloaded", timeout=60000)

            # 点击 Sign in with Google 按钮（提交 POST 表单）
            try:
                submit_btn = page.locator("button[type='submit']")
                await submit_btn.wait_for(state="visible", timeout=10000)
                await submit_btn.click()
                logger.info(f"[{profile['name']}] 已点击 Sign in with Google，等待跳转...")
            except Exception as e:
                logger.warning(f"[{profile['name']}] 点击登录按钮失败: {e}，尝试直接检查 cookie")

            # 等待跳转到 https://labs.google/ 并提取 cookie
            # 如果跳到了 accounts.google.com，尝试自动登录
            try:
                await page.wait_for_url("https://labs.google/**", timeout=30000)
                logger.info(f"[{profile['name']}] 已成功跳转到 labs.google")
            except Exception as e:
                logger.warning(f"[{profile['name']}] 等待跳转超时: {e}")
                # 检查是否在 Google 登录页面，尝试自动登录
                if "accounts.google.com" in page.url and (
                    profile.get("google_email") or profile.get("google_password") or profile.get("totp_secret")
                ):
                    logger.info(f"[{profile['name']}] 检测到 Google 登录页面，尝试自动登录...")
                    login_deadline = asyncio.get_running_loop().time() + 45.0
                    while asyncio.get_running_loop().time() < login_deadline:
                        if "accounts.google.com" not in page.url:
                            break
                        acted = await self.auto_google_login(page, profile)
                        if not acted:
                            await asyncio.sleep(1)
                    # 登录完成后等待跳转回 labs.google
                    try:
                        await page.wait_for_url("https://labs.google/**", timeout=15000)
                        logger.info(f"[{profile['name']}] 自动登录后成功跳转到 labs.google")
                    except Exception:
                        logger.warning(f"[{profile['name']}] 自动登录后仍未跳转到 labs.google")

            # 等待 cookie 更新：优先轮询 session cookie，减少资源占用
            token = None
            deadline = asyncio.get_running_loop().time() + 12.0
            while asyncio.get_running_loop().time() < deadline:
                token = await self._get_session_cookie(context)
                if token:
                    break
                await asyncio.sleep(0.5)

            if not token:
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                token = await self._get_session_cookie(context)

            if token:
                await profile_db.update_profile(
                    profile["id"],
                    is_logged_in=1,
                    last_token=self._mask_token(token),
                    last_token_time=datetime.now().isoformat(),
                )
                logger.info(f"[{profile['name']}] Flow2API Token 提取成功")
                result["flow2api_token"] = token
            else:
                logger.warning(f"[{profile['name']}] 未找到 Flow2API Token")

            # 提取 Gemini Cookie（如果配置了 Gemini API）
            if config.gemini_api_url:
                try:
                    # 先访问 gemini.google.com 刷新 cookie
                    await page.goto(config.gemini_login_url, wait_until="domcontentloaded", timeout=30000)
                    # 轮询等待 __Secure-1PSID 和 __Secure-1PSIDTS 都出现
                    gemini_cookies = {}
                    gemini_deadline = asyncio.get_running_loop().time() + 15.0
                    while asyncio.get_running_loop().time() < gemini_deadline:
                        gemini_cookies = await self._get_gemini_cookies(context)
                        if gemini_cookies.get("psid") and gemini_cookies.get("psidts"):
                            break
                        await asyncio.sleep(1)

                    # 最后再试一次
                    if not (gemini_cookies.get("psid") and gemini_cookies.get("psidts")):
                        try:
                            await page.wait_for_load_state("networkidle", timeout=8000)
                        except Exception:
                            pass
                        gemini_cookies = await self._get_gemini_cookies(context)

                except Exception as e:
                    logger.warning(f"[{profile['name']}] 访问 Gemini 页面失败: {e}")
                    gemini_cookies = {}

                if gemini_cookies.get("psid") and gemini_cookies.get("psidts"):
                    result["gemini_cookies"] = gemini_cookies
                    logger.info(f"[{profile['name']}] Gemini Cookie 提取成功 (PSID: {self._mask_token(gemini_cookies['psid'])})")
                elif gemini_cookies.get("psid"):
                    logger.warning(f"[{profile['name']}] 只找到 __Secure-1PSID，缺少 __Secure-1PSIDTS，跳过推送")
                else:
                    logger.warning(f"[{profile['name']}] 未找到 Gemini Cookie")

            # 更新登录状态
            has_any_token = bool(result["flow2api_token"]) or bool(result["gemini_cookies"].get("psid"))
            if not has_any_token:
                await profile_db.update_profile(profile["id"], is_logged_in=0)
                logger.warning(f"[{profile['name']}] 未找到任何 Token，会话可能已过期")

            return result

        except Exception as e:
            logger.error(f"[{profile['name']}] 提取异常: {e}")
            return result
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass

    async def check_login_status(self, profile_id: int) -> Dict[str, Any]:
        """检查登录状态（单次浏览器启动，同时检查两种 cookie）"""
        profile = await profile_db.get_profile(profile_id)
        if not profile:
            return {"success": False, "error": "Profile 不存在"}

        has_flow2api = False
        has_gemini = False

        async with self._lock:
            profile_dir = self._get_profile_dir(profile_id)
            if not os.path.exists(profile_dir):
                await profile_db.update_profile(profile_id, is_logged_in=0)
                return {
                    "success": True, "is_logged_in": False,
                    "has_flow2api_token": False, "has_gemini_cookie": False,
                    "profile_name": profile["name"]
                }

            # 如果当前 profile 浏览器正在运行，直接读取
            if self._active_profile_id == profile_id and self._active_context:
                has_flow2api = bool(await self._get_session_cookie(self._active_context))
                gemini_cookies = await self._get_gemini_cookies(self._active_context)
                has_gemini = bool(gemini_cookies.get("psid"))
            else:
                # 单次启动 headless 浏览器，同时检查两种 cookie
                context = None
                try:
                    if not self._playwright:
                        await self.start()
                    self._clean_locks(profile_dir)
                    proxy = await self._get_proxy(profile)
                    context = await self._playwright.chromium.launch_persistent_context(
                        user_data_dir=profile_dir,
                        headless=True,
                        viewport=self._get_viewport(profile_id),
                        locale="en-US",
                        timezone_id="America/New_York",
                        user_agent=USER_AGENT,
                        proxy=proxy,
                        args=BROWSER_ARGS,
                        ignore_default_args=["--enable-automation"],
                    )
                    await self._inject_stealth(context)
                    has_flow2api = bool(await self._get_session_cookie(context))
                    gemini_cookies = await self._get_gemini_cookies(context)
                    has_gemini = bool(gemini_cookies.get("psid"))
                except Exception:
                    pass
                finally:
                    if context:
                        try:
                            await self._persist_cookies_before_close(context)
                        except Exception:
                            pass
                        try:
                            await context.close()
                        except Exception:
                            pass

        is_logged_in = has_flow2api or has_gemini
        await profile_db.update_profile(profile_id, is_logged_in=1 if is_logged_in else 0)
        return {
            "success": True,
            "is_logged_in": is_logged_in,
            "has_flow2api_token": has_flow2api,
            "has_gemini_cookie": has_gemini,
            "profile_name": profile["name"]
        }

    async def peek_token(self, profile_id: int) -> Optional[str]:
        """轻量获取 token（不访问页面，仅读取 cookie）"""
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return None

            profile_dir = self._get_profile_dir(profile_id)
            if not os.path.exists(profile_dir):
                return None

            if self._active_profile_id == profile_id and self._active_context:
                return await self._get_session_cookie(self._active_context)

            context = None
            try:
                if not self._playwright:
                    await self.start()

                self._clean_locks(profile_dir)
                proxy = await self._get_proxy(profile)
                context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,
                    viewport=self._get_viewport(profile_id),
                    locale="en-US",
                    timezone_id="America/New_York",
                    user_agent=USER_AGENT,
                    proxy=proxy,
                    args=BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )
                await self._inject_stealth(context)
                return await self._get_session_cookie(context)
            except Exception:
                return None
            finally:
                if context:
                    try:
                        await self._persist_cookies_before_close(context)
                    except Exception:
                        pass
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def peek_gemini_cookies(self, profile_id: int) -> Dict[str, str]:
        """轻量获取 Gemini cookie（不访问页面，仅读取 cookie）"""
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return {}

            profile_dir = self._get_profile_dir(profile_id)
            if not os.path.exists(profile_dir):
                return {}

            if self._active_profile_id == profile_id and self._active_context:
                return await self._get_gemini_cookies(self._active_context)

            context = None
            try:
                if not self._playwright:
                    await self.start()

                self._clean_locks(profile_dir)
                proxy = await self._get_proxy(profile)
                context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,
                    viewport=self._get_viewport(profile_id),
                    locale="en-US",
                    timezone_id="America/New_York",
                    user_agent=USER_AGENT,
                    proxy=proxy,
                    args=BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )
                await self._inject_stealth(context)
                return await self._get_gemini_cookies(context)
            except Exception:
                return {}
            finally:
                if context:
                    try:
                        await self._persist_cookies_before_close(context)
                    except Exception:
                        pass
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def delete_profile_data(self, profile_id: int):
        """删除 profile 数据"""
        profile_dir = self._get_profile_dir(profile_id)
        if os.path.exists(profile_dir):
            shutil.rmtree(profile_dir)
            logger.info(f"已删除: {profile_dir}")

    def get_active_profile_id(self) -> Optional[int]:
        return self._active_profile_id

    def get_status(self) -> Dict[str, Any]:
        status = self._get_supervisor_status()
        vnc_stack_running = all(status.get(p) == "RUNNING" for p in ("xvfb", "x11vnc", "novnc")) if status else False
        return {
            "is_running": self._playwright is not None,
            "active_profile_id": self._active_profile_id,
            "has_active_browser": self._active_context is not None,
            "profiles_dir": config.profiles_dir,
            "enable_vnc": bool(config.enable_vnc),
            "vnc_stack_running": bool(vnc_stack_running),
        }


browser_manager = BrowserManager()
