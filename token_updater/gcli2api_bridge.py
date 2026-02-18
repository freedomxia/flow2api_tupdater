"""gcli2api 凭证桥接 - 利用已有 Google 登录态自动完成 gcli2api OAuth 授权"""
import asyncio
import httpx
from typing import Optional, Dict, Any
from .config import config
from .browser import browser_manager, BrowserManager
from .database import profile_db
from .logger import logger

# 内部通信不走代理
_NO_PROXY_CLIENT = {"proxies": {}}


class Gcli2apiBridge:
    """通过 Playwright Profile 的 Google 登录态，自动完成 gcli2api OAuth 流程"""

    def __init__(self):
        self._sync_count = 0
        self._error_count = 0

    async def sync_profile_to_gcli2api(
        self, profile_id: int, mode: str = "geminicli"
    ) -> Dict[str, Any]:
        """用指定 profile 的 Google 登录态完成 gcli2api OAuth 授权

        Args:
            profile_id: Profile ID
            mode: 凭证模式 - "geminicli" 或 "antigravity"

        流程:
        1. 调用 gcli2api /auth/start 获取 OAuth URL
        2. 用 Playwright headless 浏览器（带已有登录态）访问 OAuth URL
        3. 自动同意授权，捕获 redirect 中的 authorization code
        4. 将 code 提交给 gcli2api /auth/callback-url
        """
        gcli2api_url = config.gcli2api_url
        gcli2api_password = config.gcli2api_password
        if not gcli2api_url:
            return {"success": False, "error": "未配置 GCLI2API_URL"}

        profile = await profile_db.get_profile(profile_id)
        if not profile:
            return {"success": False, "error": "Profile 不存在"}

        mode_label = "Antigravity" if mode == "antigravity" else "GeminiCLI"
        logger.info(f"[gcli2api][{profile['name']}] 开始 {mode_label} OAuth 授权...")

        try:
            # 1. 登录 gcli2api 获取 token
            auth_token = await self._login_gcli2api(gcli2api_url, gcli2api_password)
            if not auth_token:
                return {"success": False, "error": "gcli2api 登录失败"}

            # 2. 启动 OAuth 流程（传入 mode）
            auth_info = await self._start_oauth(gcli2api_url, auth_token, mode=mode)
            if not auth_info:
                return {"success": False, "error": f"gcli2api {mode_label} OAuth 启动失败"}

            auth_url = auth_info["auth_url"]
            logger.info(f"[gcli2api][{profile['name']}] 获取到 {mode_label} OAuth URL，开始自动授权...")

            # 3. 用 Playwright 自动完成 OAuth
            code_result = await self._auto_oauth_with_profile(profile_id, profile, auth_url)
            if not code_result.get("success"):
                return code_result

            callback_url = code_result["callback_url"]
            logger.info(f"[gcli2api][{profile['name']}] 获取到回调 URL，提交给 gcli2api...")

            # 4. 提交 callback-url（传入 mode）
            callback_result = await self._submit_callback_url(
                gcli2api_url, auth_token, callback_url, mode=mode
            )

            if callback_result.get("success"):
                self._sync_count += 1
                logger.info(f"[gcli2api][{profile['name']}] {mode_label} OAuth 授权成功!")
            else:
                self._error_count += 1
                logger.error(f"[gcli2api][{profile['name']}] {mode_label} OAuth 回调失败: {callback_result.get('error')}")

            return callback_result

        except Exception as e:
            self._error_count += 1
            logger.error(f"[gcli2api][{profile['name']}] {mode_label} 异常: {e}")
            return {"success": False, "error": str(e)}

    async def sync_profile_both_modes(self, profile_id: int) -> Dict[str, Any]:
        """同时同步 geminicli 和 antigravity 两种模式"""
        results = {}
        for mode in ("geminicli", "antigravity"):
            results[mode] = await self.sync_profile_to_gcli2api(profile_id, mode=mode)
        success = any(r.get("success") for r in results.values())
        return {"success": success, "results": results}

    async def sync_all_to_gcli2api(self, mode: str = "geminicli") -> Dict[str, Any]:
        """同步所有已登录 profile 到 gcli2api

        Args:
            mode: "geminicli", "antigravity", 或 "both"（同时同步两种模式）
        """
        if not config.gcli2api_url:
            return {"success": False, "error": "未配置 GCLI2API_URL"}

        profiles = await profile_db.get_logged_in_profiles()
        if not profiles:
            return {"success": True, "total": 0, "message": "没有已登录的 Profile"}

        results = []
        success_count = 0
        for p in profiles:
            if mode == "both":
                result = await self.sync_profile_both_modes(p["id"])
            else:
                result = await self.sync_profile_to_gcli2api(p["id"], mode=mode)
            results.append({"profile_id": p["id"], "name": p["name"], **result})
            if result.get("success"):
                success_count += 1

        return {
            "success": success_count > 0,
            "total": len(profiles),
            "success_count": success_count,
            "error_count": len(profiles) - success_count,
            "results": results,
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "gcli2api_url": config.gcli2api_url or "",
            "enabled": bool(config.gcli2api_url),
            "sync_count": self._sync_count,
            "error_count": self._error_count,
        }

    # ── 内部方法 ──

    async def _login_gcli2api(self, base_url: str, password: str) -> Optional[str]:
        """登录 gcli2api 获取 auth token"""
        try:
            async with httpx.AsyncClient(timeout=15, **_NO_PROXY_CLIENT) as client:
                resp = await client.post(
                    f"{base_url}/auth/login",
                    json={"password": password},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("token")
                logger.error(f"[gcli2api] 登录失败: HTTP {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"[gcli2api] 登录异常: {e}")
            return None

    async def _start_oauth(self, base_url: str, auth_token: str, mode: str = "geminicli") -> Optional[Dict]:
        """调用 gcli2api /auth/start 获取 OAuth URL"""
        try:
            async with httpx.AsyncClient(timeout=15, **_NO_PROXY_CLIENT) as client:
                resp = await client.post(
                    f"{base_url}/auth/start",
                    json={"mode": mode},
                    headers={"Authorization": f"Bearer {auth_token}"},
                )
                if resp.status_code == 200:
                    return resp.json()
                logger.error(f"[gcli2api] /auth/start 失败: HTTP {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"[gcli2api] /auth/start 异常: {e}")
            return None

    async def _auto_oauth_with_profile(
        self, profile_id: int, profile: Dict, auth_url: str
    ) -> Dict[str, Any]:
        """用 Playwright headless 浏览器自动完成 Google OAuth 授权

        核心思路：在容器内启动一个临时 HTTP 服务器监听 11451-11470 端口，
        这样 Google OAuth redirect 到 localhost:PORT 时能被我们接住，
        从而拿到完整的 callback URL（含 code 和 state）。
        """
        context = None
        temp_server = None
        temp_server_port = None
        try:
            if not browser_manager._playwright:
                await browser_manager.start()

            profile_dir = browser_manager._get_profile_dir(profile_id)
            browser_manager._clean_locks(profile_dir)
            proxy = await browser_manager._get_proxy(profile)

            from .browser import BROWSER_ARGS, USER_AGENT, STEALTH_JS

            # 从 auth_url 中解析出 redirect_uri 的端口
            import re
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(auth_url)
            qs = parse_qs(parsed.query)
            redirect_uri = qs.get("redirect_uri", [""])[0]
            callback_port = 11451  # 默认
            if redirect_uri:
                try:
                    callback_port = int(urlparse(redirect_uri).port or 11451)
                except (ValueError, TypeError):
                    callback_port = 11451
            logger.info(f"[gcli2api][{profile['name']}] OAuth 回调端口: {callback_port}")

            # 启动临时 HTTP 服务器来接收 OAuth 回调
            captured_url: Dict[str, str] = {}
            temp_server, temp_server_port = await self._start_callback_server(
                callback_port, captured_url, profile["name"]
            )

            context = await browser_manager._playwright.chromium.launch_persistent_context(
                user_data_dir=profile_dir,
                headless=True,
                viewport=browser_manager._get_viewport(profile_id),
                locale="en-US",
                timezone_id="America/New_York",
                user_agent=USER_AGENT,
                proxy=proxy,
                args=BROWSER_ARGS,
                ignore_default_args=["--enable-automation"],
            )
            await browser_manager._inject_stealth(context)

            page = await context.new_page()

            # 访问 OAuth URL
            try:
                await page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass

            deadline = asyncio.get_running_loop().time() + 60.0
            last_url = ""
            while asyncio.get_running_loop().time() < deadline:
                if captured_url.get("url"):
                    break

                try:
                    cur_url = page.url

                    if cur_url != last_url:
                        logger.info(f"[gcli2api][{profile['name']}] 当前页面: {cur_url[:120]}")
                        last_url = cur_url

                    # 检查是否已经到达回调页面（临时服务器会返回成功页面）
                    if f"localhost:{temp_server_port}" in cur_url:
                        if not captured_url.get("url"):
                            captured_url["url"] = cur_url
                        break

                    clicked = False

                    # 0. Google 登录/密码/TOTP 页面 - 调用公共自动登录方法
                    if not clicked and "accounts.google.com" in cur_url:
                        if profile.get("google_email") or profile.get("google_password") or profile.get("totp_secret"):
                            clicked = await BrowserManager.auto_google_login(page, profile)
                        # 如果在 challenge 页面（TOTP/验证）但没有凭据，跳过后续步骤避免误点
                        if not clicked and "/signin/challenge" in cur_url:
                            logger.debug(f"[gcli2api][{profile['name']}] 在验证页面但无自动登录凭据，等待...")
                            await asyncio.sleep(2)
                            continue

                    # 1. "未验证应用" 警告页面处理（最高优先级）
                    if not clicked:
                        for unsafe_sel in [
                            # "Go to xxx (unsafe)" / "前往 xxx（不安全）" 链接
                            'a[id="proceed-link"]',
                            'a:has-text("Go to")',
                            'a:has-text("前往")',
                            'a:has-text("unsafe")',
                            'a:has-text("不安全")',
                            # "Advanced" / "高级" 展开按钮
                            'a:has-text("Advanced")',
                            'a:has-text("高级")',
                            '#details-button',
                            'a:has-text("Show")',
                            'a:has-text("显示")',
                            # 复选框（某些 scope 需要勾选）
                            'input[type="checkbox"]:not(:checked)',
                        ]:
                            el = page.locator(unsafe_sel)
                            if await el.count() > 0 and await el.first.is_visible():
                                await el.first.click()
                                logger.info(f"[gcli2api][{profile['name']}] 点击了安全警告: {unsafe_sel}")
                                clicked = True
                                await asyncio.sleep(2)
                                break

                    # 2. 同意/允许按钮
                    if not clicked:
                        for selector in [
                            'button[id="submit_approve_access"]',
                            '#submit_approve_access',
                            'button:has-text("Sign in")',
                            'button:has-text("登录")',
                            'button:has-text("Allow")',
                            'button:has-text("允许")',
                            'button:has-text("Continue")',
                            'button:has-text("继续")',
                            'button:has-text("Grant")',
                            'button:has-text("Agree")',
                            'button:has-text("Accept")',
                            'input[type="submit"][value="Allow"]',
                            'input[type="submit"][value="允许"]',
                            '#oauthScopeDialog button',
                            'button[jsname="LgbsSe"]',
                            'div[role="button"]:has-text("Allow")',
                            'div[role="button"]:has-text("Continue")',
                            'div[role="button"]:has-text("Sign in")',
                        ]:
                            btn = page.locator(selector)
                            if await btn.count() > 0 and await btn.first.is_visible():
                                await btn.first.click()
                                logger.info(f"[gcli2api][{profile['name']}] 点击了: {selector}")
                                clicked = True
                                await asyncio.sleep(2)
                                break

                    # 3. 选择账号页面（最低优先级，仅在无其他可点击元素时）
                    if not clicked:
                        for account_sel in [
                            'div[data-email]',
                            'li[data-email]',
                            'div[data-identifier]',
                            'div.JDAKTe',
                        ]:
                            el = page.locator(account_sel)
                            if await el.count() > 0 and await el.first.is_visible():
                                await el.first.click()
                                logger.info(f"[gcli2api][{profile['name']}] 点击了账号选择: {account_sel}")
                                clicked = True
                                await asyncio.sleep(2)
                                break

                except Exception as e:
                    logger.debug(f"[gcli2api][{profile['name']}] 页面交互异常: {e}")

                await asyncio.sleep(1)

            if captured_url.get("url"):
                logger.info(f"[gcli2api][{profile['name']}] 成功捕获回调 URL!")
                return {"success": True, "callback_url": captured_url["url"]}
            else:
                # 截图保存用于调试
                try:
                    screenshot_path = f"/app/logs/gcli2api_oauth_fail_{profile_id}.png"
                    await page.screenshot(path=screenshot_path)
                    logger.error(f"[gcli2api][{profile['name']}] OAuth 失败截图: {screenshot_path}")
                    logger.error(f"[gcli2api][{profile['name']}] 最终页面 URL: {page.url}")
                    logger.error(f"[gcli2api][{profile['name']}] 页面标题: {await page.title()}")
                except Exception:
                    pass
                return {"success": False, "error": "未能获取授权码，可能需要手动登录 Google 或检查账号密码/TOTP配置"}

        except Exception as e:
            logger.error(f"[gcli2api][{profile['name']}] 浏览器自动授权失败: {e}")
            return {"success": False, "error": str(e)}
        finally:
            if temp_server:
                temp_server.shutdown()
                temp_server.server_close()
                logger.info(f"[gcli2api] 临时回调服务器已关闭 (port={temp_server_port})")
            if context:
                try:
                    await context.close()
                except Exception:
                    pass


    async def _start_callback_server(
        self, target_port: int, captured_url: Dict[str, str], profile_name: str
    ) -> tuple:
        """启动临时 HTTP 服务器来接收 OAuth 回调"""
        import threading
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import socket

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                full_url = f"http://localhost:{target_port}{self.path}"
                captured_url["url"] = full_url
                logger.info(f"[gcli2api][{profile_name}] [server] 收到回调: {full_url[:120]}")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body><h2>OAuth OK</h2><p>You can close this page.</p></body></html>")

            def log_message(self, format, *args):
                pass

        # 先强制释放目标端口
        def _kill_port(port: int):
            """扫描 /proc/net/tcp 找到占用端口的进程并 kill（纯 Python，无需外部命令）"""
            import os, signal, struct
            hex_port = f"{port:04X}"
            target_pids = set()
            my_pid = os.getpid()
            # 扫描所有进程的 fd，找到绑定目标端口的 socket
            try:
                # 方法1: 解析 /proc/net/tcp 找到 inode
                target_inodes = set()
                for tcp_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
                    try:
                        with open(tcp_file) as f:
                            for line in f.readlines()[1:]:
                                parts = line.split()
                                local_addr = parts[1]
                                local_port_hex = local_addr.split(":")[1]
                                if local_port_hex == hex_port:
                                    inode = parts[9]
                                    target_inodes.add(inode)
                    except (FileNotFoundError, IndexError):
                        continue

                if target_inodes:
                    # 扫描 /proc/*/fd 找到持有这些 inode 的进程
                    for pid_str in os.listdir("/proc"):
                        if not pid_str.isdigit():
                            continue
                        pid = int(pid_str)
                        if pid == my_pid or pid == 1:
                            continue
                        fd_dir = f"/proc/{pid}/fd"
                        try:
                            for fd in os.listdir(fd_dir):
                                try:
                                    link = os.readlink(f"{fd_dir}/{fd}")
                                    if link.startswith("socket:["):
                                        inode = link[8:-1]
                                        if inode in target_inodes:
                                            target_pids.add(pid)
                                except (OSError, ValueError):
                                    continue
                        except PermissionError:
                            continue
            except Exception:
                pass

            for pid in target_pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                    logger.info(f"[gcli2api] 已杀掉占用端口 {port} 的进程 PID={pid}")
                except ProcessLookupError:
                    pass

        for attempt in range(5):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", target_port)) != 0:
                    break  # 端口空闲
            logger.info(f"[gcli2api][{profile_name}] 端口 {target_port} 被占用，尝试释放 (attempt {attempt+1})")
            _kill_port(target_port)
            await asyncio.sleep(1)

        # 用自定义子类让 SO_REUSEADDR 在 bind() 之前生效
        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True
            allow_reuse_port = True

        try:
            server = ReusableHTTPServer(("127.0.0.1", target_port), CallbackHandler)
        except OSError as e:
            logger.error(
                f"[gcli2api][{profile_name}] 无法绑定到端口 {target_port}: {e}"
            )
            raise RuntimeError(
                f"端口 {target_port} 被占用且无法释放，OAuth 回调需要此端口。"
                f"请稍后重试或手动释放端口。"
            )

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"[gcli2api][{profile_name}] 临时回调服务器已启动: localhost:{target_port}")

        return server, target_port


    async def _submit_callback_url(
        self, base_url: str, auth_token: str, callback_url: str, mode: str = "geminicli"
    ) -> Dict[str, Any]:
        """将完整回调 URL 提交给 gcli2api /auth/callback-url"""
        try:
            async with httpx.AsyncClient(timeout=30, **_NO_PROXY_CLIENT) as client:
                resp = await client.post(
                    f"{base_url}/auth/callback-url",
                    json={"callback_url": callback_url, "mode": mode},
                    headers={"Authorization": f"Bearer {auth_token}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {"success": True, "data": data}
                else:
                    body = resp.text[:200]
                    return {"success": False, "error": f"HTTP {resp.status_code}: {body}"}
        except Exception as e:
            return {"success": False, "error": str(e)}


gcli2api_bridge = Gcli2apiBridge()
