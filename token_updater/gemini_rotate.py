"""Gemini RotateCookies - 纯 HTTP 刷新 __Secure-1PSIDTS"""
import re
import httpx
from typing import Optional, Dict, List
from .logger import logger


async def rotate_psidts(
    cookies: List[Dict],
    proxy: Optional[str] = None,
) -> Optional[str]:
    """
    用 Google RotateCookies 机制刷新 __Secure-1PSIDTS。

    Args:
        cookies: Playwright 格式的 cookie 列表（从 saved_cookies.json 读取）
        proxy: 代理地址，如 "http://host:port"

    Returns:
        新的 __Secure-1PSIDTS 值，失败返回 None
    """
    # 构建 cookie header
    cookie_header = _build_cookie_header(cookies, ".google.com")
    if not cookie_header:
        logger.debug("[RotateCookies] 无可用 cookie")
        return None

    transport = httpx.AsyncHTTPTransport(proxy=proxy) if proxy else None

    try:
        async with httpx.AsyncClient(
            timeout=30,
            transport=transport,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36",
            },
        ) as client:
            # 1. 访问 gemini 页面，解析 rotate 参数
            resp = await client.get(
                "https://gemini.google.com/",
                headers={"Cookie": cookie_header},
            )
            if resp.status_code != 200:
                logger.warning(f"[RotateCookies] 访问 Gemini 页面失败: HTTP {resp.status_code}")
                return None

            params = _parse_rotate_params(resp.text)
            if not params:
                logger.warning("[RotateCookies] 未能从页面解析 rotate 参数")
                return None

            og_pid, rot, exp_id = params
            logger.info(f"[RotateCookies] 解析到参数 og_pid={og_pid[:8]}...")

            # 2. 请求 RotateCookiesPage 获取 init_value
            rotate_page_resp = await client.post(
                "https://accounts.google.com/RotateCookiesPage",
                headers={"Cookie": cookie_header, "Content-Type": "application/x-www-form-urlencoded"},
                data={"og_pid": og_pid, "rot": rot, "exp_id": exp_id},
            )
            if rotate_page_resp.status_code != 200:
                logger.warning(f"[RotateCookies] RotateCookiesPage 失败: HTTP {rotate_page_resp.status_code}")
                return None

            init_value = _parse_init_value(rotate_page_resp.text)
            if not init_value:
                logger.warning("[RotateCookies] 未能解析 init_value")
                return None

            logger.info(f"[RotateCookies] 获取到 init_value={init_value[:8]}...")

            # 3. 请求 RotateCookies 获取新的 __Secure-1PSIDTS
            rotate_resp = await client.post(
                "https://accounts.google.com/RotateCookies",
                headers={"Cookie": cookie_header, "Content-Type": "application/x-www-form-urlencoded"},
                data={"og_pid": og_pid, "init_value": init_value},
            )
            if rotate_resp.status_code != 200:
                logger.warning(f"[RotateCookies] RotateCookies 失败: HTTP {rotate_resp.status_code}")
                return None

            # 从 Set-Cookie 提取新的 __Secure-1PSIDTS
            new_psidts = _extract_psidts_from_response(rotate_resp)
            if new_psidts:
                logger.info(f"[RotateCookies] 成功获取新的 __Secure-1PSIDTS: {new_psidts[:8]}...")
            else:
                logger.warning("[RotateCookies] 响应中未找到 __Secure-1PSIDTS")

            return new_psidts

    except Exception as e:
        logger.warning(f"[RotateCookies] 异常: {e}")
        return None


def _build_cookie_header(cookies: List[Dict], domain_filter: str) -> str:
    """从 cookie 列表构建 Cookie header（只包含匹配域名的 cookie）"""
    parts = []
    for c in cookies:
        domain = c.get("domain", "")
        if domain_filter in domain or domain.endswith(domain_filter):
            name = c.get("name", "")
            value = c.get("value", "")
            if name and value:
                parts.append(f"{name}={value}")
    return "; ".join(parts)


def _parse_rotate_params(html: str) -> Optional[tuple]:
    """从 Gemini 页面 HTML 解析 og_pid, rot, exp_id"""
    # Google 在页面中嵌入这些值，格式可能是：
    # 1. JS 变量赋值
    # 2. 嵌入在 script 标签的 JSON 数据中

    og_pid = None
    rot = None
    exp_id = None

    # 尝试多种模式匹配
    # 模式1: 直接在 JS 中查找
    og_pid_patterns = [
        r'"og_pid"\s*:\s*"([^"]+)"',
        r"'og_pid'\s*:\s*'([^']+)'",
        r'og_pid=([^&"\']+)',
    ]
    rot_patterns = [
        r'"rot"\s*:\s*"([^"]+)"',
        r"'rot'\s*:\s*'([^']+)'",
        r'rot=([^&"\']+)',
    ]
    exp_id_patterns = [
        r'"exp_id"\s*:\s*"([^"]+)"',
        r"'exp_id'\s*:\s*'([^']+)'",
        r'exp_id=([^&"\']+)',
    ]

    for p in og_pid_patterns:
        m = re.search(p, html)
        if m:
            og_pid = m.group(1)
            break

    for p in rot_patterns:
        m = re.search(p, html)
        if m:
            rot = m.group(1)
            break

    for p in exp_id_patterns:
        m = re.search(p, html)
        if m:
            exp_id = m.group(1)
            break

    if og_pid and rot:
        return (og_pid, rot, exp_id or "")

    return None


def _parse_init_value(html: str) -> Optional[str]:
    """从 RotateCookiesPage 响应解析 init_value"""
    patterns = [
        r'"init_value"\s*:\s*"([^"]+)"',
        r"'init_value'\s*:\s*'([^']+)'",
        r'name="init_value"\s+value="([^"]+)"',
        r'init_value=([^&"\'<>\s]+)',
    ]
    for p in patterns:
        m = re.search(p, html)
        if m:
            return m.group(1)
    return None


def _extract_psidts_from_response(resp: httpx.Response) -> Optional[str]:
    """从响应的 Set-Cookie header 提取 __Secure-1PSIDTS"""
    # httpx 的 headers 是 multi-value 的
    for key, value in resp.headers.multi_items():
        if key.lower() == "set-cookie" and "__Secure-1PSIDTS" in value:
            m = re.search(r'__Secure-1PSIDTS=([^;]+)', value)
            if m:
                return m.group(1)
    return None
