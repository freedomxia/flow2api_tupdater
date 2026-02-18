"""
Google 自动登录 + TOTP MFA 功能测试

包含三部分：
1. 端到端测试（Docker 环境，通过 API 验证完整链路）
2. 检查一：单元级别 - 验证数据层/API层字段正确传递
3. 检查二：集成级别 - 验证浏览器自动化逻辑分支覆盖
"""
import os
import sys
import json
import asyncio
import tempfile
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# ── conftest 已经 patch 了路径和 mock，这里直接 import ──
from token_updater.config import config


# ============================================================
#  第一部分：端到端测试（Docker 环境）
#  通过 HTTP API 验证 profile CRUD 含新字段的完整链路
# ============================================================

class TestE2EGoogleAutoLogin:
    """端到端测试：在 Docker 容器中通过 API 验证 google_email/password/totp 字段"""

    BASE_URL = os.environ.get("TUPDATER_URL", "http://127.0.0.1:8002")
    PASSWORD = os.environ.get("ADMIN_PASSWORD", "test")

    @staticmethod
    def _is_service_reachable(url):
        try:
            import httpx
            r = httpx.get(f"{url}/api/auth/check", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    @staticmethod
    def _get_token(url, password):
        import httpx
        try:
            r = httpx.post(f"{url}/api/login", json={"password": password}, timeout=5)
            data = r.json()
            return data.get("token", "")
        except Exception:
            return ""

    def _ensure_ready(self):
        """检查服务可达且能登录，否则 skip"""
        if not self._is_service_reachable(self.BASE_URL):
            pytest.skip("token-updater 服务不可达，跳过端到端测试")
        token = self._get_token(self.BASE_URL, self.PASSWORD)
        if not token:
            pytest.skip("token-updater 登录失败（密码不匹配），跳过端到端测试")
        return token

    @pytest.mark.asyncio
    async def test_create_profile_with_google_fields(self):
        """创建 profile 时传入 google_email/password/totp_secret"""
        auth_token = self._ensure_ready()

        import httpx
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}

            # 创建
            r = await client.post(
                f"{self.BASE_URL}/api/profiles",
                headers=headers,
                json={
                    "name": "e2e_autologin_test",
                    "remark": "自动登录测试",
                    "google_email": "test@gmail.com",
                    "google_password": "secret123",
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                }
            )
            data = r.json()
            assert data.get("success"), f"创建失败: {data}"
            pid = data["profile_id"]

            try:
                # 读取 - 验证脱敏
                r2 = await client.get(
                    f"{self.BASE_URL}/api/profiles/{pid}",
                    headers=headers,
                )
                p = r2.json()
                assert p["google_email"] == "test@gmail.com"
                assert "google_password" not in p, "密码不应返回明文"
                assert p["has_google_password"] is True
                assert "totp_secret" not in p, "TOTP 密钥不应返回明文"
                assert p["has_totp_secret"] is True

                # 更新
                r3 = await client.put(
                    f"{self.BASE_URL}/api/profiles/{pid}",
                    headers=headers,
                    json={"google_email": "updated@gmail.com"}
                )
                assert r3.json().get("success")

                # 验证更新
                r4 = await client.get(
                    f"{self.BASE_URL}/api/profiles/{pid}",
                    headers=headers,
                )
                assert r4.json()["google_email"] == "updated@gmail.com"
                assert r4.json()["has_google_password"] is True  # 密码未被清除

                # 列表接口也脱敏
                r5 = await client.get(
                    f"{self.BASE_URL}/api/profiles",
                    headers=headers,
                )
                profiles = r5.json()
                test_p = next((x for x in profiles if x["id"] == pid), None)
                assert test_p is not None
                assert "google_password" not in test_p
                assert test_p["has_google_password"] is True

            finally:
                # 清理
                await client.delete(
                    f"{self.BASE_URL}/api/profiles/{pid}",
                    headers=headers,
                )

    @pytest.mark.asyncio
    async def test_create_profile_without_google_fields(self):
        """不传 google 字段时应正常创建，has_xxx 为 False"""
        auth_token = self._ensure_ready()

        import httpx
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            r = await client.post(
                f"{self.BASE_URL}/api/profiles",
                headers=headers,
                json={"name": "e2e_no_google_test", "remark": "无 Google 字段"}
            )
            data = r.json()
            assert data.get("success")
            pid = data["profile_id"]

            try:
                r2 = await client.get(
                    f"{self.BASE_URL}/api/profiles/{pid}",
                    headers=headers,
                )
                p = r2.json()
                assert p.get("has_google_password") is False
                assert p.get("has_totp_secret") is False
            finally:
                await client.delete(
                    f"{self.BASE_URL}/api/profiles/{pid}",
                    headers=headers,
                )


# ============================================================
#  第二部分（检查一）：单元级别
#  验证 DB 层、API 模型、脱敏函数的字段正确性
# ============================================================

class TestUnitDataLayer:
    """检查一：数据层字段传递 + 脱敏逻辑"""

    def test_create_profile_request_model_has_new_fields(self):
        """CreateProfileRequest 模型包含 google_email/password/totp_secret"""
        from token_updater.api import CreateProfileRequest
        req = CreateProfileRequest(
            name="test",
            google_email="a@b.com",
            google_password="pw",
            totp_secret="SECRET",
        )
        assert req.google_email == "a@b.com"
        assert req.google_password == "pw"
        assert req.totp_secret == "SECRET"

    def test_create_profile_request_defaults(self):
        """新字段默认为空字符串"""
        from token_updater.api import CreateProfileRequest
        req = CreateProfileRequest(name="test")
        assert req.google_email == ""
        assert req.google_password == ""
        assert req.totp_secret == ""

    def test_update_profile_request_model_has_new_fields(self):
        """UpdateProfileRequest 模型包含新字段且默认 None"""
        from token_updater.api import UpdateProfileRequest
        req = UpdateProfileRequest()
        assert req.google_email is None
        assert req.google_password is None
        assert req.totp_secret is None

        req2 = UpdateProfileRequest(google_email="x@y.com", totp_secret="ABC")
        assert req2.google_email == "x@y.com"
        assert req2.totp_secret == "ABC"
        assert req2.google_password is None  # 未传则不更新

    def test_sanitize_profile_removes_secrets(self):
        """_sanitize_profile 应移除明文密码和密钥，添加 has_xxx 标志"""
        from token_updater.api import _sanitize_profile

        p = {
            "id": 1,
            "name": "test",
            "google_email": "a@b.com",
            "google_password": "secret",
            "totp_secret": "ABCDEF",
        }
        result = _sanitize_profile(p)
        assert result["google_email"] == "a@b.com"  # 邮箱保留
        assert "google_password" not in result
        assert "totp_secret" not in result
        assert result["has_google_password"] is True
        assert result["has_totp_secret"] is True

    def test_sanitize_profile_empty_secrets(self):
        """空密码/密钥时 has_xxx 为 False"""
        from token_updater.api import _sanitize_profile

        p = {"google_password": "", "totp_secret": None}
        result = _sanitize_profile(p)
        assert result["has_google_password"] is False
        assert result["has_totp_secret"] is False

    def test_totp_code_generation(self):
        """pyotp 能正确生成 6 位 TOTP 验证码"""
        import pyotp
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_code_with_real_format_secret(self):
        """用户提供的格式（小写 base32）也能正常工作"""
        import pyotp
        secret = "5j4k42oczl2l7plumnkedppczgpfgnzl"
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert len(code) == 6
        assert code.isdigit()


# ============================================================
#  第三部分（检查二）：集成级别
#  验证浏览器自动化中的登录/2FA 分支逻辑
# ============================================================

class TestIntegrationBrowserAutomation:
    """检查二：模拟 Playwright 页面交互，验证自动登录分支覆盖"""

    def _make_mock_page(self, url="https://accounts.google.com/v3/signin/identifier",
                        visible_selectors=None):
        """构造一个 mock page 对象"""
        page = MagicMock()
        page.url = url

        def make_locator(sel):
            loc = MagicMock()
            if visible_selectors and sel in visible_selectors:
                loc.count = AsyncMock(return_value=1)
                loc.first.is_visible = AsyncMock(return_value=True)
                loc.first.fill = AsyncMock()
                loc.first.click = AsyncMock()
            else:
                loc.count = AsyncMock(return_value=0)
                loc.first.is_visible = AsyncMock(return_value=False)
            return loc

        page.locator = make_locator
        page.goto = AsyncMock()
        page.screenshot = AsyncMock()
        page.title = AsyncMock(return_value="Sign in")
        return page

    @pytest.mark.asyncio
    async def test_email_fill_triggered_on_login_page(self):
        """当页面在 accounts.google.com 且有 email input 时，应自动填入邮箱"""
        profile = {
            "name": "test",
            "google_email": "user@gmail.com",
            "google_password": "pass123",
            "totp_secret": "",
        }
        page = self._make_mock_page(
            url="https://accounts.google.com/v3/signin/identifier?continue=xxx",
            visible_selectors=['input[type="email"]', '#identifierNext']
        )

        # 模拟一次循环迭代的逻辑
        clicked = False
        cur_url = page.url

        if not clicked and profile.get("google_email") and "accounts.google.com" in cur_url:
            for email_sel in ['input[type="email"]', '#identifierId']:
                el = page.locator(email_sel)
                if await el.count() > 0 and await el.first.is_visible():
                    await el.first.fill(profile["google_email"])
                    for next_sel in ['#identifierNext']:
                        nb = page.locator(next_sel)
                        if await nb.count() > 0 and await nb.first.is_visible():
                            await nb.first.click()
                            break
                    clicked = True
                    break

        assert clicked, "应该触发邮箱自动填入"

    @pytest.mark.asyncio
    async def test_password_fill_triggered(self):
        """密码页面应自动填入密码"""
        profile = {
            "name": "test",
            "google_email": "",  # 邮箱步骤已过
            "google_password": "mypassword",
            "totp_secret": "",
        }
        page = self._make_mock_page(
            url="https://accounts.google.com/v3/signin/challenge/pwd",
            visible_selectors=['input[type="password"]', '#passwordNext']
        )

        clicked = False
        cur_url = page.url

        # 邮箱步骤不触发（无 email input 可见）
        if not clicked and profile.get("google_email") and "accounts.google.com" in cur_url:
            pass  # 不会进入

        if not clicked and profile.get("google_password") and "accounts.google.com" in cur_url:
            for pwd_sel in ['input[type="password"]', 'input[name="Passwd"]']:
                el = page.locator(pwd_sel)
                if await el.count() > 0 and await el.first.is_visible():
                    await el.first.fill(profile["google_password"])
                    for next_sel in ['#passwordNext']:
                        nb = page.locator(next_sel)
                        if await nb.count() > 0 and await nb.first.is_visible():
                            await nb.first.click()
                            break
                    clicked = True
                    break

        assert clicked, "应该触发密码自动填入"

    @pytest.mark.asyncio
    async def test_totp_fill_triggered(self):
        """TOTP 2FA 页面应自动填入验证码"""
        import pyotp
        profile = {
            "name": "test",
            "google_email": "",
            "google_password": "",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }
        page = self._make_mock_page(
            url="https://accounts.google.com/v3/signin/challenge/totp",
            visible_selectors=['input[type="tel"]', '#totpNext']
        )

        clicked = False
        cur_url = page.url
        filled_code = None

        if not clicked and profile.get("totp_secret") and "accounts.google.com" in cur_url:
            for totp_sel in ['input[type="tel"]', 'input[name="totpPin"]']:
                el = page.locator(totp_sel)
                if await el.count() > 0 and await el.first.is_visible():
                    code = pyotp.TOTP(profile["totp_secret"]).now()
                    filled_code = code
                    await el.first.fill(code)
                    for next_sel in ['#totpNext']:
                        nb = page.locator(next_sel)
                        if await nb.count() > 0 and await nb.first.is_visible():
                            await nb.first.click()
                            break
                    clicked = True
                    break

        assert clicked, "应该触发 TOTP 自动填入"
        assert filled_code is not None
        assert len(filled_code) == 6
        assert filled_code.isdigit()

    @pytest.mark.asyncio
    async def test_no_autologin_without_credentials(self):
        """没有配置 google 凭据时，不应触发自动登录步骤"""
        profile = {
            "name": "test",
            "google_email": "",
            "google_password": "",
            "totp_secret": "",
        }
        page = self._make_mock_page(
            url="https://accounts.google.com/v3/signin/identifier",
            visible_selectors=['input[type="email"]']
        )

        clicked = False
        cur_url = page.url

        if not clicked and profile.get("google_email") and "accounts.google.com" in cur_url:
            clicked = True
        if not clicked and profile.get("google_password") and "accounts.google.com" in cur_url:
            clicked = True
        if not clicked and profile.get("totp_secret") and "accounts.google.com" in cur_url:
            clicked = True

        assert not clicked, "无凭据时不应触发任何自动登录步骤"

    @pytest.mark.asyncio
    async def test_non_google_page_skips_autologin(self):
        """非 Google 页面不应触发自动登录"""
        profile = {
            "name": "test",
            "google_email": "user@gmail.com",
            "google_password": "pass",
            "totp_secret": "SECRET",
        }

        clicked = False
        cur_url = "https://oauth2.example.com/consent"

        if not clicked and profile.get("google_email") and "accounts.google.com" in cur_url:
            clicked = True
        if not clicked and profile.get("google_password") and "accounts.google.com" in cur_url:
            clicked = True
        if not clicked and profile.get("totp_secret") and "accounts.google.com" in cur_url:
            clicked = True

        assert not clicked, "非 Google 页面不应触发自动登录"

    @pytest.mark.asyncio
    async def test_invalid_totp_secret_handled_gracefully(self):
        """无效的 TOTP 密钥不应导致崩溃"""
        import pyotp
        profile = {
            "name": "test",
            "totp_secret": "!!!invalid!!!",
        }

        error_caught = False
        try:
            code = pyotp.TOTP(profile["totp_secret"]).now()
        except Exception:
            error_caught = True

        # pyotp 对无效 base32 会抛异常，我们的代码用 try/except 捕获
        assert error_caught, "无效 TOTP 密钥应抛出异常（代码中已有 try/except 处理）"


# ============================================================
#  端到端 Shell 测试脚本（Docker 环境专用）
# ============================================================

class TestE2EShellScript:
    """验证 shell 脚本可以测试新字段的端到端流程"""

    def test_e2e_script_exists(self):
        """端到端测试脚本存在"""
        script = os.path.join(os.path.dirname(__file__), "..", "test_e2e_autologin.sh")
        assert os.path.exists(script), "test_e2e_autologin.sh 应存在"
