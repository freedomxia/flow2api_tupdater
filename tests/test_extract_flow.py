"""
端到端测试：Flow2API Token 提取流程改进
验证 _extract_from_context 的新策略：先直接访问 labs.google 检查登录状态，
只有在 session 失效时才 fallback 到 OAuth 流程。

测试场景：
1. 已有有效 session cookie 时，直接提取成功，不走 OAuth
2. session 失效（被重定向到登录页）时，fallback 到 OAuth
3. extract_gemini_only 方法正常工作
4. HEADLESS_EXTRACT_ARGS 参数被正确使用
"""
import asyncio
import os
import sys
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ============ 1. _extract_from_context 新策略测试 ============

class TestExtractFromContextNewStrategy:
    """测试 _extract_from_context 的改进策略"""

    @pytest.mark.asyncio
    async def test_direct_access_with_valid_session(self):
        """已有有效 session 时，直接提取成功，不走 OAuth"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "Test", "email": "t@g.com"}

        # Mock context
        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "__Secure-next-auth.session-token", "value": "valid_token_123"}
        ]

        # Mock page
        mock_page = AsyncMock()
        mock_page.url = "https://labs.google/fx/tools/flow"  # 没有被重定向
        mock_page.goto = AsyncMock()
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""  # 不测试 Gemini
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该成功提取 token
        assert result["flow2api_token"] == "valid_token_123"
        # 应该只访问 labs_url，不访问 login_url
        calls = [str(c) for c in mock_page.goto.call_args_list]
        assert any("labs.google/fx/tools/flow" in c for c in calls)
        # 不应该访问 signin 页面（因为已有有效 session）
        # 注意：由于 mock 的 url 返回的是 labs.google，不会触发 OAuth 流程

    @pytest.mark.asyncio
    async def test_fallback_to_oauth_when_redirected(self):
        """被重定向到登录页时，fallback 到 OAuth 流程"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "Test", "email": "t@g.com"}

        # Mock context - 第一次没有 cookie，OAuth 后有
        cookie_call_count = [0]
        async def mock_cookies(*args):
            cookie_call_count[0] += 1
            if cookie_call_count[0] <= 2:
                return []  # 前两次没有 cookie
            return [{"name": "__Secure-next-auth.session-token", "value": "oauth_token_456"}]

        mock_context = AsyncMock()
        mock_context.cookies = mock_cookies

        # Mock page - 模拟被重定向到 accounts.google.com
        url_sequence = [
            "https://accounts.google.com/signin",  # 第一次访问 labs.google 被重定向
            "https://labs.google/fx/api/auth/signin/google",  # 访问 signin 页面
            "https://labs.google/fx/tools/flow",  # OAuth 成功后跳转回来
        ]
        url_index = [0]

        mock_page = AsyncMock()
        def get_url():
            idx = min(url_index[0], len(url_sequence) - 1)
            return url_sequence[idx]
        type(mock_page).url = PropertyMock(side_effect=get_url)

        async def mock_goto(*args, **kwargs):
            url_index[0] += 1

        mock_page.goto = mock_goto
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_page.wait_for_url = AsyncMock()
        mock_page.wait_for_load_state = AsyncMock()
        mock_page.locator = MagicMock()
        mock_page.locator.return_value.wait_for = AsyncMock()
        mock_page.locator.return_value.click = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该通过 OAuth 流程获取 token
        assert result["flow2api_token"] == "oauth_token_456"

    @pytest.mark.asyncio
    async def test_no_token_prompts_vnc_login(self):
        """无法获取 token 时，提示用户通过 VNC 登录"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "Test", "email": "t@g.com"}

        # Mock context - 始终没有 cookie
        mock_context = AsyncMock()
        mock_context.cookies.return_value = []

        # Mock page - 始终在 accounts.google.com
        mock_page = AsyncMock()
        mock_page.url = "https://accounts.google.com/signin"
        mock_page.goto = AsyncMock()
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_page.wait_for_url = AsyncMock(side_effect=Exception("Timeout"))
        mock_page.wait_for_load_state = AsyncMock()
        mock_page.locator = MagicMock()
        mock_page.locator.return_value.wait_for = AsyncMock()
        mock_page.locator.return_value.click = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该返回空 token
        assert result["flow2api_token"] is None
        # 应该更新 profile 为未登录状态
        mock_db.update_profile.assert_called()


# ============ 2. extract_gemini_only 测试 ============

class TestExtractGeminiOnly:
    """测试 extract_gemini_only 方法"""

    @pytest.mark.asyncio
    async def test_sqlite_direct_read_success(self):
        """SQLite 直读成功时不启动浏览器"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test"}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)

            sqlite_result = {
                "flow2api_token": None,
                "gemini_cookies": {"psid": "psid_val", "psidts": "psidts_val"},
            }

            with patch.object(bm, '_read_cookies_from_sqlite', return_value=sqlite_result):
                with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        result = await bm.extract_gemini_only(1)

        assert result["psid"] == "psid_val"
        assert result["psidts"] == "psidts_val"
        # 不应启动 playwright
        assert bm._playwright is None

    @pytest.mark.asyncio
    async def test_fallback_to_browser_when_sqlite_empty(self):
        """SQLite 直读无结果时 fallback 到浏览器"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test", "proxy_enabled": False}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)

            empty_result = {"flow2api_token": None, "gemini_cookies": {}}

            with patch.object(bm, '_read_cookies_from_sqlite', return_value=empty_result):
                with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        # Mock playwright
                        mock_page = AsyncMock()
                        mock_page.goto = AsyncMock()
                        mock_page.close = AsyncMock()

                        mock_context = AsyncMock()
                        mock_context.new_page = AsyncMock(return_value=mock_page)
                        mock_context.close = AsyncMock()

                        mock_pw = AsyncMock()
                        mock_pw.chromium.launch_persistent_context = AsyncMock(return_value=mock_context)
                        bm._playwright = mock_pw

                        with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy', return_value=None):
                                    with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                                        with patch.object(bm, '_get_gemini_cookies', return_value={"psid": "browser_psid", "psidts": "browser_psidts"}):
                                            with patch("token_updater.browser.config") as mock_config:
                                                mock_config.gemini_login_url = "https://gemini.google.com"
                                                result = await bm.extract_gemini_only(1)

        assert result["psid"] == "browser_psid"
        assert result["psidts"] == "browser_psidts"

    @pytest.mark.asyncio
    async def test_no_profile_dir_returns_empty(self):
        """无持久化数据时返回空"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test"}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)

            with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                with patch("os.path.exists", return_value=False):
                    result = await bm.extract_gemini_only(1)

        assert result == {}


# ============ 3. HEADLESS_EXTRACT_ARGS 测试 ============

class TestHeadlessExtractArgs:
    """测试 HEADLESS_EXTRACT_ARGS 参数"""

    def test_headless_extract_args_defined(self):
        """HEADLESS_EXTRACT_ARGS 应该被定义"""
        from token_updater.browser import HEADLESS_EXTRACT_ARGS
        assert isinstance(HEADLESS_EXTRACT_ARGS, list)
        assert len(HEADLESS_EXTRACT_ARGS) > 0

    def test_headless_extract_args_less_restrictive(self):
        """HEADLESS_EXTRACT_ARGS 应该比 BROWSER_ARGS 更少限制"""
        from token_updater.browser import BROWSER_ARGS, HEADLESS_EXTRACT_ARGS
        # HEADLESS_EXTRACT_ARGS 应该更短
        assert len(HEADLESS_EXTRACT_ARGS) < len(BROWSER_ARGS)
        # 应该包含基本的反检测参数
        assert "--disable-blink-features=AutomationControlled" in HEADLESS_EXTRACT_ARGS
        # 不应该包含激进的内存优化参数
        assert "--renderer-process-limit=1" not in HEADLESS_EXTRACT_ARGS

    def test_vnc_browser_args_most_permissive(self):
        """VNC_BROWSER_ARGS 应该是最宽松的"""
        from token_updater.browser import VNC_BROWSER_ARGS, HEADLESS_EXTRACT_ARGS
        # VNC 参数应该最少
        assert len(VNC_BROWSER_ARGS) <= len(HEADLESS_EXTRACT_ARGS)


# ============ 4. extract_token 使用 HEADLESS_EXTRACT_ARGS 测试 ============

class TestExtractTokenUsesCorrectArgs:
    """测试 extract_token 使用正确的浏览器参数"""

    @pytest.mark.asyncio
    async def test_extract_token_uses_headless_extract_args(self):
        """extract_token 应该使用 HEADLESS_EXTRACT_ARGS"""
        from token_updater.browser import BrowserManager, HEADLESS_EXTRACT_ARGS
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test", "proxy_enabled": False}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            empty_result = {"flow2api_token": None, "gemini_cookies": {}}

            with patch.object(bm, '_read_cookies_from_sqlite', return_value=empty_result):
                with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        mock_context = AsyncMock()
                        mock_context.close = AsyncMock()

                        mock_pw = AsyncMock()
                        bm._playwright = mock_pw

                        with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy', return_value=None):
                                    with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                                        with patch.object(bm, '_extract_from_context', return_value={"flow2api_token": "tok", "gemini_cookies": {}}):
                                            mock_pw.chromium.launch_persistent_context = AsyncMock(return_value=mock_context)
                                            await bm.extract_token(1)

                        # 验证使用了 HEADLESS_EXTRACT_ARGS
                        call_kwargs = mock_pw.chromium.launch_persistent_context.call_args[1]
                        assert call_kwargs["args"] == HEADLESS_EXTRACT_ARGS


# ============ 5. 完整流程端到端测试 ============

class TestEndToEndExtractFlow:
    """完整流程端到端测试"""

    @pytest.mark.asyncio
    async def test_full_flow_always_uses_browser(self):
        """完整流程：始终使用浏览器刷新 session"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "E2E_Test", "proxy_enabled": False}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            # 即使 SQLite 有 cookie，也应该启动浏览器
            sqlite_result = {
                "flow2api_token": "old_sqlite_token",
                "gemini_cookies": {"psid": "old_psid", "psidts": "old_psidts"},
            }

            with patch.object(bm, '_read_cookies_from_sqlite', return_value=sqlite_result):
                with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        mock_context = AsyncMock()
                        mock_context.close = AsyncMock()
                        mock_pw = AsyncMock()
                        mock_pw.chromium.launch_persistent_context = AsyncMock(return_value=mock_context)
                        bm._playwright = mock_pw

                        with patch.object(bm, '_extract_from_context', return_value={
                            "flow2api_token": "fresh_browser_token",
                            "gemini_cookies": {"psid": "fresh_psid", "psidts": "fresh_psidts"}
                        }):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy', return_value=None):
                                    with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                                        with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                                            result = await bm.extract_token(1)

        # 应该返回浏览器刷新后的新 token
        assert result["flow2api_token"] == "fresh_browser_token"
        assert result["gemini_cookies"]["psid"] == "fresh_psid"
        # 应该启动了浏览器
        mock_pw.chromium.launch_persistent_context.assert_called_once()

    @pytest.mark.asyncio
    async def test_persist_cookies_called_after_extract(self):
        """提取成功后应调用 _persist_cookies_before_close"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "Test"}

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "__Secure-next-auth.session-token", "value": "tok"}
        ]

        mock_page = AsyncMock()
        mock_page.url = "https://labs.google/fx/tools/flow"
        mock_page.goto = AsyncMock()
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        persist_called = [False]
        original_persist = bm._persist_cookies_before_close

        async def mock_persist(ctx):
            persist_called[0] = True

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', mock_persist):
                    await bm._extract_from_context(mock_profile, mock_context)

        # 应该调用 persist
        assert persist_called[0] is True


# ============ 6. 边界情况测试 ============

class TestEdgeCases:
    """边界情况测试"""

    @pytest.mark.asyncio
    async def test_page_goto_exception_handled(self):
        """page.goto 异常应被正确处理"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "Test"}

        mock_context = AsyncMock()
        mock_context.cookies.return_value = []

        mock_page = AsyncMock()
        mock_page.url = "about:blank"
        mock_page.goto = AsyncMock(side_effect=Exception("Network error"))
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    # 不应抛出异常
                    result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该返回空结果
        assert result["flow2api_token"] is None

    @pytest.mark.asyncio
    async def test_active_context_used_directly(self):
        """如果 profile 浏览器正在运行，应直接使用 active context"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test"}

        # 设置 active context
        mock_context = AsyncMock()
        bm._active_context = mock_context
        bm._active_profile_id = 1

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                with patch("os.path.exists", return_value=True):
                    with patch.object(bm, '_extract_from_context', return_value={"flow2api_token": "active_tok", "gemini_cookies": {}}) as mock_extract:
                        result = await bm.extract_token(1)

        # 应该使用 active context
        mock_extract.assert_called_once_with(mock_profile, mock_context)
        assert result["flow2api_token"] == "active_tok"



# ============ 7. 第二次深度检查：用户场景测试 ============

class TestUserScenarios:
    """从用户角度测试各种真实场景"""

    @pytest.mark.asyncio
    async def test_scenario_first_time_user_no_login(self):
        """场景：首次使用，从未登录过"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "NewUser"}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)

            with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                # 没有 profile 目录
                with patch("os.path.exists", return_value=False):
                    result = await bm.extract_token(1)

        # 应该返回空结果
        assert result["flow2api_token"] is None
        assert result["gemini_cookies"] == {}

    @pytest.mark.asyncio
    async def test_scenario_vnc_login_then_auto_sync(self):
        """场景：VNC 登录后，自动同步应该启动浏览器刷新"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "VNCUser", "proxy_enabled": False}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            # 模拟 VNC 登录后 SQLite 有 cookie
            sqlite_result = {
                "flow2api_token": "vnc_login_token",
                "gemini_cookies": {"psid": "vnc_psid", "psidts": "vnc_psidts"},
            }

            with patch.object(bm, '_read_cookies_from_sqlite', return_value=sqlite_result):
                with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        mock_context = AsyncMock()
                        mock_context.close = AsyncMock()
                        mock_pw = AsyncMock()
                        mock_pw.chromium.launch_persistent_context = AsyncMock(return_value=mock_context)
                        bm._playwright = mock_pw

                        with patch.object(bm, '_extract_from_context', return_value={
                            "flow2api_token": "refreshed_token",
                            "gemini_cookies": {"psid": "refreshed_psid", "psidts": "refreshed_psidts"}
                        }):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy', return_value=None):
                                    with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                                        with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                                            result = await bm.extract_token(1)

        # 应该返回浏览器刷新后的 token
        assert result["flow2api_token"] == "refreshed_token"
        assert result["gemini_cookies"]["psid"] == "refreshed_psid"

    @pytest.mark.asyncio
    async def test_scenario_session_expired_needs_relogin(self):
        """场景：session 过期，需要重新登录"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "ExpiredUser"}

        # Mock context - 没有 cookie
        mock_context = AsyncMock()
        mock_context.cookies.return_value = []

        # Mock page - 被重定向到 accounts.google.com
        mock_page = AsyncMock()
        mock_page.url = "https://accounts.google.com/signin"
        mock_page.goto = AsyncMock()
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_page.wait_for_url = AsyncMock(side_effect=Exception("Timeout"))
        mock_page.wait_for_load_state = AsyncMock()
        mock_page.locator = MagicMock()
        mock_page.locator.return_value.wait_for = AsyncMock()
        mock_page.locator.return_value.click = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该返回空（需要 VNC 重新登录）
        assert result["flow2api_token"] is None
        # 应该更新 profile 为未登录状态
        mock_db.update_profile.assert_called()

    @pytest.mark.asyncio
    async def test_scenario_goto_fails_fallback_to_oauth(self):
        """场景：访问 labs.google 失败，fallback 到 OAuth"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "NetworkError"}

        # Mock context
        cookie_calls = [0]
        async def mock_cookies(*args):
            cookie_calls[0] += 1
            if cookie_calls[0] >= 3:
                return [{"name": "__Secure-next-auth.session-token", "value": "recovered_token"}]
            return []

        mock_context = AsyncMock()
        mock_context.cookies = mock_cookies

        # Mock page - 第一次 goto 失败
        goto_calls = [0]
        async def mock_goto(*args, **kwargs):
            goto_calls[0] += 1
            if goto_calls[0] == 1:
                raise Exception("Network error")
            # 后续成功

        mock_page = AsyncMock()
        mock_page.url = "https://labs.google/fx/tools/flow"
        mock_page.goto = mock_goto
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_page.wait_for_url = AsyncMock()
        mock_page.wait_for_load_state = AsyncMock()
        mock_page.locator = MagicMock()
        mock_page.locator.return_value.wait_for = AsyncMock()
        mock_page.locator.return_value.click = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该通过 OAuth fallback 恢复
        assert result["flow2api_token"] == "recovered_token"


# ============ 8. 代码路径覆盖测试 ============

class TestCodePathCoverage:
    """确保所有代码路径都被测试覆盖"""

    @pytest.mark.asyncio
    async def test_token_found_after_wait(self):
        """token 在等待后才出现的情况"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "SlowToken"}

        # Mock context - 第一次没有 cookie，等待后有
        cookie_calls = [0]
        async def mock_cookies(*args):
            cookie_calls[0] += 1
            if cookie_calls[0] >= 2:  # 第二次调用时返回 cookie
                return [{"name": "__Secure-next-auth.session-token", "value": "delayed_token"}]
            return []

        mock_context = AsyncMock()
        mock_context.cookies = mock_cookies

        # Mock page - 在 labs.google（没有被重定向）
        mock_page = AsyncMock()
        mock_page.url = "https://labs.google/fx/tools/flow"
        mock_page.goto = AsyncMock()
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = ""
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    # 减少 asyncio.sleep 的等待时间
                    with patch('asyncio.sleep', new_callable=AsyncMock):
                        result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该在等待后获取到 token
        assert result["flow2api_token"] == "delayed_token"

    @pytest.mark.asyncio
    async def test_gemini_extraction_with_flow2api(self):
        """同时提取 Flow2API 和 Gemini cookie"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_profile = {"id": 1, "name": "BothTokens"}

        # Mock context
        async def mock_cookies(url=None):
            if url and "gemini" in str(url):
                return [
                    {"name": "__Secure-1PSID", "value": "gemini_psid"},
                    {"name": "__Secure-1PSIDTS", "value": "gemini_psidts"},
                ]
            return [{"name": "__Secure-next-auth.session-token", "value": "flow_token"}]

        mock_context = AsyncMock()
        mock_context.cookies = mock_cookies

        mock_page = AsyncMock()
        mock_page.url = "https://labs.google/fx/tools/flow"
        mock_page.goto = AsyncMock()
        mock_page.route = AsyncMock()
        mock_page.close = AsyncMock()
        mock_page.wait_for_load_state = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.update_profile = AsyncMock()

            with patch("token_updater.browser.config") as mock_config:
                mock_config.labs_url = "https://labs.google/fx/tools/flow"
                mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                mock_config.gemini_api_url = "http://gemini-api:8000"
                mock_config.gemini_login_url = "https://gemini.google.com"
                mock_config.session_cookie_name = "__Secure-next-auth.session-token"

                with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                    with patch('asyncio.sleep', new_callable=AsyncMock):
                        result = await bm._extract_from_context(mock_profile, mock_context)

        # 应该同时获取到两种 token
        assert result["flow2api_token"] == "flow_token"
        assert result["gemini_cookies"]["psid"] == "gemini_psid"
        assert result["gemini_cookies"]["psidts"] == "gemini_psidts"

    def test_headless_extract_args_contains_essential_params(self):
        """HEADLESS_EXTRACT_ARGS 应包含必要的参数"""
        from token_updater.browser import HEADLESS_EXTRACT_ARGS
        
        # 必须有反自动化检测
        assert "--disable-blink-features=AutomationControlled" in HEADLESS_EXTRACT_ARGS
        # 必须有 sandbox 相关（Docker 环境需要）
        assert "--no-sandbox" in HEADLESS_EXTRACT_ARGS
        # 必须有 dev-shm（Docker 环境需要）
        assert "--disable-dev-shm-usage" in HEADLESS_EXTRACT_ARGS
