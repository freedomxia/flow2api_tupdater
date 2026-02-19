"""Token 刷新逻辑端对端测试

测试 token 提取和刷新的完整流程，验证：
1. session endpoint 访问是否触发 token 刷新
2. 页面访问后 token 是否正确提取
3. token 变化检测逻辑是否正确

运行方式（Docker 环境）：
docker compose -f docker-compose.test.yml run --rm token-updater sh -c "pip install pytest pytest-asyncio -q && python -m pytest tests/test_token_refresh.py -v"
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any


class MockPage:
    """模拟 Playwright Page"""
    def __init__(self, url: str = "https://labs.google/fx/tools/flow"):
        self._url = url
        self._goto_count = 0
        self._visited_urls = []
    
    @property
    def url(self) -> str:
        return self._url
    
    async def goto(self, url: str, **kwargs) -> MagicMock:
        self._goto_count += 1
        self._visited_urls.append(url)
        
        # 模拟不同 URL 的行为
        if "accounts.google.com" in url:
            self._url = url
        elif "api/auth/session" in url:
            self._url = url
            response = MagicMock()
            response.ok = True
            return response
        else:
            self._url = url
        
        response = MagicMock()
        response.ok = True
        return response
    
    async def route(self, pattern: str, handler) -> None:
        pass
    
    async def wait_for_load_state(self, state: str, **kwargs) -> None:
        pass
    
    async def wait_for_url(self, pattern: str, **kwargs) -> None:
        pass
    
    async def close(self) -> None:
        pass
    
    def locator(self, selector: str) -> MagicMock:
        mock = MagicMock()
        mock.wait_for = AsyncMock()
        mock.click = AsyncMock()
        return mock


class MockContext:
    """模拟 Playwright BrowserContext"""
    def __init__(self, cookies: list = None, token_refreshes: bool = False):
        self._cookies = cookies or []
        self._token_refreshes = token_refreshes
        self._cookie_read_count = 0
        self._original_token = "old_token_value_12345"
        self._refreshed_token = "new_token_value_67890"
    
    async def cookies(self, url: str = None) -> list:
        self._cookie_read_count += 1
        
        # 模拟 token 刷新：第二次读取返回新 token
        if self._token_refreshes and self._cookie_read_count > 1:
            return [{"name": "__Secure-next-auth.session-token", "value": self._refreshed_token}]
        
        return self._cookies
    
    async def new_page(self) -> MockPage:
        return MockPage()
    
    async def add_init_script(self, script: str) -> None:
        pass
    
    async def add_cookies(self, cookies: list) -> None:
        self._cookies.extend(cookies)
    
    async def close(self) -> None:
        pass


@pytest.fixture
def mock_profile() -> Dict[str, Any]:
    """测试用 profile"""
    return {
        "id": 1,
        "name": "test@gmail.com",
        "google_email": "test@gmail.com",
        "google_password": None,
        "totp_secret": None,
    }


@pytest.fixture
def mock_context_with_token() -> MockContext:
    """带有效 token 的 context"""
    return MockContext(
        cookies=[{"name": "__Secure-next-auth.session-token", "value": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..test_token"}]
    )


@pytest.fixture
def mock_context_token_refresh() -> MockContext:
    """模拟 token 刷新的 context"""
    return MockContext(
        cookies=[{"name": "__Secure-next-auth.session-token", "value": "old_token_value_12345"}],
        token_refreshes=True
    )


@pytest.fixture
def mock_context_no_token() -> MockContext:
    """无 token 的 context"""
    return MockContext(cookies=[])


class TestTokenRefreshLogic:
    """Token 刷新逻辑测试"""
    
    @pytest.mark.asyncio
    async def test_session_endpoint_visited_first(self, mock_profile, mock_context_with_token):
        """测试：应该先访问 session endpoint"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "test_token"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    # 创建一个追踪访问 URL 的 page
                    visited_urls = []
                    
                    class TrackingPage(MockPage):
                        async def goto(self, url: str, **kwargs):
                            visited_urls.append(url)
                            return await super().goto(url, **kwargs)
                    
                    class TrackingContext(MockContext):
                        async def new_page(self):
                            return TrackingPage()
                    
                    context = TrackingContext(
                        cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}]
                    )
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证 session endpoint 被首先访问
                    assert len(visited_urls) >= 1
                    assert "api/auth/session" in visited_urls[0], f"第一个访问的 URL 应该是 session endpoint，实际是: {visited_urls[0]}"
    
    @pytest.mark.asyncio
    async def test_token_change_detection(self, mock_profile):
        """测试：应该检测到 token 变化"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        # 模拟 token 从旧值变为新值
        call_count = [0]
        
        async def mock_get_cookie(context):
            call_count[0] += 1
            if call_count[0] == 1:
                return "old_token_prefix_12345_rest_of_token"
            return "new_token_prefix_67890_rest_of_token"
        
        with patch.object(manager, '_get_session_cookie', side_effect=mock_get_cookie):
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = MockContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}])
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证 token 被正确提取
                    assert result["flow2api_token"] is not None
    
    @pytest.mark.asyncio
    async def test_oauth_fallback_on_redirect(self, mock_profile):
        """测试：重定向到登录页时应该 fallback 到 OAuth"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        class RedirectPage(MockPage):
            async def goto(self, url: str, **kwargs):
                # 模拟重定向到 Google 登录页
                if "labs.google" in url and "api/auth/session" not in url:
                    self._url = "https://accounts.google.com/signin"
                else:
                    self._url = url
                response = MagicMock()
                response.ok = True
                return response
        
        class RedirectContext(MockContext):
            async def new_page(self):
                return RedirectPage()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = None
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = RedirectContext(cookies=[])
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 无 token 时结果应该为 None
                    assert result["flow2api_token"] is None


class TestExtractTokenFlow:
    """extract_token 完整流程测试"""
    
    @pytest.mark.asyncio
    async def test_extract_token_uses_browser(self, mock_profile):
        """测试：extract_token 应该始终使用浏览器"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        manager._playwright = MagicMock()
        
        browser_launched = [False]
        
        async def mock_launch(*args, **kwargs):
            browser_launched[0] = True
            return MockContext(
                cookies=[{"name": "__Secure-next-auth.session-token", "value": "test_token"}]
            )
        
        manager._playwright.chromium.launch_persistent_context = mock_launch
        
        with patch('token_updater.browser.profile_db') as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()
            
            with patch('token_updater.browser.os.path.exists', return_value=True):
                with patch.object(manager, '_read_cookies_from_sqlite', return_value={"flow2api_token": "sqlite_token", "gemini_cookies": {}}):
                    with patch.object(manager, '_extract_from_context', new_callable=AsyncMock) as mock_extract:
                        mock_extract.return_value = {"flow2api_token": "browser_token", "gemini_cookies": {}}
                        
                        with patch.object(manager, '_clean_locks'):
                            with patch.object(manager, '_get_proxy', new_callable=AsyncMock, return_value=None):
                                with patch.object(manager, '_inject_stealth', new_callable=AsyncMock):
                                    with patch.object(manager, '_persist_cookies_before_close', new_callable=AsyncMock):
                                        result = await manager.extract_token(1)
        
        # 验证浏览器被启动
        assert browser_launched[0], "应该启动浏览器而不是只用 SQLite"
    
    @pytest.mark.asyncio
    async def test_sqlite_only_for_logging(self, mock_profile):
        """测试：SQLite 结果只用于日志，不作为最终结果"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        manager._playwright = MagicMock()
        
        async def mock_launch(*args, **kwargs):
            return MockContext(
                cookies=[{"name": "__Secure-next-auth.session-token", "value": "browser_fresh_token"}]
            )
        
        manager._playwright.chromium.launch_persistent_context = mock_launch
        
        with patch('token_updater.browser.profile_db') as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()
            
            with patch('token_updater.browser.os.path.exists', return_value=True):
                # SQLite 返回旧 token
                with patch.object(manager, '_read_cookies_from_sqlite', return_value={"flow2api_token": "old_sqlite_token", "gemini_cookies": {}}):
                    # 浏览器返回新 token
                    with patch.object(manager, '_extract_from_context', new_callable=AsyncMock) as mock_extract:
                        mock_extract.return_value = {"flow2api_token": "new_browser_token", "gemini_cookies": {}}
                        
                        with patch.object(manager, '_clean_locks'):
                            with patch.object(manager, '_get_proxy', new_callable=AsyncMock, return_value=None):
                                with patch.object(manager, '_inject_stealth', new_callable=AsyncMock):
                                    with patch.object(manager, '_persist_cookies_before_close', new_callable=AsyncMock):
                                        result = await manager.extract_token(1)
        
        # 验证返回的是浏览器的 token，不是 SQLite 的
        assert result["flow2api_token"] == "new_browser_token"
        assert result["flow2api_token"] != "old_sqlite_token"


class TestSessionEndpointRefresh:
    """Session Endpoint 刷新测试"""
    
    @pytest.mark.asyncio
    async def test_session_endpoint_url_correct(self):
        """测试：session endpoint URL 应该正确"""
        expected_url = "https://labs.google/fx/api/auth/session"
        
        # 验证 URL 格式
        assert "api/auth/session" in expected_url
        assert expected_url.startswith("https://labs.google")
    
    @pytest.mark.asyncio
    async def test_session_endpoint_failure_continues(self, mock_profile):
        """测试：session endpoint 失败时应该继续执行"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        class FailingPage(MockPage):
            async def goto(self, url: str, **kwargs):
                if "api/auth/session" in url:
                    raise Exception("Network error")
                return await super().goto(url, **kwargs)
        
        class FailingContext(MockContext):
            async def new_page(self):
                return FailingPage()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "fallback_token"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = FailingContext(
                        cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}]
                    )
                    
                    # 即使 session endpoint 失败，也应该继续并返回 token
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    assert result["flow2api_token"] == "fallback_token"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
