"""Token 刷新边界条件和异常处理测试

第二次深度检查：从边界条件和异常处理角度验证代码健壮性

运行方式（Docker 环境）：
docker compose -f docker-compose.test.yml run --rm token-updater sh -c "pip install pytest pytest-asyncio -q && python -m pytest tests/test_token_refresh_edge_cases.py -v"
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any


class MockPage:
    """模拟 Playwright Page"""
    def __init__(self):
        self._url = ""
        self._load_state_timeout = False
    
    @property
    def url(self) -> str:
        return self._url
    
    async def goto(self, url: str, **kwargs) -> MagicMock:
        self._url = url
        response = MagicMock()
        response.ok = True
        return response
    
    async def route(self, pattern: str, handler) -> None:
        pass
    
    async def wait_for_load_state(self, state: str, **kwargs) -> None:
        if self._load_state_timeout:
            raise asyncio.TimeoutError("Load state timeout")
    
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
    def __init__(self, cookies: list = None):
        self._cookies = cookies or []
    
    async def cookies(self, url: str = None) -> list:
        return self._cookies
    
    async def new_page(self) -> MockPage:
        return MockPage()
    
    async def add_init_script(self, script: str) -> None:
        pass
    
    async def close(self) -> None:
        pass


@pytest.fixture
def mock_profile() -> Dict[str, Any]:
    return {
        "id": 1,
        "name": "test@gmail.com",
        "google_email": "test@gmail.com",
        "google_password": None,
        "totp_secret": None,
    }


class TestEdgeCases:
    """边界条件测试"""
    
    @pytest.mark.asyncio
    async def test_empty_token_handling(self, mock_profile):
        """测试：空 token 处理"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            # 返回空字符串
            mock_get_cookie.return_value = ""
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = MockContext(cookies=[])
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 空字符串应该被视为无 token
                    assert result["flow2api_token"] == "" or result["flow2api_token"] is None
    
    @pytest.mark.asyncio
    async def test_none_token_handling(self, mock_profile):
        """测试：None token 处理"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = None
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.login_url = "https://labs.google/fx/api/auth/signin/google"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = MockContext(cookies=[])
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # None 应该正确处理，不抛异常
                    assert result["flow2api_token"] is None
    
    @pytest.mark.asyncio
    async def test_short_token_prefix_handling(self, mock_profile):
        """测试：短 token（少于20字符）的前缀处理"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        # 返回短 token
        short_token = "short"
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = short_token
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = MockContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": short_token}])
                    
                    # 不应该抛出 IndexError
                    result = await manager._extract_from_context(mock_profile, context)
                    assert result["flow2api_token"] == short_token
    
    @pytest.mark.asyncio
    async def test_network_timeout_handling(self, mock_profile):
        """测试：网络超时处理"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        class TimeoutPage(MockPage):
            async def goto(self, url: str, **kwargs):
                if "api/auth/session" in url:
                    raise asyncio.TimeoutError("Connection timeout")
                return await super().goto(url, **kwargs)
        
        class TimeoutContext(MockContext):
            async def new_page(self):
                return TimeoutPage()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "valid_token_after_timeout"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = TimeoutContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}])
                    
                    # 超时不应该导致整个流程失败
                    result = await manager._extract_from_context(mock_profile, context)
                    assert result["flow2api_token"] == "valid_token_after_timeout"
    
    @pytest.mark.asyncio
    async def test_load_state_timeout_handling(self, mock_profile):
        """测试：页面加载状态超时处理"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        class LoadTimeoutPage(MockPage):
            async def wait_for_load_state(self, state: str, **kwargs):
                raise asyncio.TimeoutError("networkidle timeout")
        
        class LoadTimeoutContext(MockContext):
            async def new_page(self):
                return LoadTimeoutPage()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "token_despite_timeout"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = LoadTimeoutContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}])
                    
                    # load state 超时不应该导致失败
                    result = await manager._extract_from_context(mock_profile, context)
                    assert result["flow2api_token"] == "token_despite_timeout"


class TestTokenPrefixLogic:
    """Token 前缀比较逻辑测试"""
    
    @pytest.mark.asyncio
    async def test_token_prefix_comparison_same(self, mock_profile):
        """测试：相同 token 前缀比较"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        same_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..same_token_value"
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = same_token
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = MockContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": same_token}])
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 即使 token 未变化，也应该返回有效 token
                    assert result["flow2api_token"] == same_token
    
    @pytest.mark.asyncio
    async def test_token_prefix_comparison_different(self, mock_profile):
        """测试：不同 token 前缀比较"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        call_count = [0]
        old_token = "old_token_prefix_1234567890_rest"
        new_token = "new_token_prefix_0987654321_rest"
        
        async def mock_get_cookie(context):
            call_count[0] += 1
            if call_count[0] == 1:
                return old_token
            return new_token
        
        with patch.object(manager, '_get_session_cookie', side_effect=mock_get_cookie):
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    context = MockContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": old_token}])
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 应该返回新 token
                    assert result["flow2api_token"] == new_token


class TestURLRedirectDetection:
    """URL 重定向检测测试"""
    
    @pytest.mark.asyncio
    async def test_google_signin_redirect_detection(self, mock_profile):
        """测试：Google 登录页重定向检测"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        redirect_urls = [
            "https://accounts.google.com/signin",
            "https://accounts.google.com/v3/signin/identifier",
            "https://labs.google/fx/api/auth/signin/google",
            "https://labs.google/signin",
        ]
        
        for redirect_url in redirect_urls:
            class RedirectPage(MockPage):
                def __init__(self):
                    super().__init__()
                    self._url = redirect_url
                
                async def goto(self, url: str, **kwargs):
                    if "api/auth/session" not in url:
                        self._url = redirect_url
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
                        
                        # 应该检测到重定向并尝试 OAuth
                        result = await manager._extract_from_context(mock_profile, context)
                        
                        # 无 token 时结果为 None
                        assert result["flow2api_token"] is None
    
    @pytest.mark.asyncio
    async def test_valid_labs_url_no_redirect(self, mock_profile):
        """测试：有效 labs.google URL 不触发重定向"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        valid_urls = [
            "https://labs.google/fx/tools/flow",
            "https://labs.google/fx/tools/flow?param=value",
            "https://labs.google/fx/",
        ]
        
        for valid_url in valid_urls:
            class ValidPage(MockPage):
                def __init__(self):
                    super().__init__()
                    self._url = valid_url
                
                async def goto(self, url: str, **kwargs):
                    self._url = valid_url
                    response = MagicMock()
                    response.ok = True
                    return response
            
            class ValidContext(MockContext):
                async def new_page(self):
                    return ValidPage()
            
            with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
                mock_get_cookie.return_value = "valid_token"
                
                with patch('token_updater.browser.profile_db') as mock_db:
                    mock_db.update_profile = AsyncMock()
                    
                    with patch('token_updater.browser.config') as mock_config:
                        mock_config.labs_url = "https://labs.google/fx/tools/flow"
                        mock_config.gemini_api_url = ""
                        mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                        
                        context = ValidContext(cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}])
                        
                        result = await manager._extract_from_context(mock_profile, context)
                        
                        # 有效 URL 应该返回 token
                        assert result["flow2api_token"] == "valid_token"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
