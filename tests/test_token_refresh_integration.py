"""Token 刷新集成测试

第三次深度检查：从集成角度验证完整流程

运行方式（Docker 环境）：
docker compose -f docker-compose.test.yml run --rm token-updater sh -c "pip install pytest pytest-asyncio -q && python -m pytest tests/test_token_refresh_integration.py -v"
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List
import logging


class MockResponse:
    """模拟 HTTP Response"""
    def __init__(self, ok: bool = True, status: int = 200):
        self.ok = ok
        self.status = status


class MockPage:
    """模拟 Playwright Page，记录所有操作"""
    def __init__(self):
        self._url = ""
        self._operations: List[str] = []
        self._goto_responses: Dict[str, MockResponse] = {}
    
    @property
    def url(self) -> str:
        return self._url
    
    @property
    def operations(self) -> List[str]:
        return self._operations
    
    def set_goto_response(self, url_pattern: str, response: MockResponse):
        self._goto_responses[url_pattern] = response
    
    async def goto(self, url: str, **kwargs) -> MockResponse:
        self._operations.append(f"goto:{url}")
        self._url = url
        
        # 查找匹配的响应
        for pattern, response in self._goto_responses.items():
            if pattern in url:
                return response
        
        return MockResponse(ok=True)
    
    async def route(self, pattern: str, handler) -> None:
        self._operations.append(f"route:{pattern}")
    
    async def wait_for_load_state(self, state: str, **kwargs) -> None:
        self._operations.append(f"wait_for_load_state:{state}")
    
    async def wait_for_url(self, pattern: str, **kwargs) -> None:
        self._operations.append(f"wait_for_url:{pattern}")
    
    async def close(self) -> None:
        self._operations.append("close")
    
    def locator(self, selector: str) -> MagicMock:
        self._operations.append(f"locator:{selector}")
        mock = MagicMock()
        mock.wait_for = AsyncMock()
        mock.click = AsyncMock()
        return mock


class MockContext:
    """模拟 Playwright BrowserContext"""
    def __init__(self, cookies: list = None):
        self._cookies = cookies or []
        self._page = MockPage()
    
    async def cookies(self, url: str = None) -> list:
        return self._cookies
    
    async def new_page(self) -> MockPage:
        return self._page
    
    async def add_init_script(self, script: str) -> None:
        pass
    
    async def close(self) -> None:
        pass
    
    @property
    def page(self) -> MockPage:
        return self._page


@pytest.fixture
def mock_profile() -> Dict[str, Any]:
    return {
        "id": 1,
        "name": "integration_test@gmail.com",
        "google_email": "integration_test@gmail.com",
        "google_password": None,
        "totp_secret": None,
    }


class TestIntegrationFlow:
    """集成流程测试"""
    
    @pytest.mark.asyncio
    async def test_complete_refresh_flow_order(self, mock_profile):
        """测试：完整刷新流程的执行顺序"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        context = MockContext(
            cookies=[{"name": "__Secure-next-auth.session-token", "value": "test_token_value"}]
        )
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "test_token_value"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证操作顺序
                    operations = context.page.operations
                    
                    # 1. 应该先设置路由
                    assert any("route" in op for op in operations), "应该设置路由"
                    
                    # 2. 应该访问 session endpoint
                    session_goto = [op for op in operations if "goto" in op and "api/auth/session" in op]
                    assert len(session_goto) > 0, "应该访问 session endpoint"
                    
                    # 3. 应该访问 labs.google
                    labs_goto = [op for op in operations if "goto" in op and "labs.google/fx/tools" in op]
                    assert len(labs_goto) > 0, "应该访问 labs.google"
                    
                    # 4. session endpoint 应该在 labs.google 之前
                    session_idx = operations.index(session_goto[0])
                    labs_idx = operations.index(labs_goto[0])
                    assert session_idx < labs_idx, "session endpoint 应该在 labs.google 之前访问"
    
    @pytest.mark.asyncio
    async def test_token_extraction_with_db_update(self, mock_profile):
        """测试：token 提取后应该更新数据库"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        context = MockContext(
            cookies=[{"name": "__Secure-next-auth.session-token", "value": "db_update_test_token"}]
        )
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "db_update_test_token"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证数据库更新被调用
                    assert mock_db.update_profile.called, "应该调用数据库更新"
                    
                    # 验证更新参数
                    call_args = mock_db.update_profile.call_args
                    assert call_args[0][0] == mock_profile["id"], "应该更新正确的 profile"
    
    @pytest.mark.asyncio
    async def test_gemini_cookie_extraction_skipped_when_disabled(self, mock_profile):
        """测试：Gemini API 未配置时应该跳过 Gemini cookie 提取"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        context = MockContext(
            cookies=[{"name": "__Secure-next-auth.session-token", "value": "test_token"}]
        )
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "test_token"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""  # 未配置
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证没有访问 gemini.google.com
                    operations = context.page.operations
                    gemini_goto = [op for op in operations if "goto" in op and "gemini.google" in op]
                    assert len(gemini_goto) == 0, "Gemini API 未配置时不应该访问 gemini.google.com"


class TestSyncerIntegration:
    """Syncer 集成测试"""
    
    @pytest.mark.asyncio
    async def test_sync_profile_uses_browser_manager(self, mock_profile):
        """测试：sync_profile 应该使用 browser_manager"""
        from token_updater.updater import TokenSyncer
        
        syncer = TokenSyncer()
        
        with patch('token_updater.updater.browser_manager') as mock_browser:
            mock_browser.extract_token = AsyncMock(return_value={
                "flow2api_token": "syncer_test_token",
                "gemini_cookies": {}
            })
            
            with patch('token_updater.updater.profile_db') as mock_db:
                mock_db.get_profile = AsyncMock(return_value=mock_profile)
                mock_db.update_profile = AsyncMock()
                
                with patch.object(syncer, '_push_to_flow2api', new_callable=AsyncMock) as mock_push:
                    mock_push.return_value = {"success": True, "email": "test@gmail.com"}
                    
                    with patch('token_updater.updater.config') as mock_config:
                        mock_config.gemini_api_url = ""
                        
                        result = await syncer.sync_profile(1)
                        
                        # 验证 browser_manager.extract_token 被调用
                        mock_browser.extract_token.assert_called_once_with(1)
    
    @pytest.mark.asyncio
    async def test_sync_profile_pushes_extracted_token(self, mock_profile):
        """测试：sync_profile 应该推送提取到的 token"""
        from token_updater.updater import TokenSyncer
        
        syncer = TokenSyncer()
        extracted_token = "extracted_token_for_push_test"
        
        with patch('token_updater.updater.browser_manager') as mock_browser:
            mock_browser.extract_token = AsyncMock(return_value={
                "flow2api_token": extracted_token,
                "gemini_cookies": {}
            })
            
            with patch('token_updater.updater.profile_db') as mock_db:
                mock_db.get_profile = AsyncMock(return_value=mock_profile)
                mock_db.update_profile = AsyncMock()
                
                with patch.object(syncer, '_push_to_flow2api', new_callable=AsyncMock) as mock_push:
                    mock_push.return_value = {"success": True, "email": "test@gmail.com"}
                    
                    with patch('token_updater.updater.config') as mock_config:
                        mock_config.gemini_api_url = ""
                        
                        result = await syncer.sync_profile(1)
                        
                        # 验证推送的是提取到的 token
                        mock_push.assert_called_once_with(extracted_token)


class TestLoggingOutput:
    """日志输出测试"""
    
    @pytest.mark.asyncio
    async def test_session_endpoint_log_message(self, mock_profile, caplog):
        """测试：应该输出 session endpoint 访问日志"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        context = MockContext(
            cookies=[{"name": "__Secure-next-auth.session-token", "value": "test_token"}]
        )
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "test_token"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    with caplog.at_level(logging.INFO):
                        result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证日志包含 session endpoint 相关信息
                    log_text = caplog.text
                    assert "session endpoint" in log_text.lower() or "session" in log_text.lower()
    
    @pytest.mark.asyncio
    async def test_token_change_log_message(self, mock_profile, caplog):
        """测试：token 变化时应该输出日志"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        call_count = [0]
        
        async def mock_get_cookie(context):
            call_count[0] += 1
            if call_count[0] == 1:
                return "old_token_12345678901234567890"
            return "new_token_09876543210987654321"
        
        context = MockContext(
            cookies=[{"name": "__Secure-next-auth.session-token", "value": "test"}]
        )
        
        with patch.object(manager, '_get_session_cookie', side_effect=mock_get_cookie):
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    with caplog.at_level(logging.INFO):
                        result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证日志包含 token 刷新信息
                    log_text = caplog.text
                    # 应该有 token 相关的日志
                    assert "token" in log_text.lower()


class TestErrorRecovery:
    """错误恢复测试"""
    
    @pytest.mark.asyncio
    async def test_recovery_after_session_endpoint_failure(self, mock_profile):
        """测试：session endpoint 失败后应该继续执行"""
        from token_updater.browser import BrowserManager
        
        manager = BrowserManager()
        
        class FailingPage(MockPage):
            async def goto(self, url: str, **kwargs):
                self._operations.append(f"goto:{url}")
                if "api/auth/session" in url:
                    raise Exception("Session endpoint failed")
                self._url = url
                return MockResponse(ok=True)
        
        class FailingContext(MockContext):
            def __init__(self):
                super().__init__(cookies=[{"name": "__Secure-next-auth.session-token", "value": "recovery_token"}])
                self._page = FailingPage()
        
        context = FailingContext()
        
        with patch.object(manager, '_get_session_cookie', new_callable=AsyncMock) as mock_get_cookie:
            mock_get_cookie.return_value = "recovery_token"
            
            with patch('token_updater.browser.profile_db') as mock_db:
                mock_db.update_profile = AsyncMock()
                
                with patch('token_updater.browser.config') as mock_config:
                    mock_config.labs_url = "https://labs.google/fx/tools/flow"
                    mock_config.gemini_api_url = ""
                    mock_config.session_cookie_name = "__Secure-next-auth.session-token"
                    
                    result = await manager._extract_from_context(mock_profile, context)
                    
                    # 验证仍然尝试访问 labs.google
                    operations = context.page.operations
                    labs_goto = [op for op in operations if "goto" in op and "labs.google/fx/tools" in op]
                    assert len(labs_goto) > 0, "session endpoint 失败后应该继续访问 labs.google"
                    
                    # 验证最终返回了 token
                    assert result["flow2api_token"] == "recovery_token"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
