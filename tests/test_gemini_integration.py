"""
测试 Gemini API 集成功能
验证 config / api / browser / updater 各层的 Gemini 支持
"""
import json
import os
import sys
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# 确保能 import token_updater
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ============ 1. Config 层测试 ============

class TestConfig:
    """测试 Config 模型和持久化"""

    def test_config_has_gemini_fields(self):
        """Config 模型应包含 gemini_api_url 和 gemini_connection_token"""
        from token_updater.config import Config
        fields = Config.model_fields
        assert "gemini_api_url" in fields
        assert "gemini_connection_token" in fields
        assert "gemini_login_url" in fields

    def test_config_gemini_defaults(self):
        """Gemini 字段默认值应为空字符串"""
        from token_updater.config import Config
        c = Config(
            admin_password="test",
            api_key="key",
            flow2api_url="http://localhost:8000",
            connection_token="tok",
            refresh_interval=60,
            enable_vnc=False,
            api_port=8002,
            session_ttl_minutes=1440,
            config_file="/tmp/test.json",
        )
        assert c.gemini_api_url == ""
        assert c.gemini_connection_token == ""
        assert c.gemini_login_url == "https://gemini.google.com"

    def test_config_gemini_custom_values(self):
        """Config 应能接受自定义 Gemini 值"""
        from token_updater.config import Config
        c = Config(
            admin_password="test",
            api_key="key",
            flow2api_url="http://localhost:8000",
            connection_token="tok",
            refresh_interval=60,
            enable_vnc=False,
            gemini_api_url="http://gemini:9000",
            gemini_connection_token="gem_token_123",
            api_port=8002,
            session_ttl_minutes=1440,
            config_file="/tmp/test.json",
        )
        assert c.gemini_api_url == "http://gemini:9000"
        assert c.gemini_connection_token == "gem_token_123"

    def test_persist_keys_include_gemini(self):
        """PERSIST_KEYS 应包含 gemini 字段"""
        from token_updater.config import PERSIST_KEYS
        assert "gemini_api_url" in PERSIST_KEYS
        assert "gemini_connection_token" in PERSIST_KEYS

    def test_config_save_includes_gemini(self):
        """config.save() 应持久化 gemini 字段"""
        from token_updater.config import Config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            config_file = f.name

        try:
            c = Config(
                admin_password="test",
                api_key="key",
                flow2api_url="http://localhost:8000",
                connection_token="tok",
                refresh_interval=60,
                enable_vnc=False,
                gemini_api_url="http://gemini:9000",
                gemini_connection_token="gem_secret",
                api_port=8002,
                session_ttl_minutes=1440,
                config_file=config_file,
            )
            c.save()

            with open(config_file, "r") as f:
                data = json.load(f)

            assert data["gemini_api_url"] == "http://gemini:9000"
            assert data["gemini_connection_token"] == "gem_secret"
            assert data["flow2api_url"] == "http://localhost:8000"
        finally:
            os.unlink(config_file)

    def test_build_config_reads_gemini_env(self):
        """_build_config 应从环境变量读取 Gemini 配置"""
        from token_updater.config import _build_config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            config_file = f.name

        try:
            env = {
                "CONFIG_FILE": config_file,
                "ADMIN_PASSWORD": "pw",
                "GEMINI_API_URL": "http://env-gemini:8080",
                "GEMINI_CONNECTION_TOKEN": "env_gem_tok",
            }
            with patch.dict(os.environ, env, clear=False):
                c = _build_config()
                assert c.gemini_api_url == "http://env-gemini:8080"
                assert c.gemini_connection_token == "env_gem_tok"
        finally:
            os.unlink(config_file)

    def test_build_config_reads_gemini_persisted(self):
        """_build_config 应从持久化文件读取 Gemini 配置"""
        from token_updater.config import _build_config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "gemini_api_url": "http://persisted-gemini:9000",
                "gemini_connection_token": "persisted_tok",
            }, f)
            config_file = f.name

        try:
            # 清除环境变量中的 gemini 配置
            env = {
                "CONFIG_FILE": config_file,
                "ADMIN_PASSWORD": "pw",
            }
            env_clear = {"GEMINI_API_URL": "", "GEMINI_CONNECTION_TOKEN": ""}
            with patch.dict(os.environ, {**env, **env_clear}, clear=False):
                c = _build_config()
                assert c.gemini_api_url == "http://persisted-gemini:9000"
                assert c.gemini_connection_token == "persisted_tok"
        finally:
            os.unlink(config_file)


# ============ 2. API 模型测试 ============

class TestAPIModels:
    """测试 API 请求/响应模型"""

    def test_update_config_request_has_gemini_fields(self):
        """UpdateConfigRequest 应包含 gemini 字段"""
        from token_updater.api import UpdateConfigRequest
        req = UpdateConfigRequest(
            gemini_api_url="http://gemini:9000",
            gemini_connection_token="tok123",
        )
        assert req.gemini_api_url == "http://gemini:9000"
        assert req.gemini_connection_token == "tok123"
        # 其他字段应为 None
        assert req.flow2api_url is None
        assert req.connection_token is None
        assert req.refresh_interval is None

    def test_update_config_request_all_none(self):
        """所有字段都可以为 None"""
        from token_updater.api import UpdateConfigRequest
        req = UpdateConfigRequest()
        assert req.gemini_api_url is None
        assert req.gemini_connection_token is None


# ============ 3. Browser 层测试 ============

class TestBrowserGeminiCookies:
    """测试 BrowserManager 的 Gemini cookie 提取"""

    @pytest.mark.asyncio
    async def test_get_gemini_cookies_extracts_both(self):
        """_get_gemini_cookies 应提取 __Secure-1PSID 和 __Secure-1PSIDTS"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "__Secure-1PSID", "value": "psid_value_123"},
            {"name": "__Secure-1PSIDTS", "value": "psidts_value_456"},
            {"name": "other_cookie", "value": "irrelevant"},
        ]

        result = await bm._get_gemini_cookies(mock_context)
        assert result["psid"] == "psid_value_123"
        assert result["psidts"] == "psidts_value_456"
        mock_context.cookies.assert_called_once_with("https://gemini.google.com")

    @pytest.mark.asyncio
    async def test_get_gemini_cookies_only_psid(self):
        """只有 PSID 没有 PSIDTS 也应返回"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "__Secure-1PSID", "value": "psid_only"},
        ]

        result = await bm._get_gemini_cookies(mock_context)
        assert result["psid"] == "psid_only"
        assert "psidts" not in result

    @pytest.mark.asyncio
    async def test_get_gemini_cookies_empty(self):
        """没有 Gemini cookie 应返回空 dict"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "unrelated", "value": "val"},
        ]

        result = await bm._get_gemini_cookies(mock_context)
        assert result == {}

    @pytest.mark.asyncio
    async def test_get_gemini_cookies_exception_fallback(self):
        """cookies() 异常时应 fallback 到无参数调用"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        # 第一次调用（带域名）抛异常，第二次（无参数）返回 cookie
        mock_context.cookies.side_effect = [
            Exception("domain not supported"),
            [{"name": "__Secure-1PSID", "value": "fallback_psid"}],
        ]

        result = await bm._get_gemini_cookies(mock_context)
        assert result["psid"] == "fallback_psid"
        assert mock_context.cookies.call_count == 2


# ============ 4. Updater 层测试 ============

class TestUpdaterGeminiPush:
    """测试 TokenSyncer 的 Gemini 推送逻辑"""

    @pytest.mark.asyncio
    async def test_push_to_gemini_api_success(self):
        """成功推送到 Gemini API"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "message": "Token updated",
            "id": "abc123",
        }

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "gem_tok"

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = mock_response
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_client

                result = await syncer._push_to_gemini_api(
                    {"psid": "test_psid", "psidts": "test_psidts"},
                    "TestProfile"
                )

                assert result["success"] is True
                # 验证请求参数
                call_args = mock_client.post.call_args
                assert call_args[1]["json"]["psid"] == "test_psid"
                assert call_args[1]["json"]["psidts"] == "test_psidts"
                assert call_args[1]["json"]["token"] == "gem_tok"
                assert call_args[1]["json"]["name"] == "TestProfile"
                assert "gemini:9000/api/plugin/update-token" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_push_to_gemini_api_no_url(self):
        """未配置 Gemini API 地址应返回错误"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = ""
            mock_config.gemini_connection_token = "tok"

            result = await syncer._push_to_gemini_api({"psid": "x"}, "test")
            assert result["success"] is False
            assert "地址" in result["error"]

    @pytest.mark.asyncio
    async def test_push_to_gemini_api_no_token(self):
        """未配置 Gemini 连接 Token 应返回错误"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = ""

            result = await syncer._push_to_gemini_api({"psid": "x"}, "test")
            assert result["success"] is False
            assert "Token" in result["error"]

    @pytest.mark.asyncio
    async def test_push_to_gemini_api_no_psid(self):
        """缺少 PSID 应返回错误"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "tok"

            result = await syncer._push_to_gemini_api({}, "test")
            assert result["success"] is False
            assert "PSID" in result["error"]

    @pytest.mark.asyncio
    async def test_push_to_gemini_api_http_error(self):
        """HTTP 错误应返回失败"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "tok"

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = mock_response
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_client

                result = await syncer._push_to_gemini_api({"psid": "x"}, "test")
                assert result["success"] is False
                assert "500" in result["error"]

    @pytest.mark.asyncio
    async def test_push_to_gemini_api_network_error(self):
        """网络异常应返回失败"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "tok"

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.side_effect = Exception("Connection refused")
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_client

                result = await syncer._push_to_gemini_api({"psid": "x"}, "test")
                assert result["success"] is False
                assert "Connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_push_to_gemini_url_trailing_slash(self):
        """URL 末尾有斜杠应正确拼接"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "message": "ok"}

        with patch("token_updater.updater.config") as mock_config:
            mock_config.gemini_api_url = "http://gemini:9000/"
            mock_config.gemini_connection_token = "tok"

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = mock_response
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_client

                result = await syncer._push_to_gemini_api({"psid": "x"}, "test")
                call_url = mock_client.post.call_args[0][0]
                # 不应有双斜杠
                assert "//" not in call_url.replace("http://", "")


# ============ 5. Sync 流程集成测试 ============

class TestSyncProfileIntegration:
    """测试 sync_profile 同时推送 Flow2API 和 Gemini"""

    @pytest.mark.asyncio
    async def test_sync_profile_both_targets(self):
        """同步应同时推送到 Flow2API 和 Gemini API"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_profile = {
            "id": 1, "name": "TestUser", "email": "test@gmail.com",
            "error_count": 0, "sync_count": 0,
        }

        with patch("token_updater.updater.profile_db") as mock_db, \
             patch("token_updater.updater.browser_manager") as mock_bm, \
             patch("token_updater.updater.config") as mock_config:

            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            # browser 返回两种 token
            mock_bm.extract_token = AsyncMock(return_value={
                "flow2api_token": "session_tok_abc",
                "gemini_cookies": {"psid": "psid_123", "psidts": "psidts_456"},
            })

            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "gem_tok"
            mock_config.connection_token = "flow_tok"
            mock_config.flow2api_url = "http://flow:8000"

            # Mock 两个推送方法
            syncer._push_to_flow2api = AsyncMock(return_value={
                "success": True, "action": "updated", "email": "test@gmail.com"
            })
            syncer._push_to_gemini_api = AsyncMock(return_value={
                "success": True, "action": "Token updated", "id": "abc"
            })

            result = await syncer.sync_profile(1)

            assert result["success"] is True
            syncer._push_to_flow2api.assert_called_once_with("session_tok_abc")
            syncer._push_to_gemini_api.assert_called_once_with(
                {"psid": "psid_123", "psidts": "psidts_456"}, "TestUser"
            )

    @pytest.mark.asyncio
    async def test_sync_profile_only_gemini(self):
        """只有 Gemini cookie 没有 Flow2API token 也应成功"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_profile = {
            "id": 1, "name": "GeminiOnly", "email": "",
            "error_count": 0, "sync_count": 0,
        }

        with patch("token_updater.updater.profile_db") as mock_db, \
             patch("token_updater.updater.browser_manager") as mock_bm, \
             patch("token_updater.updater.config") as mock_config:

            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            mock_bm.extract_token = AsyncMock(return_value={
                "flow2api_token": None,
                "gemini_cookies": {"psid": "psid_only", "psidts": "psidts_only"},
            })

            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "tok"
            mock_config.connection_token = ""
            mock_config.flow2api_url = ""

            syncer._push_to_flow2api = AsyncMock()
            syncer._push_to_gemini_api = AsyncMock(return_value={"success": True, "action": "ok"})

            result = await syncer.sync_profile(1)

            assert result["success"] is True
            # Flow2API 不应被调用（token 为 None）
            syncer._push_to_flow2api.assert_not_called()
            syncer._push_to_gemini_api.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_profile_no_tokens(self):
        """两种 token 都没有应返回失败"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_profile = {
            "id": 1, "name": "NoTokens", "email": "",
            "error_count": 0, "sync_count": 0,
        }

        with patch("token_updater.updater.profile_db") as mock_db, \
             patch("token_updater.updater.browser_manager") as mock_bm, \
             patch("token_updater.updater.config") as mock_config:

            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            mock_bm.extract_token = AsyncMock(return_value={
                "flow2api_token": None,
                "gemini_cookies": {},
            })

            result = await syncer.sync_profile(1)
            assert result["success"] is False
            assert "Token" in result["error"]

    @pytest.mark.asyncio
    async def test_sync_profile_gemini_disabled(self):
        """未配置 Gemini API 时不应推送"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        mock_profile = {
            "id": 1, "name": "FlowOnly", "email": "test@gmail.com",
            "error_count": 0, "sync_count": 0,
        }

        with patch("token_updater.updater.profile_db") as mock_db, \
             patch("token_updater.updater.browser_manager") as mock_bm, \
             patch("token_updater.updater.config") as mock_config:

            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            mock_bm.extract_token = AsyncMock(return_value={
                "flow2api_token": "session_tok",
                "gemini_cookies": {"psid": "psid_val"},
            })

            mock_config.gemini_api_url = ""  # 未配置
            mock_config.connection_token = "flow_tok"
            mock_config.flow2api_url = "http://flow:8000"

            syncer._push_to_flow2api = AsyncMock(return_value={
                "success": True, "action": "updated", "email": "test@gmail.com"
            })
            syncer._push_to_gemini_api = AsyncMock()

            result = await syncer.sync_profile(1)

            assert result["success"] is True
            syncer._push_to_flow2api.assert_called_once()
            # Gemini 不应被调用（未配置 URL）
            syncer._push_to_gemini_api.assert_not_called()


# ============ 6. 状态报告测试 ============

class TestStatusReport:
    """测试 get_status 包含 Gemini 信息"""

    def test_syncer_status_includes_gemini(self):
        """TokenSyncer.get_status 应包含 Gemini 字段"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.flow2api_url = "http://flow:8000"
            mock_config.connection_token = "tok"
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "gem_tok"
            mock_config.refresh_interval = 60

            status = syncer.get_status()
            assert "gemini_api_url" in status
            assert status["gemini_api_url"] == "http://gemini:9000"
            assert "has_gemini_connection_token" in status
            assert status["has_gemini_connection_token"] is True
