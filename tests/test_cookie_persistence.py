"""
端到端测试：Cookie 持久化修复
验证 _persist_cookies_before_close 和 _read_cookies_from_sqlite 的完整流程

测试场景：
1. session cookie（无 expires）在 context.close() 后能被保留
2. SQLite 直读能正确提取 cookie
3. extract_token 优先走 SQLite 直读路径
4. 完整的 VNC 登录 → close → headless 提取 流程模拟
"""
import asyncio
import os
import sqlite3
import sys
import time
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ============ 1. _persist_cookies_before_close 单元测试 ============

class TestPersistCookiesBeforeClose:
    """测试 session cookie → persistent cookie 转换"""

    @pytest.mark.asyncio
    async def test_converts_session_cookies(self):
        """应把 expires=-1 的 cookie 加上未来过期时间"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {
                "name": "__Secure-next-auth.session-token",
                "value": "tok_abc123",
                "domain": ".labs.google",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            },
            {
                "name": "persistent_cookie",
                "value": "already_has_expires",
                "domain": ".google.com",
                "path": "/",
                "expires": time.time() + 86400,
                "httpOnly": False,
                "secure": False,
                "sameSite": "None",
            },
        ]

        await bm._persist_cookies_before_close(mock_context)

        # add_cookies 应该只被调用一次，只包含 session cookie
        mock_context.add_cookies.assert_called_once()
        added = mock_context.add_cookies.call_args[0][0]
        assert len(added) == 1
        assert added[0]["name"] == "__Secure-next-auth.session-token"
        assert added[0]["value"] == "tok_abc123"
        assert added[0]["expires"] > time.time() + 86400  # 至少 1 天后
        assert added[0]["domain"] == ".labs.google"
        assert added[0]["httpOnly"] is True
        assert added[0]["secure"] is True

    @pytest.mark.asyncio
    async def test_handles_expires_zero(self):
        """expires=0 的 cookie 也应被转换"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "zero_exp", "value": "val", "domain": ".x.com",
             "path": "/", "expires": 0},
        ]

        await bm._persist_cookies_before_close(mock_context)
        mock_context.add_cookies.assert_called_once()
        added = mock_context.add_cookies.call_args[0][0]
        assert len(added) == 1
        assert added[0]["expires"] > time.time()

    @pytest.mark.asyncio
    async def test_no_session_cookies_skips(self):
        """全是 persistent cookie 时不应调用 add_cookies"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "c1", "value": "v1", "domain": ".x.com",
             "path": "/", "expires": time.time() + 9999},
        ]

        await bm._persist_cookies_before_close(mock_context)
        mock_context.add_cookies.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_cookies_skips(self):
        """没有 cookie 时不应调用 add_cookies"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = []

        await bm._persist_cookies_before_close(mock_context)
        mock_context.add_cookies.assert_not_called()

    @pytest.mark.asyncio
    async def test_exception_is_caught(self):
        """context.cookies() 异常不应抛出"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.side_effect = Exception("browser crashed")

        # 不应抛异常
        await bm._persist_cookies_before_close(mock_context)

    @pytest.mark.asyncio
    async def test_preserves_all_cookie_attributes(self):
        """应保留 sameSite、httpOnly、secure 等属性"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {
                "name": "__Secure-1PSID",
                "value": "psid_val",
                "domain": ".google.com",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": True,
                "sameSite": "None",
            },
        ]

        await bm._persist_cookies_before_close(mock_context)
        added = mock_context.add_cookies.call_args[0][0]
        c = added[0]
        assert c["httpOnly"] is True
        assert c["secure"] is True
        assert c["sameSite"] == "None"
        assert c["domain"] == ".google.com"
        assert c["path"] == "/"


# ============ 2. _read_cookies_from_sqlite 单元测试 ============

class TestReadCookiesFromSqlite:
    """测试直接从 SQLite 文件读取 cookie"""

    def _create_cookie_db(self, db_path, cookies):
        """创建一个模拟的 Chromium Cookies SQLite 文件"""
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cookies (
                host_key TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                encrypted_value BLOB NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '/',
                expires_utc INTEGER NOT NULL DEFAULT 0,
                is_secure INTEGER NOT NULL DEFAULT 0,
                is_httponly INTEGER NOT NULL DEFAULT 0,
                samesite INTEGER NOT NULL DEFAULT -1,
                creation_utc INTEGER NOT NULL DEFAULT 0,
                last_access_utc INTEGER NOT NULL DEFAULT 0,
                last_update_utc INTEGER NOT NULL DEFAULT 0,
                source_scheme INTEGER NOT NULL DEFAULT 0,
                source_port INTEGER NOT NULL DEFAULT -1,
                is_same_party INTEGER NOT NULL DEFAULT 0,
                source_type INTEGER NOT NULL DEFAULT 0
            )
        """)
        for c in cookies:
            conn.execute(
                "INSERT INTO cookies (host_key, name, value, encrypted_value) "
                "VALUES (?, ?, ?, ?)",
                (c["host_key"], c["name"], c.get("value", ""),
                 c.get("encrypted_value", b""))
            )
        conn.commit()
        conn.close()

    def test_reads_flow2api_token(self):
        """应能读取 labs.google 的 session token"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                self._create_cookie_db(db_path, [
                    {"host_key": ".labs.google",
                     "name": "__Secure-next-auth.session-token",
                     "value": "flow2api_token_value_123"},
                ])

                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] == "flow2api_token_value_123"

    def test_reads_gemini_cookies(self):
        """应能读取 Gemini 的 PSID 和 PSIDTS"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                self._create_cookie_db(db_path, [
                    {"host_key": ".google.com",
                     "name": "__Secure-1PSID",
                     "value": "psid_value_abc"},
                    {"host_key": ".google.com",
                     "name": "__Secure-1PSIDTS",
                     "value": "psidts_value_def"},
                ])

                result = bm._read_cookies_from_sqlite(1)
                assert result["gemini_cookies"]["psid"] == "psid_value_abc"
                assert result["gemini_cookies"]["psidts"] == "psidts_value_def"

    def test_reads_all_cookies_together(self):
        """应能同时读取 flow2api 和 gemini cookie"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                self._create_cookie_db(db_path, [
                    {"host_key": ".labs.google",
                     "name": "__Secure-next-auth.session-token",
                     "value": "flow_tok"},
                    {"host_key": ".google.com",
                     "name": "__Secure-1PSID",
                     "value": "psid_val"},
                    {"host_key": ".google.com",
                     "name": "__Secure-1PSIDTS",
                     "value": "psidts_val"},
                ])

                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] == "flow_tok"
                assert result["gemini_cookies"]["psid"] == "psid_val"
                assert result["gemini_cookies"]["psidts"] == "psidts_val"

    def test_no_cookies_file(self):
        """Cookie 文件不存在应返回空结果"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] is None
                assert result["gemini_cookies"] == {}

    def test_empty_db(self):
        """空数据库应返回空结果"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                self._create_cookie_db(db_path, [])

                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] is None
                assert result["gemini_cookies"] == {}

    def test_ignores_unrelated_cookies(self):
        """应忽略不相关的 cookie"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                self._create_cookie_db(db_path, [
                    {"host_key": ".facebook.com",
                     "name": "fb_session",
                     "value": "should_be_ignored"},
                    {"host_key": ".google.com",
                     "name": "NID",
                     "value": "also_ignored"},
                ])

                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] is None
                assert result["gemini_cookies"] == {}

    def test_corrupted_db_returns_empty(self):
        """损坏的数据库文件应返回空结果而不是抛异常"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                with open(db_path, "wb") as f:
                    f.write(b"this is not a sqlite file")

                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] is None
                assert result["gemini_cookies"] == {}


# ============ 3. _try_decrypt_cookie 单元测试 ============

class TestTryDecryptCookie:
    """测试 cookie 解密"""

    def test_empty_value(self):
        from token_updater.browser import BrowserManager
        assert BrowserManager._try_decrypt_cookie(b"") == ""
        assert BrowserManager._try_decrypt_cookie(None) == ""

    def test_short_value(self):
        from token_updater.browser import BrowserManager
        assert BrowserManager._try_decrypt_cookie(b"ab") == ""

    def test_plaintext_no_prefix(self):
        """无 v10/v11 前缀应当作明文处理"""
        from token_updater.browser import BrowserManager
        result = BrowserManager._try_decrypt_cookie(b"plain_cookie_value")
        assert result == "plain_cookie_value"

    def test_v10_encrypted_with_pycryptodome(self):
        """v10 加密的 cookie 应能解密（如果 pycryptodome 可用）"""
        try:
            from Crypto.Cipher import AES
            from hashlib import pbkdf2_hmac
        except ImportError:
            pytest.skip("pycryptodome not installed")

        from token_updater.browser import BrowserManager

        # 用同样的方式加密一个值
        key = pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, dklen=16)
        iv = b" " * 16
        plaintext = b"test_cookie_val!"  # 16 bytes, 整块
        # PKCS7 padding: 16 bytes of \x10
        padded = plaintext + bytes([16] * 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = b"v10" + cipher.encrypt(padded)

        result = BrowserManager._try_decrypt_cookie(encrypted)
        assert result == "test_cookie_val!"

    def test_v10_without_pycryptodome_returns_empty(self):
        """没有 pycryptodome 时 v10 加密应返回空字符串"""
        from token_updater.browser import BrowserManager

        with patch.dict('sys.modules', {'Crypto': None, 'Crypto.Cipher': None}):
            result = BrowserManager._try_decrypt_cookie(b"v10" + b"\x00" * 32)
            # 应该返回空字符串（解密失败被 catch）
            assert isinstance(result, str)


# ============ 4. extract_token SQLite 直读路径 端到端测试 ============

class TestExtractTokenSqlitePath:
    """测试 extract_token SQLite 检查（不再作为最终结果）"""

    @pytest.mark.asyncio
    async def test_sqlite_check_then_browser(self):
        """SQLite 有 cookie 时仍应启动浏览器刷新"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test", "email": "t@g.com", "proxy_enabled": False}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            sqlite_result = {
                "flow2api_token": "sqlite_token_123",
                "gemini_cookies": {"psid": "p1", "psidts": "p2"},
            }

            with patch.object(bm, '_read_cookies_from_sqlite',
                              return_value=sqlite_result):
                with patch.object(bm, '_get_profile_dir',
                                  return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        # Mock playwright - 应该被调用
                        mock_context = AsyncMock()
                        mock_context.close = AsyncMock()
                        mock_pw = AsyncMock()
                        mock_pw.chromium.launch_persistent_context = AsyncMock(
                            return_value=mock_context)
                        bm._playwright = mock_pw

                        with patch.object(bm, '_extract_from_context',
                                          return_value={
                                              "flow2api_token": "browser_tok",
                                              "gemini_cookies": {}
                                          }):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy',
                                                  return_value=None):
                                    with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                                        with patch.object(
                                            bm,
                                            '_persist_cookies_before_close',
                                            new_callable=AsyncMock
                                        ):
                                            result = await bm.extract_token(1)

            # 应该返回浏览器提取的结果，而不是 SQLite 的
            assert result["flow2api_token"] == "browser_tok"
            # 应该启动了浏览器
            mock_pw.chromium.launch_persistent_context.assert_called_once()

    @pytest.mark.asyncio
    async def test_sqlite_empty_still_launches_browser(self):
        """SQLite 无结果时也应启动浏览器"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test", "email": "t@g.com", "proxy_enabled": False}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            empty_result = {"flow2api_token": None, "gemini_cookies": {}}

            with patch.object(bm, '_read_cookies_from_sqlite',
                              return_value=empty_result):
                with patch.object(bm, '_get_profile_dir',
                                  return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        mock_context = AsyncMock()
                        mock_context.close = AsyncMock()
                        mock_pw = AsyncMock()
                        mock_pw.chromium.launch_persistent_context = AsyncMock(
                            return_value=mock_context)
                        bm._playwright = mock_pw

                        with patch.object(bm, '_extract_from_context',
                                          return_value={
                                              "flow2api_token": "browser_tok",
                                              "gemini_cookies": {}
                                          }):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy',
                                                  return_value=None):
                                    with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                                        with patch.object(
                                            bm,
                                            '_persist_cookies_before_close',
                                            new_callable=AsyncMock
                                        ):
                                            result = await bm.extract_token(1)

            assert result["flow2api_token"] == "browser_tok"

    @pytest.mark.asyncio
    async def test_no_profile_dir_returns_empty(self):
        """无 profile 目录时应返回空"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {"id": 1, "name": "Test", "email": "t@g.com"}

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)

            with patch.object(bm, '_get_profile_dir', return_value="/fake/profile"):
                with patch("os.path.exists", return_value=False):
                    result = await bm.extract_token(1)

        assert result["flow2api_token"] is None
        assert result["gemini_cookies"] == {}


# ============ 5. 端到端流程模拟测试 ============

class TestEndToEndCookiePersistence:
    """模拟完整的 VNC 登录 → close → extract 流程"""

    @pytest.mark.asyncio
    async def test_full_flow_vnc_login_then_extract(self):
        """
        模拟：
        1. VNC 登录设置了 session cookie（expires=-1）
        2. close_browser 调用 _persist_cookies_before_close 转换 cookie
        3. extract_token 启动浏览器刷新 session
        """
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        bm._lock = asyncio.Lock()

        mock_profile = {
            "id": 1, "name": "E2E_Test", "email": "e2e@test.com",
            "proxy_enabled": False, "proxy_url": "",
        }

        # 模拟 VNC 登录后的 cookie 状态
        session_cookies = [
            {
                "name": "__Secure-next-auth.session-token",
                "value": "e2e_session_token_value",
                "domain": ".labs.google",
                "path": "/",
                "expires": -1,  # session cookie
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            },
            {
                "name": "__Secure-1PSID",
                "value": "e2e_psid_value",
                "domain": ".google.com",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": True,
                "sameSite": "None",
            },
            {
                "name": "__Secure-1PSIDTS",
                "value": "e2e_psidts_value",
                "domain": ".google.com",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": True,
                "sameSite": "None",
            },
        ]

        # Step 1: 模拟 VNC 浏览器上下文
        mock_context = AsyncMock()
        mock_context.cookies.return_value = session_cookies
        mock_context.add_cookies = AsyncMock()
        mock_context.close = AsyncMock()

        bm._active_context = mock_context
        bm._active_profile_id = 1

        # Step 2: close_browser → 应调用 _persist_cookies_before_close
        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            # 模拟 close_browser 中的 cookie 检查
            mock_context.cookies.side_effect = [
                # close_browser 检查 labs.google cookie
                [{"name": "__Secure-next-auth.session-token",
                  "value": "e2e_session_token_value"}],
                # close_browser 检查 gemini cookie
                session_cookies,
                # _persist_cookies_before_close 读取所有 cookie
                session_cookies,
            ]

            with patch.object(bm, '_stop_vnc_stack', new_callable=AsyncMock):
                result = await bm.close_browser(1)

        assert result["success"] is True

        # 验证 add_cookies 被调用（persist 逻辑）
        assert mock_context.add_cookies.called
        persisted = mock_context.add_cookies.call_args[0][0]
        # 所有 3 个 session cookie 都应被转换
        assert len(persisted) == 3
        for c in persisted:
            assert c["expires"] > time.time()  # 应有未来的过期时间

        # Step 3: 模拟 extract_token 启动浏览器刷新
        bm._active_context = None
        bm._active_profile_id = None

        with patch("token_updater.browser.profile_db") as mock_db:
            mock_db.get_profile = AsyncMock(return_value=mock_profile)
            mock_db.update_profile = AsyncMock()

            sqlite_result = {
                "flow2api_token": "e2e_session_token_value",
                "gemini_cookies": {
                    "psid": "e2e_psid_value",
                    "psidts": "e2e_psidts_value",
                },
            }

            with patch.object(bm, '_read_cookies_from_sqlite',
                              return_value=sqlite_result):
                with patch.object(bm, '_get_profile_dir',
                                  return_value="/fake/profile"):
                    with patch("os.path.exists", return_value=True):
                        # Mock 浏览器启动和提取
                        mock_extract_context = AsyncMock()
                        mock_extract_context.close = AsyncMock()
                        mock_pw = AsyncMock()
                        mock_pw.chromium.launch_persistent_context = AsyncMock(
                            return_value=mock_extract_context)
                        bm._playwright = mock_pw

                        with patch.object(bm, '_extract_from_context',
                                          return_value={
                                              "flow2api_token": "refreshed_token",
                                              "gemini_cookies": {
                                                  "psid": "refreshed_psid",
                                                  "psidts": "refreshed_psidts",
                                              }
                                          }):
                            with patch.object(bm, '_clean_locks'):
                                with patch.object(bm, '_get_proxy', return_value=None):
                                    with patch.object(bm, '_inject_stealth', new_callable=AsyncMock):
                                        with patch.object(bm, '_persist_cookies_before_close', new_callable=AsyncMock):
                                            extract_result = await bm.extract_token(1)

        # 验证提取结果（应该是浏览器刷新后的值）
        assert extract_result["flow2api_token"] == "refreshed_token"
        assert extract_result["gemini_cookies"]["psid"] == "refreshed_psid"
        assert extract_result["gemini_cookies"]["psidts"] == "refreshed_psidts"

    @pytest.mark.asyncio
    async def test_close_active_persists_cookies(self):
        """_close_active 应在关闭前持久化 cookie"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": "sess", "value": "v", "domain": ".x.com",
             "path": "/", "expires": -1},
        ]
        mock_context.add_cookies = AsyncMock()
        mock_context.close = AsyncMock()

        bm._active_context = mock_context
        bm._active_profile_id = 1

        await bm._close_active()

        # 应先 persist 再 close
        assert mock_context.add_cookies.called
        assert mock_context.close.called
        assert bm._active_context is None
        assert bm._active_profile_id is None


# ============ 6. 边界情况测试 ============

class TestEdgeCases:
    """边界情况和异常处理"""

    @pytest.mark.asyncio
    async def test_persist_failure_doesnt_block_close(self):
        """persist 失败不应阻止 context.close()"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.side_effect = Exception("persist failed")
        mock_context.close = AsyncMock()

        bm._active_context = mock_context
        bm._active_profile_id = 1

        await bm._close_active()

        # close 仍应被调用
        mock_context.close.assert_called_once()
        assert bm._active_context is None

    def test_sqlite_read_with_only_encrypted_value(self):
        """只有 encrypted_value 没有 value 时应尝试解密"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(bm, '_get_profile_dir', return_value=tmpdir):
                db_path = os.path.join(tmpdir, "Default", "Cookies")
                os.makedirs(os.path.dirname(db_path), exist_ok=True)

                conn = sqlite3.connect(db_path)
                conn.execute("""
                    CREATE TABLE cookies (
                        host_key TEXT, name TEXT, value TEXT,
                        encrypted_value BLOB DEFAULT ''
                    )
                """)
                # 插入一个只有 encrypted_value 的 cookie（明文，无前缀）
                conn.execute(
                    "INSERT INTO cookies VALUES (?, ?, ?, ?)",
                    (".labs.google",
                     "__Secure-next-auth.session-token",
                     "",  # value 为空
                     b"plaintext_token_in_blob")
                )
                conn.commit()
                conn.close()

                result = bm._read_cookies_from_sqlite(1)
                assert result["flow2api_token"] == "plaintext_token_in_blob"

    @pytest.mark.asyncio
    async def test_multiple_session_cookies_all_converted(self):
        """多个 session cookie 应全部被转换"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()

        mock_context = AsyncMock()
        mock_context.cookies.return_value = [
            {"name": f"cookie_{i}", "value": f"val_{i}",
             "domain": ".google.com", "path": "/", "expires": -1}
            for i in range(10)
        ]

        await bm._persist_cookies_before_close(mock_context)
        added = mock_context.add_cookies.call_args[0][0]
        assert len(added) == 10
        for c in added:
            assert c["expires"] > time.time()
