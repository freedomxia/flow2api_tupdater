"""
conftest.py - 在 import 模块之前 patch 掉 Docker 路径
"""
import os
import sys
import tempfile
import logging

# 设置临时目录
_tmpdir = tempfile.mkdtemp(prefix="flow2api_test_")

# 设置环境变量
os.environ["CONFIG_FILE"] = os.path.join(_tmpdir, "config.json")
os.environ.setdefault("ADMIN_PASSWORD", "test")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 1. Patch config 的路径
import token_updater.config as _cfg
_cfg.config.db_path = os.path.join(_tmpdir, "profiles.db")
_cfg.config.profiles_dir = os.path.join(_tmpdir, "profiles")
_cfg.config.config_file = os.path.join(_tmpdir, "config.json")

# 2. 预先创建 logger 模块的 mock，避免它尝试写 /app/logs
import types
_logger_mod = types.ModuleType("token_updater.logger")
_logger_mod.logger = logging.getLogger("token_updater_test")
sys.modules["token_updater.logger"] = _logger_mod

# 3. 预先创建 database 模块的 mock，避免它尝试写 /app/data
from unittest.mock import AsyncMock, MagicMock
_db_mod = types.ModuleType("token_updater.database")
_mock_db = MagicMock()
_mock_db.get_profile = AsyncMock(return_value=None)
_mock_db.get_all_profiles = AsyncMock(return_value=[])
_mock_db.get_active_profiles = AsyncMock(return_value=[])
_mock_db.update_profile = AsyncMock()
_mock_db.add_profile = AsyncMock(return_value=1)
_mock_db.delete_profile = AsyncMock()
_mock_db.get_profile_by_name = AsyncMock(return_value=None)
_db_mod.profile_db = _mock_db
_db_mod.ProfileDB = MagicMock
sys.modules["token_updater.database"] = _db_mod

# 4. Mock proxy_utils
_proxy_mod = types.ModuleType("token_updater.proxy_utils")
_proxy_mod.parse_proxy = lambda x: None
_proxy_mod.format_proxy_for_playwright = lambda x: x
_proxy_mod.validate_proxy_format = lambda x: (True, "ok")
sys.modules["token_updater.proxy_utils"] = _proxy_mod
