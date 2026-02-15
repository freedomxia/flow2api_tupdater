"""
测试统计卡片前后端一致性
验证 HTML 中的 element ID、JS load() 引用的字段名、后端 get_status() 返回值三者对齐
"""
import os
import re
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HTML_PATH = os.path.join(
    os.path.dirname(__file__), "..", "token_updater", "static", "index.html"
)


def _read_html() -> str:
    with open(HTML_PATH, "r", encoding="utf-8") as f:
        return f.read()


# ============ 1. HTML 结构测试 ============


class TestStatsCardsHTML:
    """验证统计卡片的 HTML 结构"""

    def test_required_stat_ids_exist(self):
        """6 个统计卡片 ID 必须全部存在"""
        html = _read_html()
        required_ids = [
            "s-total",
            "s-login",
            "s-flow-sync",
            "s-flow-err",
            "s-gem-sync",
            "s-gem-err",
        ]
        for eid in required_ids:
            assert f'id="{eid}"' in html, f"缺少统计卡片 id={eid}"

    def test_old_stat_ids_removed(self):
        """旧的 s-sync / s-err 不应作为 id 出现（s-err 已被替换）"""
        html = _read_html()
        # s-sync 完全不应存在
        assert 'id="s-sync"' not in html, "旧 id s-sync 仍然存在"
        # s-err 也不应存在（已拆分为 s-flow-err 和 s-gem-err）
        assert 'id="s-err"' not in html, "旧 id s-err 仍然存在"

    def test_stat_cards_count(self):
        """应有 6 个 stat-card"""
        html = _read_html()
        # 只统计 renderMain 模板中的 stat-card（在 JS 模板字符串里）
        count = html.count('class="stat-card"')
        assert count == 6, f"期望 6 个 stat-card，实际 {count}"

    def test_stat_labels_present(self):
        """统计卡片应包含正确的中文标签"""
        html = _read_html()
        labels = [
            "Profile",
            "已登录",
            "Flow2API 成功",
            "Flow2API 失败",
            "Gemini 成功",
            "Gemini 失败",
        ]
        for label in labels:
            assert label in html, f"缺少统计标签: {label}"

    def test_no_orphan_total_error_card(self):
        """不应有笼统的「失败」卡片（已拆分为 Flow2API/Gemini 各自的失败）"""
        html = _read_html()
        # 在 stat-card 区域内不应有单独的 "失败" 标签（不带前缀）
        # 匹配 <div class="label">失败</div> 这种模式
        pattern = r'class="label">\s*失败\s*<'
        assert not re.search(pattern, html), "存在笼统的「失败」卡片，应拆分为 Flow2API/Gemini"


# ============ 2. JS load() 字段引用测试 ============


class TestLoadFunctionReferences:
    """验证 JS load() 函数引用的 DOM ID 和 API 字段"""

    def test_load_references_correct_stat_ids(self):
        """load() 应引用新的统计 ID"""
        html = _read_html()
        # 提取 load 函数体
        assert "getElementById('s-flow-sync')" in html
        assert "getElementById('s-flow-err')" in html
        assert "getElementById('s-gem-sync')" in html
        assert "getElementById('s-gem-err')" in html

    def test_load_no_old_references(self):
        """load() 不应引用旧的 s-sync / s-err"""
        html = _read_html()
        assert "getElementById('s-sync')" not in html, "load() 仍引用旧 id s-sync"
        assert "getElementById('s-err')" not in html, "load() 仍引用旧 id s-err"

    def test_load_reads_syncer_separate_counts(self):
        """load() 应从 st.syncer 读取分离的计数字段"""
        html = _read_html()
        assert "st.syncer.flow2api_sync_count" in html
        assert "st.syncer.flow2api_error_count" in html
        assert "st.syncer.gemini_sync_count" in html
        assert "st.syncer.gemini_error_count" in html

    def test_load_no_old_total_fields(self):
        """load() 不应引用旧的 total_sync_count / total_error_count"""
        html = _read_html()
        assert "st.syncer.total_sync_count" not in html, \
            "load() 仍引用旧字段 total_sync_count"
        assert "st.syncer.total_error_count" not in html, \
            "load() 仍引用旧字段 total_error_count"


# ============ 3. Gemini 配置 UI 测试 ============


class TestGeminiConfigUI:
    """验证 Gemini 配置区域的 HTML 元素"""

    def test_gemini_config_inputs_exist(self):
        """Gemini 配置输入框应存在"""
        html = _read_html()
        assert 'id="c-gemini-url"' in html
        assert 'id="c-gemini-token"' in html

    def test_gemini_config_labels(self):
        """Gemini 配置应有正确的标签"""
        html = _read_html()
        assert "Gemini API 地址" in html
        assert "Gemini 连接 Token" in html

    def test_save_config_sends_gemini_fields(self):
        """saveConfig() 应发送 gemini_api_url 和 gemini_connection_token"""
        html = _read_html()
        assert "body.gemini_api_url" in html
        assert "body.gemini_connection_token" in html

    def test_load_populates_gemini_config(self):
        """load() 应填充 Gemini 配置值"""
        html = _read_html()
        assert "cfg.gemini_api_url" in html
        assert "cfg.gemini_connection_token_preview" in html


# ============ 4. 后端 get_status 字段测试 ============


class TestSyncerStatusFields:
    """验证 TokenSyncer.get_status() 返回前端需要的所有字段"""

    def test_status_has_separate_counts(self):
        """get_status 应返回分离的 flow2api/gemini 计数"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.flow2api_url = "http://flow:8000"
            mock_config.connection_token = "tok"
            mock_config.gemini_api_url = "http://gemini:9000"
            mock_config.gemini_connection_token = "gem"
            mock_config.refresh_interval = 60

            status = syncer.get_status()

            # 前端 load() 需要的 4 个字段
            assert "flow2api_sync_count" in status
            assert "flow2api_error_count" in status
            assert "gemini_sync_count" in status
            assert "gemini_error_count" in status

    def test_status_counts_increment_correctly(self):
        """计数器应正确递增"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()
        syncer._flow2api_sync_count = 3
        syncer._flow2api_error_count = 1
        syncer._gemini_sync_count = 5
        syncer._gemini_error_count = 2

        with patch("token_updater.updater.config") as mock_config:
            mock_config.flow2api_url = ""
            mock_config.connection_token = ""
            mock_config.gemini_api_url = ""
            mock_config.gemini_connection_token = ""
            mock_config.refresh_interval = 60

            status = syncer.get_status()

            assert status["flow2api_sync_count"] == 3
            assert status["flow2api_error_count"] == 1
            assert status["gemini_sync_count"] == 5
            assert status["gemini_error_count"] == 2
            assert status["total_sync_count"] == 8
            assert status["total_error_count"] == 3


# ============ 5. 前后端字段名交叉验证 ============


class TestFrontendBackendConsistency:
    """交叉验证前端 JS 引用的字段名与后端返回的字段名一致"""

    def test_syncer_fields_match_frontend(self):
        """后端 syncer status 的 key 应覆盖前端 load() 引用的所有字段"""
        from token_updater.updater import TokenSyncer
        syncer = TokenSyncer()

        with patch("token_updater.updater.config") as mock_config:
            mock_config.flow2api_url = ""
            mock_config.connection_token = ""
            mock_config.gemini_api_url = ""
            mock_config.gemini_connection_token = ""
            mock_config.refresh_interval = 60

            status_keys = set(syncer.get_status().keys())

        html = _read_html()
        # 从 HTML 中提取 st.syncer.xxx 引用
        frontend_refs = set(re.findall(r"st\.syncer\.(\w+)", html))

        # 前端引用的每个字段都必须在后端返回中存在
        missing = frontend_refs - status_keys
        assert not missing, f"前端引用了后端不存在的字段: {missing}"

    def test_config_fields_match_frontend(self):
        """后端 /api/config 返回的 key 应覆盖前端 load() 引用的 cfg.xxx"""
        html = _read_html()
        # 从 HTML 中提取 cfg.xxx 引用
        frontend_cfg_refs = set(re.findall(r"cfg\.(\w+)", html))

        # 模拟 get_config 返回的字段
        expected_config_keys = {
            "flow2api_url",
            "refresh_interval",
            "has_connection_token",
            "connection_token_preview",
            "has_api_key",
            "enable_vnc",
            "gemini_api_url",
            "has_gemini_connection_token",
            "gemini_connection_token_preview",
        }

        missing = frontend_cfg_refs - expected_config_keys
        assert not missing, f"前端引用了 /api/config 不返回的字段: {missing}"
