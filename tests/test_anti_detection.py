"""
test_anti_detection.py - 反自动化检测配置的单元测试

验证思路 A（静态审计）：检查常量定义、参数内容、UA 版本等是否符合预期。
"""
import re
import pytest


class TestBrowserArgs:
    """验证 BROWSER_ARGS 常量"""

    def test_has_disable_automation_controlled(self):
        from token_updater.browser import BROWSER_ARGS
        assert "--disable-blink-features=AutomationControlled" in BROWSER_ARGS

    def test_no_single_process(self):
        """--single-process 容易被检测，应使用 --renderer-process-limit 替代"""
        from token_updater.browser import BROWSER_ARGS
        assert "--single-process" not in BROWSER_ARGS

    def test_has_renderer_limit(self):
        from token_updater.browser import BROWSER_ARGS
        assert any("--renderer-process-limit" in a for a in BROWSER_ARGS)

    def test_no_sandbox_for_docker(self):
        """Docker 环境必须有 --no-sandbox"""
        from token_updater.browser import BROWSER_ARGS
        assert "--no-sandbox" in BROWSER_ARGS


class TestVNCBrowserArgs:
    """验证 VNC_BROWSER_ARGS（VNC 登录专用，更轻量）"""

    def test_has_disable_automation_controlled(self):
        from token_updater.browser import VNC_BROWSER_ARGS
        assert "--disable-blink-features=AutomationControlled" in VNC_BROWSER_ARGS

    def test_no_heavy_flags(self):
        """VNC 模式不应有过多限制性参数"""
        from token_updater.browser import VNC_BROWSER_ARGS
        assert "--disable-gpu" not in VNC_BROWSER_ARGS
        assert "--single-process" not in VNC_BROWSER_ARGS

    def test_fewer_args_than_headless(self):
        from token_updater.browser import BROWSER_ARGS, VNC_BROWSER_ARGS
        assert len(VNC_BROWSER_ARGS) < len(BROWSER_ARGS)


class TestUserAgent:
    """验证 USER_AGENT 字符串"""

    def test_chrome_version_at_least_130(self):
        from token_updater.browser import USER_AGENT
        match = re.search(r"Chrome/(\d+)\.", USER_AGENT)
        assert match, "USER_AGENT 中未找到 Chrome 版本号"
        version = int(match.group(1))
        assert version >= 130, f"Chrome 版本 {version} 过旧，应 >= 130"

    def test_not_headless_chrome(self):
        from token_updater.browser import USER_AGENT
        assert "HeadlessChrome" not in USER_AGENT

    def test_windows_platform(self):
        """伪装为 Windows 平台（最常见）"""
        from token_updater.browser import USER_AGENT
        assert "Windows NT 10.0" in USER_AGENT


class TestViewportPool:
    """验证 VIEWPORT_POOL"""

    def test_pool_not_empty(self):
        from token_updater.browser import VIEWPORT_POOL
        assert len(VIEWPORT_POOL) >= 5

    def test_all_have_width_height(self):
        from token_updater.browser import VIEWPORT_POOL
        for vp in VIEWPORT_POOL:
            assert "width" in vp and "height" in vp
            assert vp["width"] >= 1024
            assert vp["height"] >= 720

    def test_deterministic_selection(self):
        """同一 profile_id 每次选取的 viewport 应一致"""
        from token_updater.browser import BrowserManager
        bm = BrowserManager()
        vp1 = bm._get_viewport(42)
        vp2 = bm._get_viewport(42)
        assert vp1 == vp2

    def test_different_profiles_can_differ(self):
        """不同 profile_id 应能选到不同 viewport"""
        from token_updater.browser import BrowserManager, VIEWPORT_POOL
        bm = BrowserManager()
        viewports = {tuple(bm._get_viewport(i).items()) for i in range(len(VIEWPORT_POOL))}
        assert len(viewports) == len(VIEWPORT_POOL)


class TestStealthJS:
    """验证 STEALTH_JS 脚本内容"""

    def test_hides_webdriver(self):
        from token_updater.browser import STEALTH_JS
        assert "navigator" in STEALTH_JS
        assert "webdriver" in STEALTH_JS

    def test_fakes_chrome_runtime(self):
        from token_updater.browser import STEALTH_JS
        assert "chrome.runtime" in STEALTH_JS

    def test_fakes_plugins(self):
        from token_updater.browser import STEALTH_JS
        assert "plugins" in STEALTH_JS
        assert "Chrome PDF" in STEALTH_JS

    def test_hides_playwright_globals(self):
        from token_updater.browser import STEALTH_JS
        assert "__playwright" in STEALTH_JS
        assert "__pw_manual" in STEALTH_JS

    def test_overrides_permissions_query(self):
        from token_updater.browser import STEALTH_JS
        assert "permissions.query" in STEALTH_JS


class TestLaunchCallsConsistency:
    """验证思路 B（静态代码审计）：检查源码中所有 launch_persistent_context 调用"""

    def _get_source(self):
        import inspect
        from token_updater.browser import BrowserManager
        return inspect.getsource(BrowserManager)

    def test_no_old_user_agent_string(self):
        """确保没有残留的旧 Chrome/120 UA 字符串"""
        src = self._get_source()
        assert "Chrome/120" not in src, "发现残留的旧 UA 字符串 Chrome/120"

    def test_no_hardcoded_viewport(self):
        """确保没有硬编码的 viewport（应使用 _get_viewport）"""
        src = self._get_source()
        # 排除 VIEWPORT_POOL 定义本身，检查 launch 调用中的硬编码
        # 在方法体中不应出现 viewport={"width": 1024
        import re
        # 查找 launch_persistent_context 调用块中的硬编码 viewport
        matches = re.findall(r'viewport=\{"width":\s*\d+', src)
        assert len(matches) == 0, f"发现硬编码 viewport: {matches}"

    def test_uses_user_agent_constant(self):
        """确保使用 USER_AGENT 常量而非内联字符串"""
        src = self._get_source()
        assert "user_agent=USER_AGENT" in src or "user_agent = USER_AGENT" in src

    def test_enable_automation_excluded(self):
        """所有 launch 调用都应排除 --enable-automation"""
        src = self._get_source()
        launch_count = src.count("launch_persistent_context")
        exclude_count = src.count('ignore_default_args=["--enable-automation"]')
        assert launch_count == exclude_count, (
            f"launch_persistent_context 调用 {launch_count} 次，"
            f"但 ignore_default_args 只出现 {exclude_count} 次"
        )
