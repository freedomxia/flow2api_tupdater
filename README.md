# Flow2API Token Updater v3.0

轻量版 Token 自动更新工具，通过 Playwright 持久化 Profile 管理 Google Labs 登录状态，并用 Headless 模式定时刷新 Token。

## 特性

- 🪶 轻量化：VNC/Xvfb/noVNC 按需启动（仅登录时运行），降低常驻内存占用
- 🔄 自动刷新：定时刷新 Token 并推送到 Flow2API
- 👥 多 Profile：支持管理多个账号（Profile 级隔离）
- 🌐 代理支持：每个 Profile 可配置独立代理
- 🖥️ 可视化登录：需要时开启 VNC 登录，关闭浏览器后自动停止以省内存

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/genz27/flow2api_tupdater.git
cd flow2api_tupdater

# 配置环境变量
cp .env.example .env
# 编辑 .env 设置 ADMIN_PASSWORD 等

# 启动（或更新后重建）
docker compose up -d --build

```

访问 http://localhost:8002 进入管理界面。

## 使用流程

1. 创建 Profile
2. 点击「登录」→ 打开 VNC 完成 Google 登录
3. 点击「关闭浏览器」保存状态（VNC 会自动停止以节省内存）
4. 配置 Flow2API 连接信息（`FLOW2API_URL` / `CONNECTION_TOKEN`）
5. 开始自动同步

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| ADMIN_PASSWORD | 管理界面密码 | admin123 |
| API_KEY | 外部 API 密钥 | - |
| FLOW2API_URL | Flow2API 地址 | http://host.docker.internal:8000 |
| CONNECTION_TOKEN | Flow2API 连接 Token | - |
| REFRESH_INTERVAL | 刷新间隔(分钟) | 60 |
| ENABLE_VNC | 是否启用 VNC 登录入口(1/0) | 1 |
| VNC_PASSWORD | VNC 密码（开启 VNC 时使用） | flow2api |

## API

### 外部 API (需要 X-API-Key)

- `GET /v1/profiles` - 列出所有 Profile
- `GET /v1/profiles/{id}/token` - 获取 Token
- `POST /v1/profiles/{id}/sync` - 同步到 Flow2API

## 从 v2.0 升级

v3.1 使用持久化 Profile 登录（按需启停 VNC 以降低内存）：

1. 备份 `data/` 目录
2. 拉取新版本
3. 重新构建镜像
4. 如需重新授权：进入管理界面逐个 Profile 点击「登录」完成 Google 登录

## 更新日志

### 2025-02-20

- 重构 `browser.py`：优化浏览器模块，改进 Token 刷新逻辑和稳定性
- 新增测试用例：
  - `test_token_refresh.py` — Token 刷新核心流程测试
  - `test_token_refresh_edge_cases.py` — Token 刷新边界情况测试
  - `test_token_refresh_integration.py` — Token 刷新集成测试
  - `test_extract_flow.py` — 提取流程测试
- 更新 `test_cookie_persistence.py`：完善 Cookie 持久化测试
- 新增 `docker-compose.test.yml`：测试环境 Docker 配置
- 更新 `.gitignore`：忽略 `.DS_Store` 等无关文件

## License

MIT
