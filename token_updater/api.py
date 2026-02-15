"""Token Updater API v3.1"""
import secrets
import time
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
from .browser import browser_manager
from .updater import token_syncer
from .database import profile_db
from .proxy_utils import validate_proxy_format
from .config import config
from .logger import logger

app = FastAPI(title="Flow2API Token Updater", version="3.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_sessions: dict[str, float] = {}

MAX_PROFILE_NAME_LEN = 64
MAX_REMARK_LEN = 200
MAX_PROXY_LEN = 512


def _session_ttl_seconds() -> int:
    ttl = config.session_ttl_minutes
    return max(60, ttl * 60) if ttl > 0 else 0


def _prune_sessions(now: float = None) -> None:
    now = now or time.time()
    expired = [t for t, exp in active_sessions.items() if exp and exp <= now]
    for t in expired:
        active_sessions.pop(t, None)


def _validate_name(name: str) -> str:
    clean = name.strip()
    if not clean:
        raise HTTPException(400, "名称不能为空")
    if len(clean) > MAX_PROFILE_NAME_LEN:
        raise HTTPException(400, "名称过长")
    return clean


def _validate_remark(remark: str) -> str:
    clean = remark.strip()
    if len(clean) > MAX_REMARK_LEN:
        raise HTTPException(400, "备注过长")
    return clean


def _validate_proxy(proxy_url: str) -> str:
    clean = proxy_url.strip()
    if not clean:
        return ""
    if len(clean) > MAX_PROXY_LEN:
        raise HTTPException(400, "代理地址过长")
    valid, msg = validate_proxy_format(clean)
    if not valid:
        raise HTTPException(400, f"代理格式错误: {msg}")
    return clean


# Models
class LoginRequest(BaseModel):
    password: str

class CreateProfileRequest(BaseModel):
    name: str
    remark: Optional[str] = ""
    proxy_url: Optional[str] = ""

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    remark: Optional[str] = None
    is_active: Optional[bool] = None
    proxy_url: Optional[str] = None
    proxy_enabled: Optional[bool] = None

class UpdateConfigRequest(BaseModel):
    flow2api_url: Optional[str] = None
    connection_token: Optional[str] = None
    refresh_interval: Optional[int] = None
    gemini_api_url: Optional[str] = None
    gemini_connection_token: Optional[str] = None

class ImportCookiesRequest(BaseModel):
    cookies_json: str


# Auth
async def verify_session(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    token = authorization[7:]
    now = time.time()
    _prune_sessions(now)
    expiry = active_sessions.get(token)
    if expiry is None or (expiry and expiry <= now):
        active_sessions.pop(token, None)
        raise HTTPException(401, "登录已过期")
    return token


async def verify_api_key(x_api_key: str = Header(None)):
    if not config.api_key:
        raise HTTPException(500, "未配置 API_KEY")
    if not x_api_key or not secrets.compare_digest(x_api_key, config.api_key):
        raise HTTPException(401, "Invalid API Key")
    return x_api_key


@app.post("/api/login")
async def login(request: LoginRequest):
    if not config.admin_password:
        raise HTTPException(500, "未设置 ADMIN_PASSWORD")
    if not secrets.compare_digest(request.password, config.admin_password):
        raise HTTPException(401, "密码错误")
    session_token = secrets.token_urlsafe(32)
    ttl = _session_ttl_seconds()
    active_sessions[session_token] = time.time() + ttl if ttl else 0
    return {"success": True, "token": session_token}


@app.post("/api/logout")
async def logout(token: str = Depends(verify_session)):
    active_sessions.pop(token, None)
    return {"success": True}


@app.get("/api/auth/check")
async def check_auth():
    return {"need_password": bool(config.admin_password)}


# Static
@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse("/app/token_updater/static/index.html")


# Status
@app.get("/api/status")
async def get_status(token: str = Depends(verify_session)):
    profiles = await profile_db.get_all_profiles()
    return {
        "browser": browser_manager.get_status(),
        "syncer": token_syncer.get_status(),
        "profiles": {
            "total": len(profiles),
            "logged_in": sum(1 for p in profiles if p.get("is_logged_in")),
            "active": sum(1 for p in profiles if p.get("is_active"))
        },
        "config": {
            "flow2api_url": config.flow2api_url,
            "refresh_interval": config.refresh_interval,
            "has_connection_token": bool(config.connection_token),
            "has_api_key": bool(config.api_key),
            "enable_vnc": bool(config.enable_vnc),
            "gemini_api_url": config.gemini_api_url,
            "has_gemini_connection_token": bool(config.gemini_connection_token),
        },
        "version": "3.1.0"
    }


# Profiles
@app.get("/api/profiles")
async def get_profiles(token: str = Depends(verify_session)):
    profiles = await profile_db.get_all_profiles()
    active_id = browser_manager.get_active_profile_id()
    for p in profiles:
        p["is_browser_active"] = (p["id"] == active_id)
        if p.get("proxy_url"):
            valid, msg = validate_proxy_format(p["proxy_url"])
            p["proxy_status"] = msg
            p["proxy_valid"] = bool(valid)
    return profiles


@app.post("/api/profiles")
async def create_profile(request: CreateProfileRequest, token: str = Depends(verify_session)):
    name = _validate_name(request.name)
    remark = _validate_remark(request.remark or "")
    proxy_url = _validate_proxy(request.proxy_url or "")
    if await profile_db.get_profile_by_name(name):
        raise HTTPException(400, "名称已存在")
    profile_id = await profile_db.add_profile(name, remark, proxy_url)
    return {"success": True, "profile_id": profile_id}


@app.get("/api/profiles/{profile_id}")
async def get_profile(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    profile["is_browser_active"] = (profile_id == browser_manager.get_active_profile_id())
    return profile


@app.put("/api/profiles/{profile_id}")
async def update_profile(profile_id: int, request: UpdateProfileRequest, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    update_data = {}
    if request.name is not None:
        new_name = _validate_name(request.name)
        existing = await profile_db.get_profile_by_name(new_name)
        if existing and existing.get("id") != profile_id:
            raise HTTPException(400, "名称已存在")
        update_data["name"] = new_name
    if request.remark is not None:
        update_data["remark"] = _validate_remark(request.remark)
    if request.is_active is not None:
        update_data["is_active"] = int(request.is_active)
    if request.proxy_url is not None:
        update_data["proxy_url"] = _validate_proxy(request.proxy_url)
    if request.proxy_enabled is not None:
        update_data["proxy_enabled"] = int(request.proxy_enabled)
    if update_data:
        await profile_db.update_profile(profile_id, **update_data)
    return {"success": True}


@app.delete("/api/profiles/{profile_id}")
async def delete_profile(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    await browser_manager.close_browser(profile_id)
    await browser_manager.delete_profile_data(profile_id)
    await profile_db.delete_profile(profile_id)
    return {"success": True}


# Browser
@app.post("/api/profiles/{profile_id}/launch")
async def launch_browser(profile_id: int, token: str = Depends(verify_session)):
    if not config.enable_vnc:
        raise HTTPException(400, "已禁用 VNC 登录（设置 ENABLE_VNC=1 可启用）")
    success = await browser_manager.launch_for_login(profile_id)
    if not success:
        raise HTTPException(500, "启动失败")
    return {"success": True, "message": "请通过 VNC 登录"}


@app.post("/api/profiles/{profile_id}/close")
async def close_browser(profile_id: int, token: str = Depends(verify_session)):
    result = await browser_manager.close_browser(profile_id)
    return result


@app.post("/api/profiles/{profile_id}/check-login")
async def check_login(profile_id: int, token: str = Depends(verify_session)):
    return await browser_manager.check_login_status(profile_id)


@app.post("/api/profiles/{profile_id}/import-cookies")
async def import_cookies(profile_id: int, request: ImportCookiesRequest, token: str = Depends(verify_session)):
    cookies_json = (request.cookies_json or "").strip()
    if not cookies_json:
        raise HTTPException(400, "Cookie 内容不能为空")
    result = await browser_manager.import_cookies(profile_id, cookies_json)
    if not result.get("success"):
        raise HTTPException(400, result.get("error") or "导入失败")
    return result

# Token & Sync
@app.post("/api/profiles/{profile_id}/extract")
async def extract_token(profile_id: int, token: str = Depends(verify_session)):
    extracted = await browser_manager.extract_token(profile_id)
    flow2api_token = extracted.get("flow2api_token")
    gemini_cookies = extracted.get("gemini_cookies", {})
    if flow2api_token or gemini_cookies.get("psid"):
        return {
            "success": True,
            "has_flow2api_token": bool(flow2api_token),
            "has_gemini_cookie": bool(gemini_cookies.get("psid")),
        }
    return {"success": False, "message": "未找到 Token，请先登录"}


@app.post("/api/profiles/{profile_id}/sync")
async def sync_profile(profile_id: int, token: str = Depends(verify_session)):
    return await token_syncer.sync_profile(profile_id)


@app.post("/api/sync-all")
async def sync_all(token: str = Depends(verify_session)):
    return await token_syncer.sync_all_profiles()


# Config
@app.get("/api/config")
async def get_config(token: str = Depends(verify_session)):
    return {
        "flow2api_url": config.flow2api_url,
        "refresh_interval": config.refresh_interval,
        "has_connection_token": bool(config.connection_token),
        "connection_token_preview": f"{config.connection_token[:10]}..." if config.connection_token else "",
        "has_api_key": bool(config.api_key),
        "enable_vnc": bool(config.enable_vnc),
        "gemini_api_url": config.gemini_api_url,
        "has_gemini_connection_token": bool(config.gemini_connection_token),
        "gemini_connection_token_preview": f"{config.gemini_connection_token[:10]}..." if config.gemini_connection_token else "",
    }


@app.post("/api/config")
async def update_config(request: UpdateConfigRequest, api_request: Request, token: str = Depends(verify_session)):
    old_interval = config.refresh_interval
    if request.flow2api_url is not None:
        v = request.flow2api_url.strip()
        if not v:
            raise HTTPException(400, "Flow2API 地址不能为空")
        config.flow2api_url = v
    if request.connection_token is not None:
        config.connection_token = request.connection_token.strip()
    if request.refresh_interval is not None:
        if request.refresh_interval < 1 or request.refresh_interval > 1440:
            raise HTTPException(400, "刷新间隔需在 1-1440 分钟之间")
        config.refresh_interval = request.refresh_interval
    if request.gemini_api_url is not None:
        config.gemini_api_url = request.gemini_api_url.strip()
    if request.gemini_connection_token is not None:
        config.gemini_connection_token = request.gemini_connection_token.strip()
    config.save()

    if request.refresh_interval and config.refresh_interval != old_interval:
        scheduler = getattr(api_request.app.state, "scheduler", None)
        job_id = getattr(api_request.app.state, "sync_job_id", "token_sync")
        if scheduler:
            try:
                scheduler.reschedule_job(job_id, trigger=IntervalTrigger(minutes=config.refresh_interval))
            except Exception as e:
                logger.warning(f"更新定时任务失败: {e}")
    return {"success": True}


# External API
@app.get("/v1/profiles")
async def ext_list_profiles(api_key: str = Depends(verify_api_key)):
    profiles = await profile_db.get_all_profiles()
    return {"profiles": [{"id": p["id"], "name": p["name"], "email": p.get("email"), "is_logged_in": bool(p.get("is_logged_in")), "is_active": bool(p.get("is_active"))} for p in profiles]}


@app.get("/v1/profiles/{profile_id}/token")
async def ext_get_token(profile_id: int, api_key: str = Depends(verify_api_key)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")
    if not profile.get("is_active"):
        raise HTTPException(400, "Profile is disabled")
    extracted = await browser_manager.extract_token(profile_id)
    token_value = extracted.get("flow2api_token")
    gemini_cookies = extracted.get("gemini_cookies", {})
    if not token_value and not gemini_cookies.get("psid"):
        raise HTTPException(400, "Failed to extract token")
    return {
        "success": True,
        "profile_id": profile_id,
        "profile_name": profile["name"],
        "email": profile.get("email"),
        "session_token": token_value,
        "has_gemini_cookie": bool(gemini_cookies.get("psid")),
    }


@app.post("/v1/profiles/{profile_id}/sync")
async def ext_sync_profile(profile_id: int, api_key: str = Depends(verify_api_key)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")
    return await token_syncer.sync_profile(profile_id)


# Health
@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.1.0"}
