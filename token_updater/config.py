"""Token Updater 配置 v3.1"""
from __future__ import annotations
import json
import os
from pydantic import BaseModel


PERSIST_KEYS = ("flow2api_url", "connection_token", "refresh_interval", "gemini_api_url", "gemini_connection_token", "gemini_refresh_interval", "gcli2api_url", "gcli2api_password")


def _get_env(name: str) -> str | None:
    value = os.getenv(name)
    return value if value else None


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_persisted(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_persisted(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


class Config(BaseModel):
    admin_password: str
    api_key: str
    flow2api_url: str
    connection_token: str
    refresh_interval: int
    enable_vnc: bool
    profiles_dir: str = "/app/profiles"
    labs_url: str = "https://labs.google/fx/tools/flow"
    login_url: str = "https://labs.google/fx/api/auth/signin/google"
    session_cookie_name: str = "__Secure-next-auth.session-token"
    gemini_api_url: str = ""
    gemini_connection_token: str = ""
    gemini_login_url: str = "https://gemini.google.com"
    gemini_refresh_interval: int = 30
    gcli2api_url: str = ""
    gcli2api_password: str = ""
    gcli2api_refresh_interval: int = 360
    api_port: int
    db_path: str = "/app/data/profiles.db"
    session_ttl_minutes: int
    config_file: str

    def save(self) -> None:
        data = {key: getattr(self, key) for key in PERSIST_KEYS}
        _save_persisted(self.config_file, data)


def _build_config() -> Config:
    config_file = _get_env("CONFIG_FILE") or "/app/data/config.json"
    persisted = _load_persisted(config_file)

    flow2api_url = _get_env("FLOW2API_URL") or persisted.get("flow2api_url") or "http://host.docker.internal:8000"
    connection_token = _get_env("CONNECTION_TOKEN") or persisted.get("connection_token", "")
    refresh_interval = _parse_int(_get_env("REFRESH_INTERVAL") or str(persisted.get("refresh_interval", 60)), 60)
    enable_vnc = _parse_bool(_get_env("ENABLE_VNC"), default=True)
    gemini_api_url = _get_env("GEMINI_API_URL") or persisted.get("gemini_api_url", "")
    gemini_connection_token = _get_env("GEMINI_CONNECTION_TOKEN") or persisted.get("gemini_connection_token", "")
    gemini_refresh_interval = _parse_int(_get_env("GEMINI_REFRESH_INTERVAL") or str(persisted.get("gemini_refresh_interval", 30)), 30)
    gcli2api_url = _get_env("GCLI2API_URL") or persisted.get("gcli2api_url", "")
    gcli2api_password = _get_env("GCLI2API_PASSWORD") or persisted.get("gcli2api_password", "")
    gcli2api_refresh_interval = _parse_int(_get_env("GCLI2API_REFRESH_INTERVAL") or str(persisted.get("gcli2api_refresh_interval", 360)), 360)

    return Config(
        admin_password=_get_env("ADMIN_PASSWORD") or "",
        api_key=_get_env("API_KEY") or "",
        flow2api_url=flow2api_url,
        connection_token=connection_token,
        refresh_interval=refresh_interval,
        enable_vnc=enable_vnc,
        gemini_api_url=gemini_api_url,
        gemini_connection_token=gemini_connection_token,
        gemini_refresh_interval=gemini_refresh_interval,
        gcli2api_url=gcli2api_url,
        gcli2api_password=gcli2api_password,
        gcli2api_refresh_interval=gcli2api_refresh_interval,
        api_port=_parse_int(_get_env("API_PORT"), 8002),
        session_ttl_minutes=_parse_int(_get_env("SESSION_TTL_MINUTES"), 1440),
        config_file=config_file,
    )


config = _build_config()
