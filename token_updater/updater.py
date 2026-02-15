"""Token 同步服务 - 按需启动浏览器"""
import httpx
from datetime import datetime
from typing import Optional, Dict, Any, List
from .config import config
from .browser import browser_manager
from .database import profile_db
from .logger import logger


class TokenSyncer:
    """Token 同步器"""
    
    def __init__(self):
        self._flow2api_sync_count = 0
        self._flow2api_error_count = 0
        self._gemini_sync_count = 0
        self._gemini_error_count = 0
        self._last_batch_time: Optional[datetime] = None
    
    async def _check_tokens_status(self, emails: List[str] = None) -> Dict[str, Any]:
        """从 Flow2API 查询 token 状态
        
        Returns:
            {
                "success": True,
                "tokens": [...],
                "needs_refresh_emails": ["email1", "email2"]
            }
        """
        if not config.connection_token:
            return {"success": False, "error": "未配置 CONNECTION_TOKEN"}
        
        url = f"{config.flow2api_url}/api/plugin/check-tokens"
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                payload = {}
                if emails:
                    payload["emails"] = emails
                
                response = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {config.connection_token}"
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    tokens = data.get("tokens", [])
                    needs_refresh_emails = [
                        t["email"] for t in tokens 
                        if t.get("needs_refresh") and t.get("is_active")
                    ]
                    return {
                        "success": True,
                        "tokens": tokens,
                        "needs_refresh_emails": needs_refresh_emails
                    }
                else:
                    return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def sync_profile(self, profile_id: int) -> Dict[str, Any]:
        """同步单个 profile"""
        profile = await profile_db.get_profile(profile_id)
        if not profile:
            return {"success": False, "error": "Profile 不存在"}
        
        logger.info(f"[{profile['name']}] 开始同步...")
        
        # 提取 token (按需启动浏览器，用完即关)
        extracted = await browser_manager.extract_token(profile_id)
        flow2api_token = extracted.get("flow2api_token")
        gemini_cookies = extracted.get("gemini_cookies", {})
        
        if not flow2api_token and not (gemini_cookies.get("psid") and gemini_cookies.get("psidts")):
            await profile_db.update_profile(
                profile_id,
                last_sync_time=datetime.now().isoformat(),
                last_sync_result="failed: no token",
                error_count=profile.get("error_count", 0) + 1
            )
            self._flow2api_error_count += 1
            self._gemini_error_count += 1
            return {"success": False, "error": "无法提取 Token，请先登录"}
        
        flow2api_result = {"success": False, "skipped": True}
        gemini_result = {"success": False, "skipped": True}
        
        # 推送到 Flow2API
        if flow2api_token:
            logger.info(f"[{profile['name']}] 提取到 Flow2API Token: {flow2api_token[:20]}...{flow2api_token[-10:]}")
            flow2api_result = await self._push_to_flow2api(flow2api_token)
        
        # 推送到 Gemini API
        if gemini_cookies.get("psid") and gemini_cookies.get("psidts") and config.gemini_api_url:
            logger.info(f"[{profile['name']}] 提取到 Gemini Cookie，推送到 Gemini API...")
            gemini_result = await self._push_to_gemini_api(gemini_cookies, profile.get("name", ""))
        
        # 判断整体结果
        any_success = flow2api_result.get("success") or gemini_result.get("success")
        any_attempted = not flow2api_result.get("skipped") or not gemini_result.get("skipped")
        
        if any_success:
            email = flow2api_result.get("email") or profile.get("email")
            sync_parts = []
            if flow2api_result.get("success"):
                sync_parts.append("flow2api")
                self._flow2api_sync_count += 1
            if gemini_result.get("success"):
                sync_parts.append("gemini")
                self._gemini_sync_count += 1
            await profile_db.update_profile(
                profile_id,
                email=email,
                last_sync_time=datetime.now().isoformat(),
                last_sync_result=f"success: {'+'.join(sync_parts)}",
                sync_count=profile.get("sync_count", 0) + 1
            )
            logger.info(f"[{profile['name']}] 同步成功 ({'+'.join(sync_parts)})")
        elif any_attempted:
            errors = []
            if not flow2api_result.get("skipped") and not flow2api_result.get("success"):
                errors.append(f"flow2api: {flow2api_result.get('error', 'unknown')}")
                self._flow2api_error_count += 1
            if not gemini_result.get("skipped") and not gemini_result.get("success"):
                errors.append(f"gemini: {gemini_result.get('error', 'unknown')}")
                self._gemini_error_count += 1
            error_msg = "; ".join(errors)
            await profile_db.update_profile(
                profile_id,
                last_sync_time=datetime.now().isoformat(),
                last_sync_result=f"failed: {error_msg}",
                error_count=profile.get("error_count", 0) + 1
            )
            logger.error(f"[{profile['name']}] 同步失败: {error_msg}")
        
        return {
            "success": any_success,
            "flow2api": flow2api_result if not flow2api_result.get("skipped") else None,
            "gemini": gemini_result if not gemini_result.get("skipped") else None,
            "email": flow2api_result.get("email") if flow2api_result.get("success") else None,
        }
    
    async def sync_all_profiles(self) -> Dict[str, Any]:
        """同步所有活跃 profile（智能模式：只刷新快过期的）"""
        if not config.connection_token:
            return {"success": False, "error": "未配置 CONNECTION_TOKEN"}
        
        logger.info("=" * 40)
        logger.info("开始智能同步...")
        
        self._last_batch_time = datetime.now()
        profiles = await profile_db.get_active_profiles()
        
        if not profiles:
            logger.info("没有活跃的 Profile")
            return {"success": True, "total": 0, "synced": 0, "skipped": 0}
        
        # 获取所有 profile 的 email
        profile_emails = {p.get("email"): p for p in profiles if p.get("email")}
        
        # 查询 Flow2API 哪些 token 需要刷新
        check_result = await self._check_tokens_status(list(profile_emails.keys()))
        
        if not check_result["success"]:
            logger.warning(f"无法查询 token 状态: {check_result.get('error')}，回退到全量同步")
            # 回退到全量同步
            return await self._sync_all_profiles_force()
        
        needs_refresh_emails = set(check_result.get("needs_refresh_emails", []))
        
        if not needs_refresh_emails:
            logger.info("所有 token 状态良好，无需刷新")
            return {
                "success": True,
                "total": len(profiles),
                "synced": 0,
                "skipped": len(profiles),
                "message": "所有 token 未过期"
            }
        
        logger.info(f"需要刷新的 token: {len(needs_refresh_emails)} 个")
        
        results = []
        success_count = 0
        error_count = 0
        skipped_count = 0
        
        for profile in profiles:
            email = profile.get("email")
            if email and email in needs_refresh_emails:
                result = await self.sync_profile(profile["id"])
                results.append({
                    "profile_id": profile["id"],
                    "profile_name": profile["name"],
                    **result
                })
                if result["success"]:
                    success_count += 1
                else:
                    error_count += 1
            else:
                skipped_count += 1
                logger.info(f"[{profile['name']}] token 未过期，跳过")
        
        logger.info(f"智能同步完成: 成功 {success_count}, 失败 {error_count}, 跳过 {skipped_count}")
        
        return {
            "success": True,
            "total": len(profiles),
            "synced": success_count + error_count,
            "success_count": success_count,
            "error_count": error_count,
            "skipped": skipped_count,
            "results": results
        }
    
    async def _sync_all_profiles_force(self) -> Dict[str, Any]:
        """强制同步所有 profile（不检查过期状态）"""
        profiles = await profile_db.get_active_profiles()
        
        results = []
        success_count = 0
        error_count = 0
        
        for profile in profiles:
            result = await self.sync_profile(profile["id"])
            results.append({
                "profile_id": profile["id"],
                "profile_name": profile["name"],
                **result
            })
            if result["success"]:
                success_count += 1
            else:
                error_count += 1
        
        logger.info(f"强制同步完成: 成功 {success_count}, 失败 {error_count}")
        
        return {
            "success": True,
            "total": len(profiles),
            "success_count": success_count,
            "error_count": error_count,
            "results": results
        }
    
    async def _push_to_flow2api(self, session_token: str) -> Dict[str, Any]:
        """推送到 Flow2API"""
        if not config.connection_token:
            return {"success": False, "error": "未配置 CONNECTION_TOKEN"}
        
        url = f"{config.flow2api_url}/api/plugin/update-token"
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    url,
                    json={"session_token": session_token},
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {config.connection_token}"
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # 从 message 提取 email
                    email = None
                    msg = data.get("message", "")
                    if " for " in msg:
                        email = msg.split(" for ")[-1]
                    
                    return {
                        "success": True,
                        "action": data.get("action"),
                        "message": msg,
                        "email": email
                    }
                else:
                    return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _push_to_gemini_api(self, gemini_cookies: Dict[str, str], profile_name: str = "") -> Dict[str, Any]:
        """推送 Gemini Cookie 到逆向 Gemini API"""
        if not config.gemini_api_url:
            return {"success": False, "error": "未配置 Gemini API 地址"}
        if not config.gemini_connection_token:
            return {"success": False, "error": "未配置 Gemini 连接 Token"}

        psid = gemini_cookies.get("psid", "")
        psidts = gemini_cookies.get("psidts", "")
        if not psid:
            return {"success": False, "error": "缺少 __Secure-1PSID"}

        url = f"{config.gemini_api_url.rstrip('/')}/api/plugin/update-token"

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    url,
                    json={
                        "token": config.gemini_connection_token,
                        "psid": psid,
                        "psidts": psidts,
                        "name": profile_name,
                    },
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        return {
                            "success": True,
                            "action": data.get("message", "synced"),
                            "id": data.get("id"),
                        }
                    else:
                        return {"success": False, "error": data.get("message", "unknown")}
                else:
                    return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "total_sync_count": self._flow2api_sync_count + self._gemini_sync_count,
            "total_error_count": self._flow2api_error_count + self._gemini_error_count,
            "flow2api_sync_count": self._flow2api_sync_count,
            "flow2api_error_count": self._flow2api_error_count,
            "gemini_sync_count": self._gemini_sync_count,
            "gemini_error_count": self._gemini_error_count,
            "last_batch_time": self._last_batch_time.isoformat() if self._last_batch_time else None,
            "flow2api_url": config.flow2api_url,
            "has_connection_token": bool(config.connection_token),
            "gemini_api_url": config.gemini_api_url,
            "has_gemini_connection_token": bool(config.gemini_connection_token),
            "refresh_interval_minutes": config.refresh_interval
        }


token_syncer = TokenSyncer()
