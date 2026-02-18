"""Profile 数据库管理"""
import aiosqlite
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from .config import config


class ProfileDB:
    """Profile 数据库"""
    
    def __init__(self):
        self.db_path = config.db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    async def init(self):
        """初始化数据库"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    email TEXT,
                    is_logged_in INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    last_token TEXT,
                    last_token_time TEXT,
                    last_sync_time TEXT,
                    last_sync_result TEXT,
                    sync_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    remark TEXT,
                    proxy_url TEXT,
                    proxy_enabled INTEGER DEFAULT 0
                )
            """)
            
            # 检查并添加新列
            cursor = await db.execute("PRAGMA table_info(profiles)")
            columns = [row[1] for row in await cursor.fetchall()]
            
            if 'proxy_url' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN proxy_url TEXT")
            if 'proxy_enabled' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN proxy_enabled INTEGER DEFAULT 0")
            if 'google_email' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN google_email TEXT")
            if 'google_password' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN google_password TEXT")
            if 'totp_secret' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN totp_secret TEXT")
            
            await db.commit()
    
    async def add_profile(self, name: str, remark: str = "", proxy_url: str = "",
                         google_email: str = "", google_password: str = "", totp_secret: str = "") -> int:
        """添加 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "INSERT INTO profiles (name, remark, proxy_url, proxy_enabled, google_email, google_password, totp_secret, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (name, remark, proxy_url, 1 if proxy_url else 0, google_email or None, google_password or None, totp_secret or None, datetime.now().isoformat())
            )
            await db.commit()
            return cursor.lastrowid
    
    async def get_all_profiles(self) -> List[Dict[str, Any]]:
        """获取所有 profiles"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM profiles ORDER BY id")
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_profile(self, profile_id: int) -> Optional[Dict[str, Any]]:
        """获取单个 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_profile_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """通过名称获取 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM profiles WHERE name = ?", (name,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def update_profile(self, profile_id: int, **kwargs):
        """更新 profile"""
        if not kwargs:
            return
        
        fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [profile_id]
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(f"UPDATE profiles SET {fields} WHERE id = ?", values)
            await db.commit()
    
    async def delete_profile(self, profile_id: int):
        """删除 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
            await db.commit()
    
    async def get_active_profiles(self) -> List[Dict[str, Any]]:
        """获取所有启用的 profiles"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM profiles WHERE is_active = 1 ORDER BY id"
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_logged_in_profiles(self) -> List[Dict[str, Any]]:
        """获取所有已登录的 profiles"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM profiles WHERE is_logged_in = 1 AND is_active = 1 ORDER BY id"
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


# 全局实例
profile_db = ProfileDB()
