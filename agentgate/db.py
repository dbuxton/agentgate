"""
SQLite-backed storage for agentgate.

All persistence goes through AgentGateDB — no ORM dependency.
Uses WAL mode for concurrent reads alongside the FastAPI server.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

from .models import Profile, User, SessionToken, AuditEvent

DEFAULT_DB_PATH = os.environ.get("AGENTGATE_DB", "agentgate.db")


class AgentGateDB:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    allowed_tools TEXT NOT NULL DEFAULT '["*"]',
                    denied_tools TEXT NOT NULL DEFAULT '[]',
                    rate_limit_per_hour INTEGER NOT NULL DEFAULT 0,
                    max_tokens_per_day INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    profile_id TEXT NOT NULL REFERENCES profiles(id),
                    external_id TEXT DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    revoked_at REAL
                );

                CREATE TABLE IF NOT EXISTS session_tokens (
                    token_id TEXT PRIMARY KEY,
                    token TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL REFERENCES users(id),
                    profile_id TEXT NOT NULL REFERENCES profiles(id),
                    conversation_id TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_at REAL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    token_id TEXT,
                    tool_name TEXT,
                    granted INTEGER,
                    deny_reason TEXT,
                    conversation_id TEXT,
                    profile_id TEXT,
                    timestamp REAL NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS usage_counters (
                    user_id TEXT NOT NULL,
                    window_key TEXT NOT NULL,  -- "hourly:YYYY-MM-DD-HH" or "daily:YYYY-MM-DD"
                    tool_calls INTEGER NOT NULL DEFAULT 0,
                    token_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, window_key)
                );

                CREATE INDEX IF NOT EXISTS idx_tokens_user ON session_tokens(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_users_external ON users(external_id);
            """)

    # ── Profiles ─────────────────────────────────────────────────────────────

    def create_profile(
        self,
        name: str,
        description: str = "",
        allowed_tools: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
        rate_limit_per_hour: int = 0,
        max_tokens_per_day: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Profile:
        profile = Profile(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            allowed_tools=allowed_tools or ["*"],
            denied_tools=denied_tools or [],
            rate_limit_per_hour=rate_limit_per_hour,
            max_tokens_per_day=max_tokens_per_day,
            metadata=metadata or {},
            created_at=time.time(),
        )
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO profiles
                   (id, name, description, allowed_tools, denied_tools,
                    rate_limit_per_hour, max_tokens_per_day, metadata, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    profile.id, profile.name, profile.description,
                    json.dumps(profile.allowed_tools), json.dumps(profile.denied_tools),
                    profile.rate_limit_per_hour, profile.max_tokens_per_day,
                    json.dumps(profile.metadata), profile.created_at,
                ),
            )
        return profile

    def get_profile(self, profile_id: str) -> Optional[Profile]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            return self._row_to_profile(row) if row else None

    def get_profile_by_name(self, name: str) -> Optional[Profile]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE name=?", (name,)).fetchone()
            return self._row_to_profile(row) if row else None

    def list_profiles(self) -> List[Profile]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM profiles ORDER BY name").fetchall()
            return [self._row_to_profile(r) for r in rows]

    def _row_to_profile(self, row) -> Profile:
        return Profile(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            allowed_tools=json.loads(row["allowed_tools"]),
            denied_tools=json.loads(row["denied_tools"]),
            rate_limit_per_hour=row["rate_limit_per_hour"],
            max_tokens_per_day=row["max_tokens_per_day"],
            metadata=json.loads(row["metadata"]),
            created_at=row["created_at"],
        )

    # ── Users ─────────────────────────────────────────────────────────────────

    def create_user(
        self,
        name: str,
        email: str,
        profile_id: str,
        external_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        user = User(
            id=str(uuid.uuid4()),
            name=name,
            email=email,
            profile_id=profile_id,
            external_id=external_id,
            active=True,
            metadata=metadata or {},
            created_at=time.time(),
        )
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO users
                   (id, name, email, profile_id, external_id, active, metadata, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    user.id, user.name, user.email, user.profile_id,
                    user.external_id, 1, json.dumps(user.metadata), user.created_at,
                ),
            )
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            return self._row_to_user(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            return self._row_to_user(row) if row else None

    def get_user_by_external_id(self, external_id: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE external_id=? AND active=1", (external_id,)
            ).fetchone()
            return self._row_to_user(row) if row else None

    def list_users(self, active_only: bool = True) -> List[User]:
        with self._conn() as conn:
            q = "SELECT * FROM users"
            if active_only:
                q += " WHERE active=1"
            q += " ORDER BY name"
            rows = conn.execute(q).fetchall()
            return [self._row_to_user(r) for r in rows]

    def revoke_user(self, user_id: str) -> bool:
        """Deactivate a user — all future token checks will fail."""
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE users SET active=0, revoked_at=? WHERE id=? AND active=1",
                (now, user_id),
            )
            return cur.rowcount > 0

    def update_user_profile(self, user_id: str, profile_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE users SET profile_id=? WHERE id=?", (profile_id, user_id)
            )
            return cur.rowcount > 0

    def _row_to_user(self, row) -> User:
        return User(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            profile_id=row["profile_id"],
            external_id=row["external_id"] or "",
            active=bool(row["active"]),
            metadata=json.loads(row["metadata"]),
            created_at=row["created_at"],
            revoked_at=row["revoked_at"],
        )

    # ── Session Tokens ────────────────────────────────────────────────────────

    def store_token(self, token: SessionToken) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO session_tokens
                   (token_id, token, user_id, profile_id, conversation_id,
                    issued_at, expires_at, revoked, metadata)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    token.token_id, token.token, token.user_id, token.profile_id,
                    token.conversation_id, token.issued_at, token.expires_at,
                    0, json.dumps(token.metadata),
                ),
            )

    def get_token(self, token_str: str) -> Optional[SessionToken]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM session_tokens WHERE token=?", (token_str,)
            ).fetchone()
            return self._row_to_token(row) if row else None

    def revoke_token(self, token_id: str) -> bool:
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE session_tokens SET revoked=1, revoked_at=? WHERE token_id=? AND revoked=0",
                (now, token_id),
            )
            return cur.rowcount > 0

    def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke every active token for a user (called on user revocation)."""
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE session_tokens SET revoked=1, revoked_at=? WHERE user_id=? AND revoked=0",
                (now, user_id),
            )
            return cur.rowcount

    def list_user_tokens(self, user_id: str, active_only: bool = False) -> List[SessionToken]:
        with self._conn() as conn:
            q = "SELECT * FROM session_tokens WHERE user_id=?"
            params = [user_id]
            if active_only:
                q += " AND revoked=0 AND expires_at>?"
                params.append(time.time())
            q += " ORDER BY issued_at DESC"
            rows = conn.execute(q, params).fetchall()
            return [self._row_to_token(r) for r in rows]

    def _row_to_token(self, row) -> SessionToken:
        return SessionToken(
            token_id=row["token_id"],
            token=row["token"],
            user_id=row["user_id"],
            profile_id=row["profile_id"],
            conversation_id=row["conversation_id"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
            revoked=bool(row["revoked"]),
            revoked_at=row["revoked_at"],
            metadata=json.loads(row["metadata"]),
        )

    # ── Audit Log ─────────────────────────────────────────────────────────────

    def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        token_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        granted: Optional[bool] = None,
        deny_reason: Optional[str] = None,
        conversation_id: Optional[str] = None,
        profile_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            user_id=user_id,
            token_id=token_id,
            tool_name=tool_name,
            granted=granted,
            deny_reason=deny_reason,
            conversation_id=conversation_id,
            profile_id=profile_id,
            timestamp=time.time(),
            metadata=metadata or {},
        )
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO audit_log
                   (id, event_type, user_id, token_id, tool_name, granted,
                    deny_reason, conversation_id, profile_id, timestamp, metadata)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.id, event.event_type, event.user_id, event.token_id,
                    event.tool_name,
                    int(event.granted) if event.granted is not None else None,
                    event.deny_reason, event.conversation_id, event.profile_id,
                    event.timestamp, json.dumps(event.metadata),
                ),
            )
        return event

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEvent]:
        conditions = []
        params: List[Any] = []
        if user_id:
            conditions.append("user_id=?")
            params.append(user_id)
        if conversation_id:
            conditions.append("conversation_id=?")
            params.append(conversation_id)
        if event_type:
            conditions.append("event_type=?")
            params.append(event_type)
        q = "SELECT * FROM audit_log"
        if conditions:
            q += " WHERE " + " AND ".join(conditions)
        q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
            return [self._row_to_event(r) for r in rows]

    def _row_to_event(self, row) -> AuditEvent:
        granted = row["granted"]
        return AuditEvent(
            id=row["id"],
            event_type=row["event_type"],
            user_id=row["user_id"],
            token_id=row["token_id"],
            tool_name=row["tool_name"],
            granted=bool(granted) if granted is not None else None,
            deny_reason=row["deny_reason"],
            conversation_id=row["conversation_id"],
            profile_id=row["profile_id"],
            timestamp=row["timestamp"],
            metadata=json.loads(row["metadata"]),
        )

    # ── Usage Counters ────────────────────────────────────────────────────────

    def _hourly_key(self) -> str:
        import datetime
        now = datetime.datetime.utcnow()
        return f"hourly:{now.strftime('%Y-%m-%d-%H')}"

    def _daily_key(self) -> str:
        import datetime
        now = datetime.datetime.utcnow()
        return f"daily:{now.strftime('%Y-%m-%d')}"

    def increment_usage(self, user_id: str, token_count: int = 0) -> None:
        hourly = self._hourly_key()
        daily = self._daily_key()
        with self._conn() as conn:
            for window in [hourly, daily]:
                conn.execute(
                    """INSERT INTO usage_counters (user_id, window_key, tool_calls, token_count)
                       VALUES (?,?,1,?)
                       ON CONFLICT(user_id, window_key)
                       DO UPDATE SET tool_calls=tool_calls+1, token_count=token_count+?""",
                    (user_id, window, token_count, token_count),
                )

    def get_hourly_tool_calls(self, user_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT tool_calls FROM usage_counters WHERE user_id=? AND window_key=?",
                (user_id, self._hourly_key()),
            ).fetchone()
            return row["tool_calls"] if row else 0

    def get_daily_tokens(self, user_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT token_count FROM usage_counters WHERE user_id=? AND window_key=?",
                (user_id, self._daily_key()),
            ).fetchone()
            return row["token_count"] if row else 0

    def get_usage_stats(self, user_id: str) -> Dict[str, Any]:
        """Usage summary for a user across available windows."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT window_key, tool_calls, token_count
                   FROM usage_counters WHERE user_id=?
                   ORDER BY window_key DESC LIMIT 48""",
                (user_id,),
            ).fetchall()
            return {
                row["window_key"]: {
                    "tool_calls": row["tool_calls"],
                    "token_count": row["token_count"],
                }
                for row in rows
            }
