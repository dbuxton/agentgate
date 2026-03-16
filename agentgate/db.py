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

from .models import Profile, User, SessionToken, AuditEvent, Role, Team, TeamMembership

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

                CREATE TABLE IF NOT EXISTS roles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    allowed_tools TEXT NOT NULL DEFAULT '["*"]',
                    denied_tools TEXT NOT NULL DEFAULT '[]',
                    rate_limit_per_hour INTEGER NOT NULL DEFAULT 0,
                    max_tokens_per_day INTEGER NOT NULL DEFAULT 0,
                    level INTEGER NOT NULL DEFAULT 10,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS teams (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    role_id TEXT NOT NULL REFERENCES roles(id),
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS team_members (
                    team_id TEXT NOT NULL REFERENCES teams(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    added_at REAL NOT NULL,
                    PRIMARY KEY (team_id, user_id)
                );

                CREATE TABLE IF NOT EXISTS elevation_requests (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id),
                    token_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    reviewed_at REAL,
                    reviewed_by TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_tokens_user ON session_tokens(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_users_external ON users(external_id);
                CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
                CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
                CREATE INDEX IF NOT EXISTS idx_elevation_status ON elevation_requests(status);
                CREATE INDEX IF NOT EXISTS idx_elevation_user ON elevation_requests(user_id);
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

    # ── Roles ──────────────────────────────────────────────────────────────────

    def create_role(
        self,
        name: str,
        description: str = "",
        allowed_tools: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
        rate_limit_per_hour: int = 0,
        max_tokens_per_day: int = 0,
        level: int = 10,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Role:
        role = Role(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            allowed_tools=allowed_tools or ["*"],
            denied_tools=denied_tools or [],
            rate_limit_per_hour=rate_limit_per_hour,
            max_tokens_per_day=max_tokens_per_day,
            level=level,
            metadata=metadata or {},
            created_at=time.time(),
        )
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO roles
                   (id, name, description, allowed_tools, denied_tools,
                    rate_limit_per_hour, max_tokens_per_day, level, metadata, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    role.id, role.name, role.description,
                    json.dumps(role.allowed_tools), json.dumps(role.denied_tools),
                    role.rate_limit_per_hour, role.max_tokens_per_day,
                    role.level, json.dumps(role.metadata), role.created_at,
                ),
            )
        return role

    def get_role(self, role_id: str) -> Optional[Role]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
            return self._row_to_role(row) if row else None

    def get_role_by_name(self, name: str) -> Optional[Role]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM roles WHERE name=?", (name,)).fetchone()
            return self._row_to_role(row) if row else None

    def list_roles(self) -> List[Role]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM roles ORDER BY level DESC, name").fetchall()
            return [self._row_to_role(r) for r in rows]

    def _row_to_role(self, row) -> Role:
        return Role(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            allowed_tools=json.loads(row["allowed_tools"]),
            denied_tools=json.loads(row["denied_tools"]),
            rate_limit_per_hour=row["rate_limit_per_hour"],
            max_tokens_per_day=row["max_tokens_per_day"],
            level=row["level"],
            metadata=json.loads(row["metadata"]),
            created_at=row["created_at"],
        )

    # ── Teams ──────────────────────────────────────────────────────────────────

    def create_team(
        self,
        name: str,
        role_id: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Team:
        team = Team(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            role_id=role_id,
            metadata=metadata or {},
            created_at=time.time(),
        )
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO teams (id, name, description, role_id, metadata, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (team.id, team.name, team.description, team.role_id,
                 json.dumps(team.metadata), team.created_at),
            )
        return team

    def get_team(self, team_id: str) -> Optional[Team]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM teams WHERE id=?", (team_id,)).fetchone()
            return self._row_to_team(row) if row else None

    def get_team_by_name(self, name: str) -> Optional[Team]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM teams WHERE name=?", (name,)).fetchone()
            return self._row_to_team(row) if row else None

    def list_teams(self) -> List[Team]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM teams ORDER BY name").fetchall()
            return [self._row_to_team(r) for r in rows]

    def _row_to_team(self, row) -> Team:
        return Team(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            role_id=row["role_id"],
            metadata=json.loads(row["metadata"]),
            created_at=row["created_at"],
        )

    # ── Team memberships ───────────────────────────────────────────────────────

    def add_team_member(self, team_id: str, user_id: str) -> TeamMembership:
        membership = TeamMembership(
            team_id=team_id,
            user_id=user_id,
            added_at=time.time(),
        )
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO team_members (team_id, user_id, added_at)
                   VALUES (?,?,?)""",
                (membership.team_id, membership.user_id, membership.added_at),
            )
        return membership

    def remove_team_member(self, team_id: str, user_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM team_members WHERE team_id=? AND user_id=?",
                (team_id, user_id),
            )
            return cur.rowcount > 0

    def get_user_teams(self, user_id: str) -> List[Team]:
        """Return all teams a user belongs to."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT t.* FROM teams t
                   JOIN team_members m ON t.id = m.team_id
                   WHERE m.user_id=?
                   ORDER BY t.name""",
                (user_id,),
            ).fetchall()
            return [self._row_to_team(r) for r in rows]

    def get_team_members(self, team_id: str) -> List[User]:
        """Return all users in a team."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT u.* FROM users u
                   JOIN team_members m ON u.id = m.user_id
                   WHERE m.team_id=? AND u.active=1
                   ORDER BY u.name""",
                (team_id,),
            ).fetchall()
            return [self._row_to_user(r) for r in rows]

    def get_team_member_count(self, team_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT COUNT(*) as cnt FROM team_members m
                   JOIN users u ON u.id = m.user_id
                   WHERE m.team_id=? AND u.active=1""",
                (team_id,),
            ).fetchone()
            return row["cnt"] if row else 0

    def get_user_roles(self, user_id: str) -> List[Role]:
        """Return all roles a user has via team memberships."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT r.* FROM roles r
                   JOIN teams t ON t.role_id = r.id
                   JOIN team_members m ON t.id = m.team_id
                   WHERE m.user_id=?
                   ORDER BY r.level DESC""",
                (user_id,),
            ).fetchall()
            return [self._row_to_role(r) for r in rows]

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

    def get_usage(self, user_id: str, window_key: str) -> int:
        """Get tool_calls counter for a specific window key."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT tool_calls FROM usage_counters WHERE user_id=? AND window_key=?",
                (user_id, window_key),
            ).fetchone()
            return row["tool_calls"] if row else 0

    # ── Elevation Requests ─────────────────────────────────────────────────────

    def create_elevation_request(
        self,
        user_id: str,
        token_id: str,
        tool_name: str,
        reason: str,
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """
        Create a pending elevation request — an agent self-nominates for more access.

        Requests expire after ttl_seconds (default 1 hour) if not reviewed.
        Returns a dict representation of the created request.
        """
        req_id = str(uuid.uuid4())
        now = time.time()
        expires_at = now + ttl_seconds

        with self._conn() as conn:
            conn.execute(
                """INSERT INTO elevation_requests
                   (id, user_id, token_id, tool_name, reason, status, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (req_id, user_id, token_id, tool_name, reason, "pending", now, expires_at),
            )
        return {
            "id": req_id,
            "user_id": user_id,
            "token_id": token_id,
            "tool_name": tool_name,
            "reason": reason,
            "status": "pending",
            "created_at": now,
            "expires_at": expires_at,
            "reviewed_at": None,
            "reviewed_by": None,
        }

    def get_elevation_request(self, req_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM elevation_requests WHERE id=?", (req_id,)
            ).fetchone()
            return self._row_to_elevation(row) if row else None

    def list_elevation_requests(
        self,
        status: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        conditions = []
        params: List[Any] = []
        if status:
            conditions.append("status=?")
            params.append(status)
        if user_id:
            conditions.append("user_id=?")
            params.append(user_id)
        q = "SELECT * FROM elevation_requests"
        if conditions:
            q += " WHERE " + " AND ".join(conditions)
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
            return [self._row_to_elevation(r) for r in rows]

    def update_elevation_status(
        self,
        req_id: str,
        status: str,
        reviewed_by: Optional[str] = None,
    ) -> bool:
        """Set status to 'approved' or 'denied'. Returns True if updated."""
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                """UPDATE elevation_requests
                   SET status=?, reviewed_at=?, reviewed_by=?
                   WHERE id=? AND status='pending'""",
                (status, now, reviewed_by, req_id),
            )
            return cur.rowcount > 0

    def _row_to_elevation(self, row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "token_id": row["token_id"],
            "tool_name": row["tool_name"],
            "reason": row["reason"],
            "status": row["status"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "reviewed_at": row["reviewed_at"],
            "reviewed_by": row["reviewed_by"],
        }
