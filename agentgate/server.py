"""
agentgate FastAPI server.

Exposes:
  POST /profiles             — create profile
  GET  /profiles             — list profiles
  GET  /profiles/{id}        — get profile

  POST /roles                — create role
  GET  /roles                — list roles
  GET  /roles/{id}           — get role

  POST /teams                — create team
  GET  /teams                — list teams
  GET  /teams/{id}           — get team
  GET  /teams/{id}/members   — list team members
  POST /teams/{id}/members   — add member to team
  DELETE /teams/{id}/members/{user_id} — remove member

  POST /users                — create user
  GET  /users                — list users
  GET  /users/{id}           — get user
  GET  /users/{id}/teams     — get user's teams
  GET  /users/{id}/permissions — resolved effective permissions
  POST /users/{id}/revoke    — offboard user (revokes all tokens)
  PUT  /users/{id}/profile   — update user's profile

  POST /tokens/issue         — issue session token
  POST /tokens/revoke        — revoke a token
  GET  /tokens/{token_id}    — inspect a token

  POST /enforce              — check tool call (hot path)

  GET  /audit                — audit log (filterable)
  GET  /usage/{user_id}      — usage stats for a user

  GET  /                     — dark-mode dashboard
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .db import AgentGateDB
from .gate import AgentGate
from .models import EnforceRequest
from .tokens import TokenManager

# ── Setup ─────────────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("AGENTGATE_DB", "agentgate.db")
SECRET = os.environ.get("AGENTGATE_SECRET", "change-me-in-production")
TOKEN_TTL = int(os.environ.get("AGENTGATE_TOKEN_TTL", str(8 * 3600)))

db = AgentGateDB(DB_PATH)
tm = TokenManager(secret=SECRET, ttl_seconds=TOKEN_TTL)
gate = AgentGate(db=db, token_manager=tm)

app = FastAPI(title="agentgate", version="0.1.0", docs_url="/docs")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CreateProfileRequest(BaseModel):
    name: str
    description: str = ""
    allowed_tools: List[str] = ["*"]
    denied_tools: List[str] = []
    rate_limit_per_hour: int = 0
    max_tokens_per_day: int = 0
    metadata: dict = {}


class CreateRoleRequest(BaseModel):
    name: str
    description: str = ""
    allowed_tools: List[str] = ["*"]
    denied_tools: List[str] = []
    rate_limit_per_hour: int = 0
    max_tokens_per_day: int = 0
    level: int = 10
    metadata: dict = {}


class CreateTeamRequest(BaseModel):
    name: str
    role_id: str
    description: str = ""
    metadata: dict = {}


class AddTeamMemberRequest(BaseModel):
    user_id: str


class CreateUserRequest(BaseModel):
    name: str
    email: str
    profile_id: str
    external_id: str = ""
    metadata: dict = {}


class UpdateProfileRequest(BaseModel):
    profile_id: str


class IssueTokenRequest(BaseModel):
    user_id: str
    conversation_id: Optional[str] = None
    ttl_seconds: Optional[int] = None
    metadata: dict = {}


class RevokeTokenRequest(BaseModel):
    token_id: str


class EnforceHTTPRequest(BaseModel):
    token: str
    tool_name: str
    token_count: int = 0
    metadata: dict = {}


# ── Profiles ──────────────────────────────────────────────────────────────────

@app.post("/profiles", status_code=201)
def create_profile(req: CreateProfileRequest):
    profile = db.create_profile(
        name=req.name,
        description=req.description,
        allowed_tools=req.allowed_tools,
        denied_tools=req.denied_tools,
        rate_limit_per_hour=req.rate_limit_per_hour,
        max_tokens_per_day=req.max_tokens_per_day,
        metadata=req.metadata,
    )
    return _profile_dict(profile)


@app.get("/profiles")
def list_profiles():
    return [_profile_dict(p) for p in db.list_profiles()]


@app.get("/profiles/{profile_id}")
def get_profile(profile_id: str):
    p = db.get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    return _profile_dict(p)


# ── Roles ─────────────────────────────────────────────────────────────────────

@app.post("/roles", status_code=201)
def create_role(req: CreateRoleRequest):
    role = db.create_role(
        name=req.name,
        description=req.description,
        allowed_tools=req.allowed_tools,
        denied_tools=req.denied_tools,
        rate_limit_per_hour=req.rate_limit_per_hour,
        max_tokens_per_day=req.max_tokens_per_day,
        level=req.level,
        metadata=req.metadata,
    )
    return _role_dict(role)


@app.get("/roles")
def list_roles():
    return [_role_dict(r) for r in db.list_roles()]


@app.get("/roles/{role_id}")
def get_role(role_id: str):
    r = db.get_role(role_id)
    if not r:
        raise HTTPException(404, "Role not found")
    return _role_dict(r)


# ── Teams ─────────────────────────────────────────────────────────────────────

@app.post("/teams", status_code=201)
def create_team(req: CreateTeamRequest):
    if not db.get_role(req.role_id):
        raise HTTPException(400, f"Role {req.role_id!r} not found")
    team = db.create_team(
        name=req.name,
        role_id=req.role_id,
        description=req.description,
        metadata=req.metadata,
    )
    return _team_dict(team)


@app.get("/teams")
def list_teams():
    teams = db.list_teams()
    result = []
    for t in teams:
        role = db.get_role(t.role_id)
        d = _team_dict(t)
        d["role_name"] = role.name if role else None
        d["member_count"] = db.get_team_member_count(t.id)
        result.append(d)
    return result


@app.get("/teams/{team_id}")
def get_team(team_id: str):
    t = db.get_team(team_id)
    if not t:
        raise HTTPException(404, "Team not found")
    role = db.get_role(t.role_id)
    d = _team_dict(t)
    d["role_name"] = role.name if role else None
    d["member_count"] = db.get_team_member_count(t.id)
    return d


@app.get("/teams/{team_id}/members")
def get_team_members(team_id: str):
    if not db.get_team(team_id):
        raise HTTPException(404, "Team not found")
    return [_user_dict(u) for u in db.get_team_members(team_id)]


@app.post("/teams/{team_id}/members", status_code=201)
def add_team_member(team_id: str, req: AddTeamMemberRequest):
    if not db.get_team(team_id):
        raise HTTPException(404, "Team not found")
    if not db.get_user(req.user_id):
        raise HTTPException(400, "User not found")
    db.add_team_member(team_id=team_id, user_id=req.user_id)
    return {"status": "added", "team_id": team_id, "user_id": req.user_id}


@app.delete("/teams/{team_id}/members/{user_id}")
def remove_team_member(team_id: str, user_id: str):
    if not db.get_team(team_id):
        raise HTTPException(404, "Team not found")
    ok = db.remove_team_member(team_id=team_id, user_id=user_id)
    if not ok:
        raise HTTPException(404, "Membership not found")
    return {"status": "removed", "team_id": team_id, "user_id": user_id}


# ── Users ─────────────────────────────────────────────────────────────────────

@app.post("/users", status_code=201)
def create_user(req: CreateUserRequest):
    if not db.get_profile(req.profile_id):
        raise HTTPException(400, f"Profile {req.profile_id!r} not found")
    user = db.create_user(
        name=req.name,
        email=req.email,
        profile_id=req.profile_id,
        external_id=req.external_id,
        metadata=req.metadata,
    )
    return _user_dict(user)


@app.get("/users")
def list_users(active_only: bool = Query(True)):
    return [_user_dict(u) for u in db.list_users(active_only=active_only)]


@app.get("/users/{user_id}")
def get_user(user_id: str):
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return _user_dict(user)


@app.get("/users/{user_id}/teams")
def get_user_teams(user_id: str):
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    teams = db.get_user_teams(user_id)
    result = []
    for t in teams:
        role = db.get_role(t.role_id)
        d = _team_dict(t)
        d["role_name"] = role.name if role else None
        result.append(d)
    return result


@app.get("/users/{user_id}/permissions")
def get_user_permissions(user_id: str):
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    perms = gate.resolve_effective_permissions(user)
    teams = db.get_user_teams(user_id)
    return {
        "user_id": user_id,
        "user_name": user.name,
        "source_profile_id": perms.source_profile_id,
        "source_team_ids": perms.source_team_ids,
        "source_teams": [t.name for t in teams],
        "effective_allowed_tools": perms.allowed_tools,
        "effective_denied_tools": perms.denied_tools,
        "effective_rate_limit_per_hour": perms.rate_limit_per_hour,
        "effective_max_tokens_per_day": perms.max_tokens_per_day,
    }


@app.post("/users/{user_id}/revoke")
def revoke_user(user_id: str):
    if not db.get_user(user_id):
        raise HTTPException(404, "User not found")
    result = gate.revoke_user(user_id)
    return {"status": "revoked", **result}


@app.put("/users/{user_id}/profile")
def update_user_profile(user_id: str, req: UpdateProfileRequest):
    if not db.get_user(user_id):
        raise HTTPException(404, "User not found")
    if not db.get_profile(req.profile_id):
        raise HTTPException(400, "Profile not found")
    ok = db.update_user_profile(user_id, req.profile_id)
    return {"updated": ok}


# ── Tokens ────────────────────────────────────────────────────────────────────

@app.post("/tokens/issue", status_code=201)
def issue_token(req: IssueTokenRequest):
    try:
        token = gate.issue_token(
            user_id=req.user_id,
            conversation_id=req.conversation_id,
            ttl_seconds=req.ttl_seconds,
            metadata=req.metadata,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _token_dict(token)


@app.post("/tokens/revoke")
def revoke_token(req: RevokeTokenRequest):
    ok = gate.revoke_token(req.token_id)
    if not ok:
        raise HTTPException(404, "Token not found or already revoked")
    return {"status": "revoked", "token_id": req.token_id}


@app.get("/tokens/{token_id}")
def get_token(token_id: str):
    with db._conn() as conn:
        row = conn.execute(
            "SELECT * FROM session_tokens WHERE token_id=?", (token_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Token not found")
    return _token_dict(db._row_to_token(row))


# ── Enforce (hot path) ────────────────────────────────────────────────────────

@app.post("/enforce")
def enforce(req: EnforceHTTPRequest):
    result = gate.enforce(
        EnforceRequest(
            token=req.token,
            tool_name=req.tool_name,
            token_count=req.token_count,
            metadata=req.metadata,
        )
    )
    return {
        "granted": result.granted,
        "deny_reason": result.deny_reason,
        "user_id": result.user_id,
        "profile_id": result.profile_id,
        "conversation_id": result.conversation_id,
        "rate_limit_remaining": result.rate_limit_remaining,
        "daily_tokens_remaining": result.daily_tokens_remaining,
    }


# ── Audit ─────────────────────────────────────────────────────────────────────

@app.get("/audit")
def get_audit(
    user_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    events = db.get_audit_log(
        user_id=user_id,
        conversation_id=conversation_id,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )
    return [_event_dict(e) for e in events]


@app.get("/usage/{user_id}")
def get_usage(user_id: str):
    if not db.get_user(user_id):
        raise HTTPException(404, "User not found")
    return db.get_usage_stats(user_id)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard():
    users = db.list_users(active_only=False)
    profiles = db.list_profiles()
    roles = db.list_roles()
    teams = db.list_teams()
    audit = db.get_audit_log(limit=20)

    profile_map = {p.id: p.name for p in profiles}
    role_map = {r.id: r for r in roles}

    def fmt_time(ts):
        if ts is None:
            return "—"
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows_users = ""
    for u in users:
        status = "✅ Active" if u.active else "🚫 Revoked"
        hourly = db.get_hourly_tool_calls(u.id)
        daily_tok = db.get_daily_tokens(u.id)
        p_name = profile_map.get(u.profile_id, u.profile_id[:8])
        user_teams = db.get_user_teams(u.id)
        team_badges = "".join(f'<span class="tag team-tag">{t.name}</span> ' for t in user_teams)
        rows_users += f"""
        <tr>
          <td><code>{u.id[:8]}</code></td>
          <td>{u.name}</td>
          <td>{u.email}</td>
          <td><span class="tag">{p_name}</span></td>
          <td>{team_badges or '<span class="muted">—</span>'}</td>
          <td class="{'active' if u.active else 'revoked'}">{status}</td>
          <td>{hourly}</td>
          <td>{daily_tok:,}</td>
          <td class="ts">{fmt_time(u.created_at)}</td>
        </tr>"""

    rows_profiles = ""
    for p in profiles:
        rows_profiles += f"""
        <tr>
          <td><code>{p.id[:8]}</code></td>
          <td>{p.name}</td>
          <td>{', '.join(p.allowed_tools) or '—'}</td>
          <td class="deny">{', '.join(p.denied_tools) or '—'}</td>
          <td>{'∞' if not p.rate_limit_per_hour else str(p.rate_limit_per_hour) + '/hr'}</td>
          <td>{'∞' if not p.max_tokens_per_day else f'{p.max_tokens_per_day:,}/day'}</td>
        </tr>"""

    rows_roles = ""
    for r in roles:
        rows_roles += f"""
        <tr>
          <td><code>{r.id[:8]}</code></td>
          <td>{r.name}</td>
          <td><span class="tag">{r.level}</span></td>
          <td>{', '.join(r.allowed_tools) or '—'}</td>
          <td class="deny">{', '.join(r.denied_tools) or '—'}</td>
          <td>{'∞' if not r.rate_limit_per_hour else str(r.rate_limit_per_hour) + '/hr'}</td>
          <td>{'∞' if not r.max_tokens_per_day else f'{r.max_tokens_per_day:,}/day'}</td>
        </tr>"""

    rows_teams = ""
    for t in teams:
        role = role_map.get(t.role_id)
        member_count = db.get_team_member_count(t.id)
        rows_teams += f"""
        <tr>
          <td><code>{t.id[:8]}</code></td>
          <td>{t.name}</td>
          <td>{t.description or '—'}</td>
          <td><span class="tag">{role.name if role else t.role_id[:8]}</span></td>
          <td>{member_count}</td>
          <td class="ts">{fmt_time(t.created_at)}</td>
        </tr>"""

    rows_audit = ""
    for e in audit:
        icon = {"tool_call": "🔧", "token_issued": "🔑", "token_revoked": "🗑️", "user_revoked": "🚫"}.get(e.event_type, "📋")
        verdict = ""
        if e.granted is True:
            verdict = '<span class="active">✅</span>'
        elif e.granted is False:
            verdict = f'<span class="revoked">✗ {e.deny_reason}</span>'
        rows_audit += f"""
        <tr>
          <td class="ts">{fmt_time(e.timestamp)}</td>
          <td>{icon} {e.event_type}</td>
          <td><code>{(e.user_id or '')[:8] or '—'}</code></td>
          <td>{e.tool_name or '—'}</td>
          <td>{verdict}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>agentgate</title>
<style>
  :root {{
    --bg: #0d0d0d; --surface: #161616; --border: #2a2a2a;
    --text: #e8e8e8; --muted: #888; --accent: #6c8eff;
    --green: #4ade80; --red: #f87171; --yellow: #fbbf24;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; font-size: 14px; }}
  header {{ display: flex; align-items: center; gap: 12px; padding: 20px 28px; border-bottom: 1px solid var(--border); }}
  header h1 {{ font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }}
  header h1 span {{ color: var(--accent); }}
  header .sub {{ color: var(--muted); font-size: 13px; }}
  .container {{ padding: 28px; max-width: 1400px; margin: 0 auto; }}
  h2 {{ font-size: 15px; font-weight: 600; margin-bottom: 14px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  section {{ margin-bottom: 40px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }}
  th {{ padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.03); }}
  code {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; color: var(--accent); background: rgba(108,142,255,0.1); padding: 2px 6px; border-radius: 4px; }}
  .tag {{ background: rgba(108,142,255,0.15); color: var(--accent); padding: 2px 8px; border-radius: 12px; font-size: 12px; }}
  .active {{ color: var(--green); }}
  .revoked {{ color: var(--red); }}
  .deny {{ color: var(--red); font-size: 12px; }}
  .ts {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 16px; margin-bottom: 36px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; }}
  .stat .label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
  .stat .value {{ font-size: 28px; font-weight: 700; }}
  .stat .value.accent {{ color: var(--accent); }}
  .stat .value.green {{ color: var(--green); }}
  .stat .value.red {{ color: var(--red); }}
  .refresh {{ font-size: 12px; color: var(--muted); margin-left: auto; }}
  .team-tag {{ background: rgba(251,191,36,0.15); color: var(--yellow); }}
  .muted {{ color: var(--muted); }}
  .level {{ color: var(--yellow); }}
</style>
<script>setTimeout(()=>location.reload(), 60000)</script>
</head>
<body>
<header>
  <div>
    <h1>agent<span>gate</span> <span style="font-size:13px;color:var(--muted);font-weight:400">— identity-aware access control for AI agents</span></h1>
  </div>
  <span class="refresh">auto-refresh 60s</span>
</header>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="label">Total Users</div><div class="value accent">{len(users)}</div></div>
    <div class="stat"><div class="label">Active Users</div><div class="value green">{sum(1 for u in users if u.active)}</div></div>
    <div class="stat"><div class="label">Revoked Users</div><div class="value red">{sum(1 for u in users if not u.active)}</div></div>
    <div class="stat"><div class="label">Teams</div><div class="value accent">{len(teams)}</div></div>
    <div class="stat"><div class="label">Roles</div><div class="value accent">{len(roles)}</div></div>
    <div class="stat"><div class="label">Profiles</div><div class="value accent">{len(profiles)}</div></div>
  </div>

  <section>
    <h2>Users</h2>
    <table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Email</th><th>Profile</th><th>Teams</th><th>Status</th>
        <th>Calls/hr</th><th>Tokens today</th><th>Created</th>
      </tr></thead>
      <tbody>{rows_users}</tbody>
    </table>
  </section>

  <section>
    <h2>Teams</h2>
    <table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Description</th><th>Role</th><th>Members</th><th>Created</th>
      </tr></thead>
      <tbody>{rows_teams if rows_teams else '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No teams yet — create one with <code>agentgate team create</code></td></tr>'}</tbody>
    </table>
  </section>

  <section>
    <h2>Roles</h2>
    <table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Level</th><th>Allowed Tools</th><th>Denied Tools</th>
        <th>Rate Limit</th><th>Token Quota</th>
      </tr></thead>
      <tbody>{rows_roles if rows_roles else '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">No roles yet — create one with <code>agentgate role create</code></td></tr>'}</tbody>
    </table>
  </section>

  <section>
    <h2>Profiles</h2>
    <table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Allowed Tools</th><th>Denied Tools</th>
        <th>Rate Limit</th><th>Token Quota</th>
      </tr></thead>
      <tbody>{rows_profiles}</tbody>
    </table>
  </section>

  <section>
    <h2>Recent Audit Events</h2>
    <table>
      <thead><tr>
        <th>Time</th><th>Event</th><th>User</th><th>Tool</th><th>Result</th>
      </tr></thead>
      <tbody>{rows_audit}</tbody>
    </table>
  </section>
</div>
</body></html>"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _profile_dict(p):
    return {
        "id": p.id, "name": p.name, "description": p.description,
        "allowed_tools": p.allowed_tools, "denied_tools": p.denied_tools,
        "rate_limit_per_hour": p.rate_limit_per_hour,
        "max_tokens_per_day": p.max_tokens_per_day,
        "metadata": p.metadata,
        "created_at": p.created_at,
    }


def _role_dict(r):
    return {
        "id": r.id, "name": r.name, "description": r.description,
        "allowed_tools": r.allowed_tools, "denied_tools": r.denied_tools,
        "rate_limit_per_hour": r.rate_limit_per_hour,
        "max_tokens_per_day": r.max_tokens_per_day,
        "level": r.level,
        "metadata": r.metadata,
        "created_at": r.created_at,
    }


def _team_dict(t):
    return {
        "id": t.id, "name": t.name, "description": t.description,
        "role_id": t.role_id,
        "metadata": t.metadata,
        "created_at": t.created_at,
    }


def _user_dict(u):
    return {
        "id": u.id, "name": u.name, "email": u.email,
        "profile_id": u.profile_id, "external_id": u.external_id,
        "active": u.active, "metadata": u.metadata,
        "created_at": u.created_at, "revoked_at": u.revoked_at,
    }


def _token_dict(t):
    return {
        "token_id": t.token_id, "token": t.token,
        "user_id": t.user_id, "profile_id": t.profile_id,
        "conversation_id": t.conversation_id,
        "issued_at": t.issued_at, "expires_at": t.expires_at,
        "revoked": t.revoked, "revoked_at": t.revoked_at,
        "metadata": t.metadata,
    }


def _event_dict(e):
    return {
        "id": e.id, "event_type": e.event_type,
        "user_id": e.user_id, "token_id": e.token_id,
        "tool_name": e.tool_name, "granted": e.granted,
        "deny_reason": e.deny_reason, "conversation_id": e.conversation_id,
        "profile_id": e.profile_id, "timestamp": e.timestamp,
        "metadata": e.metadata,
    }
