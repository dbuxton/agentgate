#!/usr/bin/env python3
"""
agentgate CLI

Usage:
  agentgate profile create --name "employee" --allowed "crm_*,email_*" --rate 100
  agentgate profile list
  agentgate profile get <name_or_id>

  agentgate user create --name "Alice" --email alice@acme.com --profile "employee"
  agentgate user list
  agentgate user get <id_or_email>
  agentgate user revoke <id_or_email>     # offboard — kills all sessions instantly
  agentgate user profile <id> --set <profile_name>

  agentgate token issue --user <id_or_email> [--conversation <id>] [--ttl 3600]
  agentgate token revoke <token_id>
  agentgate token inspect <token_string>

  agentgate enforce --token <tok> --tool <name>

  agentgate audit [--user <id>] [--conversation <id>] [--limit 50]
  agentgate usage <user_id_or_email>

  agentgate serve [--host 0.0.0.0] [--port 8765]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .db import AgentGateDB
from .gate import AgentGate
from .models import EnforceRequest
from .tokens import TokenManager

DB_PATH = os.environ.get("AGENTGATE_DB", "agentgate.db")
SECRET = os.environ.get("AGENTGATE_SECRET", "change-me-in-production")

def get_db():
    return AgentGateDB(DB_PATH)

def get_gate(db):
    return AgentGate(db=db, token_manager=TokenManager(secret=SECRET))

def fmt_ts(ts):
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def resolve_user(db, ref):
    """Find user by id or email."""
    user = db.get_user(ref)
    if not user:
        user = db.get_user_by_email(ref)
    if not user:
        print(f"✗ User not found: {ref!r}", file=sys.stderr)
        sys.exit(1)
    return user

def resolve_profile(db, ref):
    """Find profile by id or name."""
    p = db.get_profile(ref)
    if not p:
        p = db.get_profile_by_name(ref)
    if not p:
        print(f"✗ Profile not found: {ref!r}", file=sys.stderr)
        sys.exit(1)
    return p


# ── profile ───────────────────────────────────────────────────────────────────

def cmd_profile_create(args):
    db = get_db()
    allowed = [t.strip() for t in (args.allowed or "*").split(",") if t.strip()]
    denied = [t.strip() for t in (args.denied or "").split(",") if t.strip()]
    p = db.create_profile(
        name=args.name,
        description=args.description or "",
        allowed_tools=allowed,
        denied_tools=denied,
        rate_limit_per_hour=args.rate or 0,
        max_tokens_per_day=args.tokens or 0,
    )
    print(f"✅ Profile created")
    print(f"   id:            {p.id}")
    print(f"   name:          {p.name}")
    print(f"   allowed_tools: {', '.join(p.allowed_tools)}")
    print(f"   denied_tools:  {', '.join(p.denied_tools) or '—'}")
    print(f"   rate_limit:    {'∞' if not p.rate_limit_per_hour else str(p.rate_limit_per_hour) + '/hr'}")
    print(f"   token_quota:   {'∞' if not p.max_tokens_per_day else str(p.max_tokens_per_day) + '/day'}")


def cmd_profile_list(args):
    db = get_db()
    profiles = db.list_profiles()
    if not profiles:
        print("No profiles.")
        return
    print(f"{'NAME':<20} {'ALLOWED':<25} {'DENIED':<20} {'RATE':<10} {'QUOTA':<12} {'ID'}")
    print("-" * 100)
    for p in profiles:
        rate = "∞" if not p.rate_limit_per_hour else f"{p.rate_limit_per_hour}/hr"
        quota = "∞" if not p.max_tokens_per_day else f"{p.max_tokens_per_day}/day"
        allowed = ', '.join(p.allowed_tools)[:23]
        denied = ', '.join(p.denied_tools)[:18] or "—"
        print(f"{p.name:<20} {allowed:<25} {denied:<20} {rate:<10} {quota:<12} {p.id[:8]}")


def cmd_profile_get(args):
    db = get_db()
    p = resolve_profile(db, args.ref)
    print(json.dumps({
        "id": p.id, "name": p.name, "description": p.description,
        "allowed_tools": p.allowed_tools, "denied_tools": p.denied_tools,
        "rate_limit_per_hour": p.rate_limit_per_hour, "max_tokens_per_day": p.max_tokens_per_day,
        "created_at": fmt_ts(p.created_at),
    }, indent=2))


# ── user ──────────────────────────────────────────────────────────────────────

def cmd_user_create(args):
    db = get_db()
    profile = resolve_profile(db, args.profile)
    user = db.create_user(
        name=args.name,
        email=args.email,
        profile_id=profile.id,
        external_id=args.external_id or "",
    )
    print(f"✅ User created")
    print(f"   id:         {user.id}")
    print(f"   name:       {user.name}")
    print(f"   email:      {user.email}")
    print(f"   profile:    {profile.name} ({profile.id[:8]})")
    print(f"   created_at: {fmt_ts(user.created_at)}")


def cmd_user_list(args):
    db = get_db()
    users = db.list_users(active_only=not args.all)
    if not users:
        print("No users.")
        return
    print(f"{'NAME':<25} {'EMAIL':<30} {'PROFILE':<20} {'STATUS':<10} {'ID'}")
    print("-" * 110)
    for u in users:
        status = "active" if u.active else "REVOKED"
        profile = db.get_profile(u.profile_id)
        pname = profile.name if profile else u.profile_id[:8]
        print(f"{u.name:<25} {u.email:<30} {pname:<20} {status:<10} {u.id[:8]}")


def cmd_user_get(args):
    db = get_db()
    user = resolve_user(db, args.ref)
    profile = db.get_profile(user.profile_id)
    active_tokens = len(db.list_user_tokens(user.id, active_only=True))
    print(json.dumps({
        "id": user.id, "name": user.name, "email": user.email,
        "profile": profile.name if profile else user.profile_id,
        "profile_id": user.profile_id,
        "external_id": user.external_id,
        "active": user.active,
        "active_sessions": active_tokens,
        "hourly_tool_calls": db.get_hourly_tool_calls(user.id),
        "daily_tokens": db.get_daily_tokens(user.id),
        "created_at": fmt_ts(user.created_at),
        "revoked_at": fmt_ts(user.revoked_at),
    }, indent=2))


def cmd_user_revoke(args):
    db = get_db()
    gate = get_gate(db)
    user = resolve_user(db, args.ref)
    if not user.active:
        print(f"⚠️  User {user.email!r} is already revoked.")
        return
    result = gate.revoke_user(user.id)
    print(f"🚫 User revoked: {user.name} ({user.email})")
    print(f"   tokens killed: {result['tokens_revoked']}")
    print(f"   Access is immediately denied on all active sessions.")


def cmd_user_set_profile(args):
    db = get_db()
    user = resolve_user(db, args.ref)
    profile = resolve_profile(db, args.set)
    ok = db.update_user_profile(user.id, profile.id)
    print(f"{'✅' if ok else '✗'} Profile updated: {user.name} → {profile.name}")


# ── token ─────────────────────────────────────────────────────────────────────

def cmd_token_issue(args):
    db = get_db()
    gate = get_gate(db)
    user = resolve_user(db, args.user)
    token = gate.issue_token(
        user_id=user.id,
        conversation_id=args.conversation,
        ttl_seconds=args.ttl,
    )
    print(f"🔑 Token issued")
    print(f"   token_id:        {token.token_id}")
    print(f"   user:            {user.name} ({user.email})")
    print(f"   conversation_id: {token.conversation_id}")
    print(f"   expires_at:      {fmt_ts(token.expires_at)}")
    print(f"")
    print(f"   TOKEN:")
    print(f"   {token.token}")


def cmd_token_revoke(args):
    db = get_db()
    gate = get_gate(db)
    ok = gate.revoke_token(args.token_id)
    print(f"{'🗑️  Token revoked' if ok else '✗ Token not found or already revoked'}: {args.token_id}")


def cmd_token_inspect(args):
    db = get_db()
    tm = TokenManager(secret=SECRET)
    payload = tm.verify(args.token)
    token = db.get_token(args.token)
    if not payload:
        print("✗ Invalid or expired token (signature verification failed)")
        return
    if token:
        user = db.get_user(token.user_id)
        profile = db.get_profile(token.profile_id)
        print(json.dumps({
            "valid": token.is_valid,
            "revoked": token.revoked,
            "token_id": token.token_id,
            "user": user.name if user else token.user_id,
            "email": user.email if user else None,
            "user_active": user.active if user else None,
            "profile": profile.name if profile else token.profile_id,
            "conversation_id": token.conversation_id,
            "issued_at": fmt_ts(token.issued_at),
            "expires_at": fmt_ts(token.expires_at),
        }, indent=2))
    else:
        print(json.dumps({"valid": True, "payload": payload}, indent=2))


# ── enforce ───────────────────────────────────────────────────────────────────

def cmd_enforce(args):
    db = get_db()
    gate = get_gate(db)
    result = gate.enforce(EnforceRequest(token=args.token, tool_name=args.tool))
    if result.granted:
        print(f"✅ GRANTED — tool: {args.tool}")
        if result.rate_limit_remaining is not None:
            print(f"   rate_limit_remaining: {result.rate_limit_remaining}")
        if result.daily_tokens_remaining is not None:
            print(f"   daily_tokens_remaining: {result.daily_tokens_remaining}")
    else:
        print(f"✗  DENIED  — tool: {args.tool} — reason: {result.deny_reason}", file=sys.stderr)
        sys.exit(1)


# ── audit ─────────────────────────────────────────────────────────────────────

def cmd_audit(args):
    db = get_db()
    user_id = None
    if args.user:
        user = resolve_user(db, args.user)
        user_id = user.id
    events = db.get_audit_log(
        user_id=user_id,
        conversation_id=args.conversation,
        limit=args.limit or 50,
    )
    if not events:
        print("No audit events.")
        return
    print(f"{'TIME':<22} {'TYPE':<20} {'USER':<20} {'TOOL':<30} {'RESULT'}")
    print("-" * 110)
    for e in events:
        verdict = "✅" if e.granted is True else ("✗ " + (e.deny_reason or "")) if e.granted is False else ""
        uid_short = (e.user_id or "")[:8] or "—"
        print(f"{fmt_ts(e.timestamp):<22} {e.event_type:<20} {uid_short:<20} {(e.tool_name or '—'):<30} {verdict}")


def cmd_usage(args):
    db = get_db()
    user = resolve_user(db, args.ref)
    stats = db.get_usage_stats(user.id)
    print(f"Usage for {user.name} ({user.email}):")
    print(f"  Hourly calls (now): {db.get_hourly_tool_calls(user.id)}")
    print(f"  Daily tokens (today): {db.get_daily_tokens(user.id):,}")
    print(f"\n  All windows:")
    for window, data in sorted(stats.items(), reverse=True)[:20]:
        print(f"  {window:<30} calls={data['tool_calls']:<6} tokens={data['token_count']:,}")


# ── serve ─────────────────────────────────────────────────────────────────────

def cmd_serve(args):
    try:
        import uvicorn
    except ImportError:
        print("✗ uvicorn not installed. Run: pip install uvicorn", file=sys.stderr)
        sys.exit(1)
    os.environ["AGENTGATE_DB"] = DB_PATH
    os.environ["AGENTGATE_SECRET"] = SECRET
    host = args.host or "127.0.0.1"
    port = args.port or 8765
    print(f"🚀 agentgate server → http://{host}:{port}")
    uvicorn.run("agentgate.server:app", host=host, port=port, reload=False)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(prog="agentgate", description="Identity-aware access control for AI agents")
    sub = parser.add_subparsers(dest="command")

    # profile
    p_profile = sub.add_parser("profile", help="Manage profiles")
    ps = p_profile.add_subparsers(dest="subcommand")
    pc = ps.add_parser("create")
    pc.add_argument("--name", required=True)
    pc.add_argument("--description", default="")
    pc.add_argument("--allowed", default="*", help="Comma-separated tool globs (default: *)")
    pc.add_argument("--denied", default="", help="Comma-separated denied tool globs")
    pc.add_argument("--rate", type=int, default=0, help="Max tool calls per hour (0=unlimited)")
    pc.add_argument("--tokens", type=int, default=0, help="Max LLM tokens per day (0=unlimited)")
    ps.add_parser("list")
    pg = ps.add_parser("get"); pg.add_argument("ref")

    # user
    p_user = sub.add_parser("user", help="Manage users")
    us = p_user.add_subparsers(dest="subcommand")
    uc = us.add_parser("create")
    uc.add_argument("--name", required=True)
    uc.add_argument("--email", required=True)
    uc.add_argument("--profile", required=True, help="Profile name or id")
    uc.add_argument("--external-id", default="")
    ul = us.add_parser("list"); ul.add_argument("--all", action="store_true")
    ug = us.add_parser("get"); ug.add_argument("ref")
    ur = us.add_parser("revoke"); ur.add_argument("ref")
    up = us.add_parser("profile"); up.add_argument("ref"); up.add_argument("--set", required=True)

    # token
    p_token = sub.add_parser("token", help="Manage session tokens")
    ts2 = p_token.add_subparsers(dest="subcommand")
    ti = ts2.add_parser("issue")
    ti.add_argument("--user", required=True)
    ti.add_argument("--conversation")
    ti.add_argument("--ttl", type=int)
    trv = ts2.add_parser("revoke"); trv.add_argument("token_id")
    tin = ts2.add_parser("inspect"); tin.add_argument("token")

    # enforce
    p_enforce = sub.add_parser("enforce", help="Check a tool call")
    p_enforce.add_argument("--token", required=True)
    p_enforce.add_argument("--tool", required=True)

    # audit
    p_audit = sub.add_parser("audit", help="Query audit log")
    p_audit.add_argument("--user")
    p_audit.add_argument("--conversation")
    p_audit.add_argument("--limit", type=int, default=50)

    # usage
    p_usage = sub.add_parser("usage", help="Usage stats for a user")
    p_usage.add_argument("ref")

    # serve
    p_serve = sub.add_parser("serve", help="Start API server + dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)

    args = parser.parse_args()

    dispatch = {
        ("profile", "create"): cmd_profile_create,
        ("profile", "list"): cmd_profile_list,
        ("profile", "get"): cmd_profile_get,
        ("user", "create"): cmd_user_create,
        ("user", "list"): cmd_user_list,
        ("user", "get"): cmd_user_get,
        ("user", "revoke"): cmd_user_revoke,
        ("user", "profile"): cmd_user_set_profile,
        ("token", "issue"): cmd_token_issue,
        ("token", "revoke"): cmd_token_revoke,
        ("token", "inspect"): cmd_token_inspect,
        ("enforce", None): cmd_enforce,
        ("audit", None): cmd_audit,
        ("usage", None): cmd_usage,
        ("serve", None): cmd_serve,
    }

    key = (args.command, getattr(args, "subcommand", None))
    fn = dispatch.get(key)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
