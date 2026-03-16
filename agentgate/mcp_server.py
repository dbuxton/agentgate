"""
agentgate MCP Server

Exposes agentgate capabilities as MCP (Model Context Protocol) tools,
so AI agents can query and participate in their own governance.

Protocol: JSON-RPC 2.0 over stdio (MCP 2024-11-05 spec)
No external SDK required — pure stdlib asyncio.

Tools:
  check_permission         — pre-check a tool call before executing
  list_my_permissions      — introspect effective permission set
  get_quota_status         — remaining rate limit and daily token quota
  request_elevation        — self-service access escalation request

Usage:
  # Direct stdio (pipe to MCP client)
  AGENTGATE_DB=agentgate.db AGENTGATE_SECRET=... agentgate-mcp

  # With Claude Desktop (add to claude_desktop_config.json):
  {
    "mcpServers": {
      "agentgate": {
        "command": "agentgate-mcp",
        "env": {
          "AGENTGATE_DB": "/path/to/agentgate.db",
          "AGENTGATE_SECRET": "your-secret"
        }
      }
    }
  }
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, Optional

from .db import AgentGateDB
from .gate import AgentGate
from .models import EnforceRequest
from .tokens import TokenManager

# ── Constants ─────────────────────────────────────────────────────────────────

MCP_VERSION = "2024-11-05"
SERVER_NAME = "agentgate"
SERVER_VERSION = "0.2.0"

# ── Tool definitions ──────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "check_permission",
        "description": (
            "Check whether a tool call is permitted for an agent session token. "
            "Call this before executing any tool to pre-validate access. "
            "Returns granted/denied with the reason and remaining quota."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "Agent session token (AGENTGATE_TOKEN env var or from token issuance)",
                },
                "tool_name": {
                    "type": "string",
                    "description": "Name of the tool being checked (e.g. 'crm_get_contact')",
                },
                "token_count": {
                    "type": "integer",
                    "description": "LLM tokens consumed in this call (optional, for quota tracking)",
                    "default": 0,
                },
            },
            "required": ["token", "tool_name"],
        },
    },
    {
        "name": "list_my_permissions",
        "description": (
            "List the effective permissions for an agent session token. "
            "Shows allowed tool patterns, denied patterns, rate limits, and "
            "which profile/teams contribute to the effective permission set."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "Agent session token",
                },
            },
            "required": ["token"],
        },
    },
    {
        "name": "get_quota_status",
        "description": (
            "Get remaining rate limit and daily token quota for an agent session. "
            "Use this to decide whether to proceed with a task or ask for human "
            "approval before consuming budget."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "Agent session token",
                },
            },
            "required": ["token"],
        },
    },
    {
        "name": "request_elevation",
        "description": (
            "Request elevated access to a tool that is not currently permitted. "
            "Creates a pending elevation request that a human admin can approve or deny. "
            "Use this when you need to perform an action outside your normal permission set. "
            "Always include a clear reason — vague requests are more likely to be denied."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "Agent session token",
                },
                "tool_name": {
                    "type": "string",
                    "description": "Tool name you need elevated access to",
                },
                "reason": {
                    "type": "string",
                    "description": "Clear explanation of why you need access to this tool",
                },
            },
            "required": ["token", "tool_name", "reason"],
        },
    },
]

# ── MCP Server ────────────────────────────────────────────────────────────────


class AgentGateMCPServer:
    """
    Stdio MCP server for agentgate.

    Implements the MCP JSON-RPC 2.0 protocol over stdin/stdout.
    Each line on stdin is a complete JSON message; responses are line-delimited JSON.
    """

    def __init__(self, db_path: str, secret: str, token_ttl: int = 8 * 3600):
        self.db = AgentGateDB(db_path)
        tm = TokenManager(secret=secret, ttl_seconds=token_ttl)
        self.gate = AgentGate(db=self.db, token_manager=tm)
        self._initialized = False

    # ── Protocol ──────────────────────────────────────────────────────────────

    def _ok(self, req_id: Any, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _err(self, req_id: Any, code: int, message: str, data: Any = None) -> dict:
        err = {"code": code, "message": message}
        if data:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}

    def _text_content(self, text: str) -> list:
        return [{"type": "text", "text": text}]

    # ── Handlers ──────────────────────────────────────────────────────────────

    def handle_initialize(self, req_id: Any, params: dict) -> dict:
        self._initialized = True
        return self._ok(req_id, {
            "protocolVersion": MCP_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        })

    def handle_initialized(self, req_id: Any, params: dict) -> Optional[dict]:
        # Notification — no response
        return None

    def handle_tools_list(self, req_id: Any, params: dict) -> dict:
        return self._ok(req_id, {"tools": TOOLS})

    def handle_tools_call(self, req_id: Any, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments", {})

        try:
            if name == "check_permission":
                return self._tool_check_permission(req_id, args)
            elif name == "list_my_permissions":
                return self._tool_list_permissions(req_id, args)
            elif name == "get_quota_status":
                return self._tool_quota_status(req_id, args)
            elif name == "request_elevation":
                return self._tool_request_elevation(req_id, args)
            else:
                return self._err(req_id, -32601, f"Unknown tool: {name}")
        except Exception as e:
            return self._ok(req_id, {
                "content": self._text_content(f"Error: {e}"),
                "isError": True,
            })

    # ── Tool implementations ──────────────────────────────────────────────────

    def _resolve_token(self, args: dict) -> tuple[str, dict]:
        """Extract token from args; fall back to AGENTGATE_TOKEN env var."""
        token = args.get("token") or os.environ.get("AGENTGATE_TOKEN", "")
        if not token:
            raise ValueError(
                "No token provided. Pass 'token' argument or set AGENTGATE_TOKEN env var."
            )
        return token

    def _tool_check_permission(self, req_id: Any, args: dict) -> dict:
        token = self._resolve_token(args)
        tool_name = args.get("tool_name", "")
        token_count = int(args.get("token_count", 0))

        if not tool_name:
            raise ValueError("tool_name is required")

        req = EnforceRequest(token=token, tool_name=tool_name, token_count=token_count)
        result = self.gate.enforce(req)

        if result.granted:
            lines = [
                f"✅ GRANTED — `{tool_name}` is permitted",
                "",
            ]
            if result.rate_limit_remaining is not None:
                lines.append(f"Rate limit remaining: {result.rate_limit_remaining}/hr")
            if result.daily_tokens_remaining is not None:
                lines.append(f"Daily token quota remaining: {result.daily_tokens_remaining:,}")
        else:
            lines = [
                f"✗ DENIED — `{tool_name}` is not permitted",
                f"Reason: {result.deny_reason}",
                "",
                "You can call request_elevation() to ask an admin for access.",
            ]

        return self._ok(req_id, {
            "content": self._text_content("\n".join(lines)),
            "isError": not result.granted,
        })

    def _tool_list_permissions(self, req_id: Any, args: dict) -> dict:
        token = self._resolve_token(args)

        # Decode token to get user
        claims = self.gate.tm.verify(token)
        if not claims:
            raise ValueError("Invalid or expired token")

        user = self.db.get_user(claims["uid"])
        if not user:
            raise ValueError("User not found")

        perms = self.gate.resolve_effective_permissions(user)

        lines = [
            f"**Effective permissions for session**",
            f"User: {user.name} ({user.email})",
            "",
            "**Allowed tool patterns:**",
        ]
        for pat in perms.allowed_tools:
            lines.append(f"  • {pat}")

        if perms.denied_tools:
            lines.append("\n**Denied tool patterns (override allowed):**")
            for pat in perms.denied_tools:
                lines.append(f"  • {pat}")
        else:
            lines.append("\nNo explicit denies.")

        lines.append("")
        if perms.rate_limit_per_hour > 0:
            lines.append(f"Rate limit: {perms.rate_limit_per_hour} calls/hour")
        else:
            lines.append("Rate limit: unlimited")

        if perms.max_tokens_per_day > 0:
            lines.append(f"Daily token quota: {perms.max_tokens_per_day:,} tokens")
        else:
            lines.append("Daily token quota: unlimited")

        lines.append(f"\nSource profile: {perms.source_profile_id}")
        if perms.source_team_ids:
            lines.append(f"Team roles: {', '.join(perms.source_team_ids)}")

        return self._ok(req_id, {
            "content": self._text_content("\n".join(lines)),
        })

    def _tool_quota_status(self, req_id: Any, args: dict) -> dict:
        token = self._resolve_token(args)

        claims = self.gate.tm.verify(token)
        if not claims:
            raise ValueError("Invalid or expired token")

        user = self.db.get_user(claims["uid"])
        if not user:
            raise ValueError("User not found")

        perms = self.gate.resolve_effective_permissions(user)

        # Get usage counters
        now = time.time()
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(now, tz=timezone.utc)
        hour_key = f"hourly:{dt.strftime('%Y-%m-%d-%H')}"
        day_key = f"daily:{dt.strftime('%Y-%m-%d')}"

        hourly_used = self.db.get_usage(user.id, hour_key)
        daily_used = self.db.get_usage(user.id, day_key)

        lines = ["**Quota Status**", ""]

        if perms.rate_limit_per_hour > 0:
            remaining = max(0, perms.rate_limit_per_hour - hourly_used)
            pct = int(100 * hourly_used / perms.rate_limit_per_hour)
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
            lines.append(f"Rate limit: {hourly_used}/{perms.rate_limit_per_hour} calls this hour")
            lines.append(f"  [{bar}] {pct}%")
            lines.append(f"  Remaining: {remaining} calls")
        else:
            lines.append("Rate limit: unlimited (no cap set)")

        lines.append("")

        if perms.max_tokens_per_day > 0:
            remaining = max(0, perms.max_tokens_per_day - daily_used)
            pct = int(100 * daily_used / perms.max_tokens_per_day)
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
            lines.append(f"Token quota: {daily_used:,}/{perms.max_tokens_per_day:,} tokens today")
            lines.append(f"  [{bar}] {pct}%")
            lines.append(f"  Remaining: {remaining:,} tokens")
        else:
            lines.append("Token quota: unlimited (no cap set)")

        # Warn if running low
        warnings = []
        if perms.rate_limit_per_hour > 0:
            r = max(0, perms.rate_limit_per_hour - hourly_used)
            if r < perms.rate_limit_per_hour * 0.1:
                warnings.append(f"⚠️  Rate limit nearly exhausted ({r} calls remaining)")
        if perms.max_tokens_per_day > 0:
            r = max(0, perms.max_tokens_per_day - daily_used)
            if r < perms.max_tokens_per_day * 0.1:
                warnings.append(f"⚠️  Token quota nearly exhausted ({r:,} tokens remaining)")

        if warnings:
            lines.append("")
            lines.extend(warnings)

        return self._ok(req_id, {
            "content": self._text_content("\n".join(lines)),
        })

    def _tool_request_elevation(self, req_id: Any, args: dict) -> dict:
        token = self._resolve_token(args)
        tool_name = args.get("tool_name", "")
        reason = args.get("reason", "")

        if not tool_name:
            raise ValueError("tool_name is required")
        if not reason or len(reason) < 10:
            raise ValueError("reason must be at least 10 characters — explain clearly why you need access")

        claims = self.gate.tm.verify(token)
        if not claims:
            raise ValueError("Invalid or expired token")

        user = self.db.get_user(claims["uid"])
        if not user:
            raise ValueError("User not found")

        # Check if already has permission
        req = EnforceRequest(token=token, tool_name=tool_name)
        # Do a dry-run check without recording to audit log
        result = self.gate.enforce(req)
        if result.granted:
            return self._ok(req_id, {
                "content": self._text_content(
                    f"ℹ️  You already have permission to use `{tool_name}`. No elevation needed."
                ),
            })

        # Create elevation request
        elev = self.db.create_elevation_request(
            user_id=user.id,
            token_id=claims.get("tid", ""),
            tool_name=tool_name,
            reason=reason,
        )

        lines = [
            f"📋 Elevation request submitted",
            f"",
            f"Request ID: {elev['id']}",
            f"Tool: {tool_name}",
            f"Status: pending",
            f"",
            f"An admin has been notified. Your request will be reviewed shortly.",
            f"To check status: GET /elevation/{elev['id']} on the agentgate server.",
        ]

        return self._ok(req_id, {
            "content": self._text_content("\n".join(lines)),
        })

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def dispatch(self, message: dict) -> Optional[dict]:
        """Route a JSON-RPC message to the appropriate handler."""
        req_id = message.get("id")
        method = message.get("method", "")
        params = message.get("params", {})

        if method == "initialize":
            return self.handle_initialize(req_id, params)
        elif method == "notifications/initialized":
            return None  # notification, no response
        elif method == "tools/list":
            return self.handle_tools_list(req_id, params)
        elif method == "tools/call":
            return self.handle_tools_call(req_id, params)
        elif method == "ping":
            return self._ok(req_id, {})
        else:
            if req_id is not None:
                return self._err(req_id, -32601, f"Method not found: {method}")
            return None

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run(self):
        """Read JSON-RPC messages from stdin, write responses to stdout."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        writer_transport, writer_protocol = await loop.connect_write_pipe(
            asyncio.BaseProtocol, sys.stdout.buffer
        )

        async def write_json(obj: dict):
            line = json.dumps(obj) + "\n"
            writer_transport.write(line.encode())

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                try:
                    message = json.loads(line)
                except json.JSONDecodeError as e:
                    resp = self._err(None, -32700, f"Parse error: {e}")
                    await write_json(resp)
                    continue

                response = self.dispatch(message)
                if response is not None:
                    await write_json(response)

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log to stderr, not stdout (stdout is the MCP channel)
                print(f"[agentgate-mcp] Error: {e}", file=sys.stderr)


def main():
    """Entry point: agentgate-mcp"""
    db_path = os.environ.get("AGENTGATE_DB", "agentgate.db")
    secret = os.environ.get("AGENTGATE_SECRET", "change-me-in-production")
    token_ttl = int(os.environ.get("AGENTGATE_TOKEN_TTL", str(8 * 3600)))

    server = AgentGateMCPServer(db_path=db_path, secret=secret, token_ttl=token_ttl)
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
