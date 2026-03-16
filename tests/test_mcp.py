"""
Tests for agentgate MCP server.

Tests the MCP JSON-RPC dispatch layer, tool implementations,
and protocol correctness — without requiring a real asyncio
event loop or stdio pipe.
"""

import json
import pytest

from agentgate.db import AgentGateDB
from agentgate.gate import AgentGate
from agentgate.mcp_server import AgentGateMCPServer, TOOLS
from agentgate.tokens import TokenManager


@pytest.fixture
def server(tmp_path):
    db_path = str(tmp_path / "mcp_test.db")
    secret = "mcp-test-secret"
    return AgentGateMCPServer(db_path=db_path, secret=secret, token_ttl=3600)


@pytest.fixture
def user_token(server):
    """Create a user with restricted profile and return a valid session token."""
    profile = server.db.create_profile(
        name="analyst",
        allowed_tools=["read_*", "search_*"],
        denied_tools=["delete_*"],
        rate_limit_per_hour=20,
        max_tokens_per_day=5000,
    )
    user = server.db.create_user(name="Dana", email="dana@corp.com", profile_id=profile.id)
    token = server.gate.issue_token(user_id=user.id, conversation_id="conv-mcp-001")
    return token.token, user


# ── Protocol tests ─────────────────────────────────────────────────────────────

class TestMCPProtocol:
    def test_initialize(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test"}},
        })
        assert resp["id"] == 1
        assert "result" in resp
        assert resp["result"]["protocolVersion"] == "2024-11-05"
        assert resp["result"]["serverInfo"]["name"] == "agentgate"
        assert "tools" in resp["result"]["capabilities"]

    def test_tools_list(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        })
        assert resp["id"] == 2
        tools = resp["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        assert "check_permission" in tool_names
        assert "list_my_permissions" in tool_names
        assert "get_quota_status" in tool_names
        assert "request_elevation" in tool_names

    def test_tools_have_input_schema(self, server):
        for tool in TOOLS:
            assert "inputSchema" in tool
            assert tool["inputSchema"]["type"] == "object"
            assert "properties" in tool["inputSchema"]

    def test_ping(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "ping",
            "params": {},
        })
        assert resp["result"] == {}

    def test_unknown_method_returns_error(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "not_a_method",
            "params": {},
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    def test_notification_no_response(self, server):
        """Notifications (no id) should return None."""
        resp = server.dispatch({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        })
        assert resp is None

    def test_unknown_notification_silent(self, server):
        """Unknown notifications (no id) should return None, not error."""
        resp = server.dispatch({
            "jsonrpc": "2.0",
            "method": "some/unknown/notification",
            "params": {},
        })
        assert resp is None


# ── Tool: check_permission ────────────────────────────────────────────────────

class TestCheckPermission:
    def test_allowed_tool(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "token": token, "tool_name": "read_orders",
            }},
        })
        content = resp["result"]["content"][0]["text"]
        assert "GRANTED" in content
        assert "read_orders" in content
        assert resp["result"].get("isError") is not True

    def test_denied_tool(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "token": token, "tool_name": "delete_user",
            }},
        })
        result = resp["result"]
        content = result["content"][0]["text"]
        assert "DENIED" in content
        assert result.get("isError") is True

    def test_not_in_allowed_glob(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "token": token, "tool_name": "write_orders",
            }},
        })
        # write_* is not in allowed_tools=["read_*", "search_*"]
        assert resp["result"].get("isError") is True

    def test_denied_shows_elevation_hint(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 13, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "token": token, "tool_name": "delete_record",
            }},
        })
        content = resp["result"]["content"][0]["text"]
        assert "request_elevation" in content

    def test_invalid_token(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 14, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "token": "bad.token.here", "tool_name": "read_x",
            }},
        })
        # Should return isError=True, not crash
        assert resp["result"].get("isError") is True

    def test_missing_token(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 15, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "tool_name": "read_x",
            }},
        })
        assert resp["result"].get("isError") is True

    def test_missing_tool_name(self, server, user_token):
        token, _ = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 16, "method": "tools/call",
            "params": {"name": "check_permission", "arguments": {
                "token": token,
            }},
        })
        assert resp["result"].get("isError") is True


# ── Tool: list_my_permissions ─────────────────────────────────────────────────

class TestListMyPermissions:
    def test_lists_allowed_tools(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 20, "method": "tools/call",
            "params": {"name": "list_my_permissions", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "read_*" in content
        assert "search_*" in content
        assert "Allowed" in content

    def test_lists_denied_tools(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 21, "method": "tools/call",
            "params": {"name": "list_my_permissions", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "delete_*" in content

    def test_shows_rate_limit(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 22, "method": "tools/call",
            "params": {"name": "list_my_permissions", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "20" in content  # rate_limit_per_hour
        assert "5,000" in content  # max_tokens_per_day

    def test_shows_user_name(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 23, "method": "tools/call",
            "params": {"name": "list_my_permissions", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "Dana" in content

    def test_invalid_token(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 24, "method": "tools/call",
            "params": {"name": "list_my_permissions", "arguments": {"token": "bad"}},
        })
        assert resp["result"].get("isError") is True


# ── Tool: get_quota_status ────────────────────────────────────────────────────

class TestGetQuotaStatus:
    def test_fresh_user_shows_zero_usage(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {"name": "get_quota_status", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "Quota Status" in content
        assert "0/" in content  # 0/20 calls or 0/5000 tokens

    def test_shows_rate_limit_bar(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 31, "method": "tools/call",
            "params": {"name": "get_quota_status", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "█" in content or "░" in content  # progress bar characters

    def test_unlimited_profile_shows_unlimited(self, server):
        profile = server.db.create_profile(
            name="unlimited",
            allowed_tools=["*"],
            rate_limit_per_hour=0,
            max_tokens_per_day=0,
        )
        user = server.db.create_user(name="Free", email="free@x.com", profile_id=profile.id)
        token = server.gate.issue_token(user_id=user.id, conversation_id="conv-free").token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": {"name": "get_quota_status", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "unlimited" in content.lower()

    def test_usage_reflected_after_enforce(self, server, user_token):
        from agentgate.models import EnforceRequest
        token, user = user_token
        # Make a successful tool call to increment counters
        server.gate.enforce(EnforceRequest(token=token, tool_name="read_data", token_count=100))
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 33, "method": "tools/call",
            "params": {"name": "get_quota_status", "arguments": {"token": token}},
        })
        content = resp["result"]["content"][0]["text"]
        assert "1/" in content  # 1/20 calls used


# ── Tool: request_elevation ───────────────────────────────────────────────────

class TestRequestElevation:
    def test_creates_pending_request(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 40, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": token,
                "tool_name": "delete_old_records",
                "reason": "Removing expired trial accounts as part of Q1 cleanup",
            }},
        })
        content = resp["result"]["content"][0]["text"]
        assert "submitted" in content.lower()
        assert "delete_old_records" in content
        assert "Request ID" in content

        # Verify it's in the DB
        pending = server.db.list_elevation_requests(status="pending")
        assert any(e["tool_name"] == "delete_old_records" for e in pending)

    def test_already_permitted_tool_no_request(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 41, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": token,
                "tool_name": "read_reports",  # already allowed by read_*
                "reason": "Need to read reports for analysis",
            }},
        })
        content = resp["result"]["content"][0]["text"]
        assert "already have permission" in content.lower()

    def test_short_reason_rejected(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": token,
                "tool_name": "delete_x",
                "reason": "need it",
            }},
        })
        assert resp["result"].get("isError") is True

    def test_invalid_token(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 43, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": "invalid",
                "tool_name": "admin_x",
                "reason": "This is a valid reason with enough characters",
            }},
        })
        assert resp["result"].get("isError") is True

    def test_request_includes_id_for_tracking(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 44, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": token,
                "tool_name": "write_audit",
                "reason": "Writing compliance audit trail for SOC 2 review",
            }},
        })
        content = resp["result"]["content"][0]["text"]
        # Request ID should be in the output for tracking
        assert "Request ID" in content

    def test_missing_tool_name(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 45, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": token,
                "reason": "A long enough reason to pass validation",
            }},
        })
        assert resp["result"].get("isError") is True

    def test_missing_reason(self, server, user_token):
        token, user = user_token
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 46, "method": "tools/call",
            "params": {"name": "request_elevation", "arguments": {
                "token": token,
                "tool_name": "delete_y",
            }},
        })
        assert resp["result"].get("isError") is True


# ── Unknown tool ──────────────────────────────────────────────────────────────

class TestUnknownTool:
    def test_unknown_tool_name_returns_error(self, server):
        resp = server.dispatch({
            "jsonrpc": "2.0", "id": 99, "method": "tools/call",
            "params": {"name": "do_something_not_defined", "arguments": {}},
        })
        assert "error" in resp or resp["result"].get("isError")
