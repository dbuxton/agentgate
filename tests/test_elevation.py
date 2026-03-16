"""
Tests for elevation request feature (DB + REST API).

Covers: create, get, list, approve, deny, duplicate review prevention,
and expired-request edge cases.
"""

import time
import pytest
from fastapi.testclient import TestClient

from agentgate.db import AgentGateDB
from agentgate.gate import AgentGate
from agentgate.tokens import TokenManager
from agentgate.server import app, db as _db, gate as _gate, tm as _tm


# ── DB-level tests ─────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    return AgentGateDB(str(tmp_path / "test.db"))


@pytest.fixture
def profile(db):
    return db.create_profile(
        name="limited",
        allowed_tools=["read_*"],
        denied_tools=["write_*"],
        rate_limit_per_hour=50,
        max_tokens_per_day=10000,
    )


@pytest.fixture
def user(db, profile):
    return db.create_user(name="Bob", email="bob@acme.com", profile_id=profile.id)


class TestElevationDB:
    def test_create_elevation_request(self, db, user):
        elev = db.create_elevation_request(
            user_id=user.id,
            token_id="tok-001",
            tool_name="write_orders",
            reason="Need to update order status for customer complaint",
        )
        assert elev["id"]
        assert elev["status"] == "pending"
        assert elev["tool_name"] == "write_orders"
        assert elev["user_id"] == user.id
        assert elev["expires_at"] > elev["created_at"]

    def test_get_elevation_request(self, db, user):
        elev = db.create_elevation_request(
            user_id=user.id,
            token_id="tok-002",
            tool_name="delete_record",
            reason="Removing duplicate customer entry per manager request",
        )
        fetched = db.get_elevation_request(elev["id"])
        assert fetched is not None
        assert fetched["id"] == elev["id"]
        assert fetched["tool_name"] == "delete_record"

    def test_get_nonexistent(self, db):
        assert db.get_elevation_request("no-such-id") is None

    def test_list_all(self, db, user):
        db.create_elevation_request(user.id, "t1", "tool_a", "reason for tool_a access needed")
        db.create_elevation_request(user.id, "t2", "tool_b", "reason for tool_b access needed")
        items = db.list_elevation_requests()
        assert len(items) >= 2

    def test_list_by_status(self, db, user):
        elev = db.create_elevation_request(user.id, "t3", "tool_c", "need tool_c for bulk ops")
        # Before review — only one pending
        pending = db.list_elevation_requests(status="pending")
        assert any(e["id"] == elev["id"] for e in pending)
        # After approval
        db.update_elevation_status(elev["id"], "approved", reviewed_by="admin@acme.com")
        pending2 = db.list_elevation_requests(status="pending")
        assert not any(e["id"] == elev["id"] for e in pending2)
        approved = db.list_elevation_requests(status="approved")
        assert any(e["id"] == elev["id"] for e in approved)

    def test_approve(self, db, user):
        elev = db.create_elevation_request(user.id, "t4", "tool_d", "needs tool_d for reporting")
        ok = db.update_elevation_status(elev["id"], "approved", reviewed_by="admin")
        assert ok
        updated = db.get_elevation_request(elev["id"])
        assert updated["status"] == "approved"
        assert updated["reviewed_by"] == "admin"
        assert updated["reviewed_at"] is not None

    def test_deny(self, db, user):
        elev = db.create_elevation_request(user.id, "t5", "tool_e", "wants tool_e just in case")
        ok = db.update_elevation_status(elev["id"], "denied", reviewed_by="security@acme.com")
        assert ok
        updated = db.get_elevation_request(elev["id"])
        assert updated["status"] == "denied"

    def test_cannot_re_review(self, db, user):
        """Once approved or denied, status cannot be changed again."""
        elev = db.create_elevation_request(user.id, "t6", "tool_f", "needs tool_f for compliance")
        db.update_elevation_status(elev["id"], "approved")
        # Second call should return False (no rows updated)
        ok = db.update_elevation_status(elev["id"], "denied")
        assert not ok
        # Status still approved
        final = db.get_elevation_request(elev["id"])
        assert final["status"] == "approved"

    def test_invalid_status_value(self, db, user):
        elev = db.create_elevation_request(user.id, "t7", "tool_g", "needs tool_g access now")
        with pytest.raises(ValueError):
            db.update_elevation_status(elev["id"], "pending")  # not allowed via update

    def test_list_by_user(self, db, profile):
        user_a = db.create_user(name="A", email="a@x.com", profile_id=profile.id)
        user_b = db.create_user(name="B", email="b@x.com", profile_id=profile.id)
        db.create_elevation_request(user_a.id, "t8", "tool_h", "user_a needs tool_h for onboarding")
        db.create_elevation_request(user_b.id, "t9", "tool_i", "user_b needs tool_i for reports")
        only_a = db.list_elevation_requests(user_id=user_a.id)
        assert all(e["user_id"] == user_a.id for e in only_a)


# ── REST API tests ─────────────────────────────────────────────────────────────

@pytest.fixture
def api_client(tmp_path):
    """
    Override the module-level db/gate/tm with a fresh temp DB for API tests.
    """
    import agentgate.server as srv
    fresh_db = AgentGateDB(str(tmp_path / "api_test.db"))
    fresh_tm = TokenManager(secret="test-secret", ttl_seconds=3600)
    fresh_gate = AgentGate(db=fresh_db, token_manager=fresh_tm)

    # Patch server globals
    original_db, original_gate, original_tm = srv.db, srv.gate, srv.tm
    srv.db = fresh_db
    srv.gate = fresh_gate
    srv.tm = fresh_tm

    client = TestClient(app)
    yield client, fresh_db, fresh_gate, fresh_tm

    srv.db = original_db
    srv.gate = original_gate
    srv.tm = original_tm


@pytest.fixture
def setup_user(api_client):
    client, db, gate, tm = api_client
    profile = db.create_profile(name="base", allowed_tools=["read_*"], denied_tools=["admin_*"])
    user = db.create_user(name="Carol", email="carol@acme.com", profile_id=profile.id)
    token = gate.issue_token(user_id=user.id, conversation_id="conv-elev")
    return client, db, user, token.token


class TestElevationAPI:
    def test_create_via_api(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_reports",
            "reason": "Need to pull quarterly report for board meeting",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["tool_name"] == "admin_reports"

    def test_create_reason_too_short(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_x",
            "reason": "short",
        })
        assert resp.status_code == 400

    def test_create_invalid_token(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": "bad-token",
            "tool_name": "tool_x",
            "reason": "long enough reason here",
        })
        assert resp.status_code == 401

    def test_list_empty(self, api_client):
        client, *_ = api_client
        resp = client.get("/elevation")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_with_filter(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_delete",
            "reason": "Cleanup duplicate user records from import",
        })
        req_id = resp.json()["id"]

        # List all
        all_items = client.get("/elevation").json()
        assert any(e["id"] == req_id for e in all_items)

        # Filter pending
        pending = client.get("/elevation?status=pending").json()
        assert any(e["id"] == req_id for e in pending)

        # Filter approved (should be empty)
        approved = client.get("/elevation?status=approved").json()
        assert not any(e["id"] == req_id for e in approved)

    def test_get_single(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_export",
            "reason": "Exporting customer data for annual audit",
        })
        req_id = resp.json()["id"]
        get_resp = client.get(f"/elevation/{req_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == req_id

    def test_approve_via_api(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_approve",
            "reason": "Manager confirmed this is needed for onboarding flow",
        })
        req_id = resp.json()["id"]

        approve_resp = client.post(f"/elevation/{req_id}/approve", json={"reviewed_by": "admin@acme.com"})
        assert approve_resp.status_code == 200
        data = approve_resp.json()
        assert data["status"] == "approved"
        assert data["reviewed_by"] == "admin@acme.com"

    def test_deny_via_api(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_nuke",
            "reason": "Want to delete all records from the production database",
        })
        req_id = resp.json()["id"]

        deny_resp = client.post(f"/elevation/{req_id}/deny", json={"reviewed_by": "security@acme.com"})
        assert deny_resp.status_code == 200
        assert deny_resp.json()["status"] == "denied"

    def test_double_approve_rejected(self, setup_user):
        client, db, user, token = setup_user
        resp = client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_readonly",
            "reason": "Need read-only admin access for debugging session",
        })
        req_id = resp.json()["id"]
        client.post(f"/elevation/{req_id}/approve", json={})
        # Second approval attempt
        resp2 = client.post(f"/elevation/{req_id}/approve", json={})
        assert resp2.status_code == 400  # already reviewed

    def test_approve_nonexistent(self, api_client):
        client, *_ = api_client
        resp = client.post("/elevation/no-such-id/approve", json={})
        assert resp.status_code == 404

    def test_dashboard_includes_elevation(self, setup_user):
        client, db, user, token = setup_user
        client.post("/elevation", json={
            "token": token,
            "tool_name": "admin_view",
            "reason": "Checking admin panel for support escalation",
        })
        dash = client.get("/")
        assert dash.status_code == 200
        html = dash.text
        assert "Elevation Requests" in html
        assert "admin_view" in html
        assert "pending" in html
