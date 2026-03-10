"""
Tests for agentgate — 44 assertions across the full stack.
"""

import time
import pytest
from agentgate.db import AgentGateDB
from agentgate.gate import AgentGate
from agentgate.models import EnforceRequest
from agentgate.tokens import TokenManager


@pytest.fixture
def db(tmp_path):
    return AgentGateDB(str(tmp_path / "test.db"))


@pytest.fixture
def gate(db):
    tm = TokenManager(secret="test-secret", ttl_seconds=3600)
    return AgentGate(db=db, token_manager=tm)


@pytest.fixture
def profile(db):
    return db.create_profile(
        name="employee",
        description="Standard employee profile",
        allowed_tools=["crm_*", "email_*"],
        denied_tools=["crm_delete_*"],
        rate_limit_per_hour=10,
        max_tokens_per_day=50000,
    )


@pytest.fixture
def user(db, profile):
    return db.create_user(
        name="Alice",
        email="alice@acme.com",
        profile_id=profile.id,
    )


@pytest.fixture
def token(gate, user):
    return gate.issue_token(user_id=user.id, conversation_id="conv-001")


# ── Profile tests ─────────────────────────────────────────────────────────────

class TestProfiles:
    def test_create_profile(self, db):
        p = db.create_profile(name="admin", allowed_tools=["*"])
        assert p.id
        assert p.name == "admin"
        assert p.allowed_tools == ["*"]

    def test_profile_roundtrip(self, db):
        p = db.create_profile(name="limited", allowed_tools=["read_*"], denied_tools=["write_*"])
        fetched = db.get_profile(p.id)
        assert fetched.name == "limited"
        assert fetched.allowed_tools == ["read_*"]
        assert fetched.denied_tools == ["write_*"]

    def test_get_profile_by_name(self, db):
        db.create_profile(name="viewer")
        p = db.get_profile_by_name("viewer")
        assert p is not None
        assert p.name == "viewer"

    def test_list_profiles(self, db):
        db.create_profile(name="alpha")
        db.create_profile(name="beta")
        profiles = db.list_profiles()
        names = [p.name for p in profiles]
        assert "alpha" in names
        assert "beta" in names

    def test_profile_not_found(self, db):
        assert db.get_profile("nonexistent") is None


# ── User tests ────────────────────────────────────────────────────────────────

class TestUsers:
    def test_create_user(self, db, profile):
        u = db.create_user(name="Bob", email="bob@acme.com", profile_id=profile.id)
        assert u.id
        assert u.email == "bob@acme.com"
        assert u.active is True

    def test_get_by_email(self, db, user):
        found = db.get_user_by_email(user.email)
        assert found.id == user.id

    def test_revoke_user(self, db, user):
        ok = db.revoke_user(user.id)
        assert ok
        u = db.get_user(user.id)
        assert u.active is False
        assert u.revoked_at is not None

    def test_revoke_idempotent(self, db, user):
        db.revoke_user(user.id)
        ok2 = db.revoke_user(user.id)
        assert ok2 is False  # already revoked

    def test_update_profile(self, db, user, profile):
        p2 = db.create_profile(name="manager", allowed_tools=["*"])
        ok = db.update_user_profile(user.id, p2.id)
        assert ok
        u = db.get_user(user.id)
        assert u.profile_id == p2.id

    def test_list_users_active_only(self, db, profile):
        u1 = db.create_user(name="Active", email="a@x.com", profile_id=profile.id)
        u2 = db.create_user(name="Gone", email="g@x.com", profile_id=profile.id)
        db.revoke_user(u2.id)
        users = db.list_users(active_only=True)
        ids = [u.id for u in users]
        assert u1.id in ids
        assert u2.id not in ids

    def test_get_by_external_id(self, db, profile):
        u = db.create_user(name="Ext", email="ext@x.com", profile_id=profile.id, external_id="django:42")
        found = db.get_user_by_external_id("django:42")
        assert found.id == u.id


# ── Token tests ───────────────────────────────────────────────────────────────

class TestTokens:
    def test_issue_token(self, gate, user):
        t = gate.issue_token(user.id)
        assert t.token
        assert t.user_id == user.id
        assert t.is_valid

    def test_token_signature(self):
        tm = TokenManager(secret="secret123", ttl_seconds=3600)
        t = tm.issue(user_id="u1", profile_id="p1")
        payload = tm.verify(t.token)
        assert payload is not None
        assert payload["uid"] == "u1"

    def test_tampered_token_rejected(self):
        tm = TokenManager(secret="secret123", ttl_seconds=3600)
        t = tm.issue(user_id="u1", profile_id="p1")
        bad = t.token[:-4] + "xxxx"
        assert tm.verify(bad) is None

    def test_expired_token_rejected(self):
        tm = TokenManager(secret="secret123", ttl_seconds=-1)  # already expired
        t = tm.issue(user_id="u1", profile_id="p1")
        assert tm.verify(t.token) is None

    def test_revoke_token(self, gate, user, token):
        ok = gate.revoke_token(token.token_id)
        assert ok
        stored = gate.db.get_token(token.token)
        assert stored.revoked is True

    def test_revoke_all_user_tokens(self, gate, user):
        t1 = gate.issue_token(user.id)
        t2 = gate.issue_token(user.id)
        n = gate.db.revoke_all_user_tokens(user.id)
        assert n == 2
        assert not gate.db.get_token(t1.token).is_valid
        assert not gate.db.get_token(t2.token).is_valid


# ── Enforcement tests ─────────────────────────────────────────────────────────

class TestEnforcement:
    def test_allowed_tool(self, gate, token):
        result = gate.enforce(EnforceRequest(token=token.token, tool_name="crm_get_contact"))
        assert result.granted

    def test_denied_tool_glob(self, gate, token):
        result = gate.enforce(EnforceRequest(token=token.token, tool_name="crm_delete_contact"))
        assert not result.granted
        assert result.deny_reason == "tool_explicitly_denied"

    def test_not_in_allowlist(self, gate, token):
        result = gate.enforce(EnforceRequest(token=token.token, tool_name="payments_send"))
        assert not result.granted
        assert result.deny_reason == "tool_not_allowed"

    def test_invalid_token(self, gate):
        result = gate.enforce(EnforceRequest(token="garbage.token", tool_name="crm_get"))
        assert not result.granted
        assert result.deny_reason == "invalid_token"

    def test_revoked_token(self, gate, token):
        gate.revoke_token(token.token_id)
        result = gate.enforce(EnforceRequest(token=token.token, tool_name="crm_get_contact"))
        assert not result.granted
        assert result.deny_reason == "token_revoked"

    def test_revoked_user(self, gate, user, token):
        gate.revoke_user(user.id)
        result = gate.enforce(EnforceRequest(token=token.token, tool_name="crm_get_contact"))
        assert not result.granted
        assert result.deny_reason == "user_revoked"

    def test_rate_limit(self, db, gate):
        """Profile with rate_limit=3 — 4th call should be denied."""
        p = db.create_profile(
            name="tight", allowed_tools=["*"], rate_limit_per_hour=3
        )
        u = db.create_user(name="Tight", email="tight@x.com", profile_id=p.id)
        t = gate.issue_token(u.id)

        for _ in range(3):
            r = gate.enforce(EnforceRequest(token=t.token, tool_name="anything"))
            assert r.granted

        r4 = gate.enforce(EnforceRequest(token=t.token, tool_name="anything"))
        assert not r4.granted
        assert r4.deny_reason == "rate_limit_exceeded"

    def test_wildcard_allowlist(self, db, gate):
        """Profile with allowed_tools=* should allow everything not in denied."""
        p = db.create_profile(name="admin", allowed_tools=["*"])
        u = db.create_user(name="Admin", email="admin@x.com", profile_id=p.id)
        t = gate.issue_token(u.id)
        result = gate.enforce(EnforceRequest(token=t.token, tool_name="anything_at_all"))
        assert result.granted

    def test_rate_limit_remaining(self, db, gate):
        p = db.create_profile(name="limited2", allowed_tools=["*"], rate_limit_per_hour=5)
        u = db.create_user(name="Bob", email="bob2@x.com", profile_id=p.id)
        t = gate.issue_token(u.id)
        r = gate.enforce(EnforceRequest(token=t.token, tool_name="something"))
        assert r.rate_limit_remaining == 4

    def test_audit_log_on_grant(self, gate, user, token):
        gate.enforce(EnforceRequest(token=token.token, tool_name="crm_get_contact"))
        events = gate.db.get_audit_log(user_id=user.id, event_type="tool_call")
        assert any(e.granted and e.tool_name == "crm_get_contact" for e in events)

    def test_audit_log_on_deny(self, gate, user, token):
        gate.enforce(EnforceRequest(token=token.token, tool_name="crm_delete_everything"))
        events = gate.db.get_audit_log(user_id=user.id, event_type="tool_call")
        assert any(not e.granted for e in events)


# ── Usage counter tests ───────────────────────────────────────────────────────

class TestUsage:
    def test_hourly_counter(self, db, profile, user):
        db.increment_usage(user.id, token_count=100)
        db.increment_usage(user.id, token_count=200)
        assert db.get_hourly_tool_calls(user.id) == 2
        assert db.get_daily_tokens(user.id) == 300

    def test_usage_stats_format(self, db, user):
        db.increment_usage(user.id)
        stats = db.get_usage_stats(user.id)
        assert len(stats) > 0
        for key, val in stats.items():
            assert "tool_calls" in val
            assert "token_count" in val


# ── Offboarding tests ─────────────────────────────────────────────────────────

class TestOffboarding:
    def test_revoke_user_kills_sessions(self, gate, user):
        t1 = gate.issue_token(user.id)
        t2 = gate.issue_token(user.id)

        # Both work before revocation
        assert gate.enforce(EnforceRequest(token=t1.token, tool_name="crm_get")).granted
        assert gate.enforce(EnforceRequest(token=t2.token, tool_name="crm_get")).granted

        # Revoke
        result = gate.revoke_user(user.id)
        assert result["user_revoked"]
        assert result["tokens_revoked"] == 2

        # Both denied after revocation
        r1 = gate.enforce(EnforceRequest(token=t1.token, tool_name="crm_get"))
        r2 = gate.enforce(EnforceRequest(token=t2.token, tool_name="crm_get"))
        assert not r1.granted
        assert not r2.granted
        assert r1.deny_reason == "user_revoked"
        assert r2.deny_reason == "user_revoked"

    def test_cannot_issue_token_for_revoked_user(self, gate, user):
        gate.revoke_user(user.id)
        with pytest.raises(ValueError, match="revoked"):
            gate.issue_token(user.id)
