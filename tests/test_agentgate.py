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


# ── Team RBAC tests ───────────────────────────────────────────────────────────

class TestRoles:
    def test_create_role(self, db):
        r = db.create_role(name="analyst", allowed_tools=["read_*"], level=50)
        assert r.id
        assert r.name == "analyst"
        assert r.allowed_tools == ["read_*"]
        assert r.level == 50

    def test_role_roundtrip(self, db):
        r = db.create_role(
            name="senior",
            allowed_tools=["crm_*", "read_*"],
            denied_tools=["crm_delete_*"],
            rate_limit_per_hour=100,
            max_tokens_per_day=500000,
            level=75,
        )
        fetched = db.get_role(r.id)
        assert fetched.name == "senior"
        assert fetched.denied_tools == ["crm_delete_*"]
        assert fetched.level == 75

    def test_get_role_by_name(self, db):
        db.create_role(name="intern", allowed_tools=["search_*"], level=10)
        r = db.get_role_by_name("intern")
        assert r is not None
        assert r.name == "intern"

    def test_list_roles_ordered_by_level_desc(self, db):
        db.create_role(name="junior", level=10)
        db.create_role(name="senior", level=75)
        db.create_role(name="admin", level=100)
        roles = db.list_roles()
        names = [r.name for r in roles]
        assert names.index("admin") < names.index("senior") < names.index("junior")

    def test_role_not_found(self, db):
        assert db.get_role("nonexistent") is None


class TestTeams:
    @pytest.fixture
    def role_analyst(self, db):
        return db.create_role(name="analyst", allowed_tools=["read_*", "search_*"], level=50)

    @pytest.fixture
    def role_admin(self, db):
        return db.create_role(name="admin", allowed_tools=["*"], level=100)

    @pytest.fixture
    def team_data(self, db, role_analyst):
        return db.create_team(name="data-team", role_id=role_analyst.id, description="Data analysts")

    def test_create_team(self, db, role_analyst):
        t = db.create_team(name="alpha", role_id=role_analyst.id)
        assert t.id
        assert t.name == "alpha"
        assert t.role_id == role_analyst.id

    def test_get_team_by_name(self, db, role_analyst):
        db.create_team(name="beta-team", role_id=role_analyst.id)
        t = db.get_team_by_name("beta-team")
        assert t is not None
        assert t.name == "beta-team"

    def test_add_and_remove_member(self, db, profile, role_analyst):
        team = db.create_team(name="eng", role_id=role_analyst.id)
        u = db.create_user(name="Charlie", email="charlie@x.com", profile_id=profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)

        members = db.get_team_members(team.id)
        assert any(m.id == u.id for m in members)

        ok = db.remove_team_member(team_id=team.id, user_id=u.id)
        assert ok
        assert db.get_team_member_count(team.id) == 0

    def test_add_member_idempotent(self, db, profile, role_analyst):
        team = db.create_team(name="ops", role_id=role_analyst.id)
        u = db.create_user(name="Dana", email="dana@x.com", profile_id=profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)
        db.add_team_member(team_id=team.id, user_id=u.id)  # second add — should not raise
        assert db.get_team_member_count(team.id) == 1

    def test_get_user_teams(self, db, profile, role_analyst, role_admin):
        t1 = db.create_team(name="engineering", role_id=role_admin.id)
        t2 = db.create_team(name="data", role_id=role_analyst.id)
        u = db.create_user(name="Eve", email="eve@x.com", profile_id=profile.id)
        db.add_team_member(team_id=t1.id, user_id=u.id)
        db.add_team_member(team_id=t2.id, user_id=u.id)

        user_teams = db.get_user_teams(u.id)
        team_names = [t.name for t in user_teams]
        assert "engineering" in team_names
        assert "data" in team_names

    def test_get_user_roles(self, db, profile, role_analyst, role_admin):
        t1 = db.create_team(name="eng2", role_id=role_admin.id)
        t2 = db.create_team(name="dat2", role_id=role_analyst.id)
        u = db.create_user(name="Frank", email="frank@x.com", profile_id=profile.id)
        db.add_team_member(t1.id, u.id)
        db.add_team_member(t2.id, u.id)

        user_roles = db.get_user_roles(u.id)
        role_names = [r.name for r in user_roles]
        assert "admin" in role_names
        assert "analyst" in role_names
        # Ordered by level DESC — admin (100) first
        assert user_roles[0].name == "admin"


class TestTeamRBAC:
    """
    Test the effective permissions resolution — the core of team RBAC.
    Union strategy: allowed = union of profile + team roles; denied = union of all denies.
    """

    @pytest.fixture
    def basic_profile(self, db):
        return db.create_profile(
            name="base",
            allowed_tools=["crm_*"],
            denied_tools=[],
        )

    @pytest.fixture
    def role_analytics(self, db):
        return db.create_role(
            name="analytics",
            allowed_tools=["analytics_*", "reports_*"],
            denied_tools=[],
            level=50,
        )

    @pytest.fixture
    def role_restrictive(self, db):
        return db.create_role(
            name="restricted",
            allowed_tools=["*"],
            denied_tools=["payments_*"],  # team denies payment tools
            level=10,
        )

    def test_effective_permissions_no_teams(self, db, gate, basic_profile):
        """User with no team memberships — perms come entirely from their profile."""
        u = db.create_user(name="Solo", email="solo@x.com", profile_id=basic_profile.id)
        perms = gate.resolve_effective_permissions(u)
        assert perms.allowed_tools == ["crm_*"]
        assert perms.denied_tools == []
        assert perms.source_team_ids == []

    def test_team_role_expands_allowed_tools(self, db, gate, basic_profile, role_analytics):
        """User in a team gets union of profile + team role allowed tools."""
        team = db.create_team(name="analytics-team", role_id=role_analytics.id)
        u = db.create_user(name="Grace", email="grace@x.com", profile_id=basic_profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)

        perms = gate.resolve_effective_permissions(u)
        # Should have crm_* from profile AND analytics_*, reports_* from team role
        assert "crm_*" in perms.allowed_tools
        assert "analytics_*" in perms.allowed_tools
        assert "reports_*" in perms.allowed_tools

    def test_team_deny_propagates(self, db, gate, basic_profile, role_restrictive):
        """A deny in ANY team role applies globally — any deny wins."""
        team = db.create_team(name="restricted-team", role_id=role_restrictive.id)
        u = db.create_user(name="Hank", email="hank@x.com", profile_id=basic_profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)

        perms = gate.resolve_effective_permissions(u)
        assert "payments_*" in perms.denied_tools

    def test_enforce_with_team_expanded_tools(self, db, gate, basic_profile, role_analytics):
        """User can call analytics_get_report even though their profile doesn't include it
        (the team role grants it)."""
        team = db.create_team(name="analytics2", role_id=role_analytics.id)
        u = db.create_user(name="Iris", email="iris@x.com", profile_id=basic_profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)
        token = gate.issue_token(u.id)

        # Profile alone wouldn't allow this
        result = gate.enforce(EnforceRequest(token=token.token, tool_name="analytics_get_report"))
        assert result.granted, f"Expected granted, got deny: {result.deny_reason}"

        # Profile tools still work too
        result2 = gate.enforce(EnforceRequest(token=token.token, tool_name="crm_get_contact"))
        assert result2.granted

    def test_enforce_team_deny_blocks_tool(self, db, gate, basic_profile, role_restrictive):
        """Team deny blocks payment tools even though the team role's allowed_tools includes *."""
        team = db.create_team(name="no-pay-team", role_id=role_restrictive.id)
        u = db.create_user(name="Jack", email="jack@x.com", profile_id=basic_profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)
        token = gate.issue_token(u.id)

        result = gate.enforce(EnforceRequest(token=token.token, tool_name="payments_send"))
        assert not result.granted
        assert result.deny_reason == "tool_explicitly_denied"

    def test_most_restrictive_rate_limit(self, db, gate):
        """When user profile has rate_limit=10 and team role has rate_limit=5,
        effective limit is 5 (more restrictive)."""
        profile = db.create_profile(
            name="rate10", allowed_tools=["*"], rate_limit_per_hour=10
        )
        role = db.create_role(
            name="rate5-role", allowed_tools=["*"], rate_limit_per_hour=5
        )
        team = db.create_team(name="capped-team", role_id=role.id)
        u = db.create_user(name="Kate", email="kate@x.com", profile_id=profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)
        token = gate.issue_token(u.id)

        perms = gate.resolve_effective_permissions(u)
        assert perms.rate_limit_per_hour == 5  # most restrictive

        # 5 calls succeed, 6th is denied
        for _ in range(5):
            r = gate.enforce(EnforceRequest(token=token.token, tool_name="anything"))
            assert r.granted

        r6 = gate.enforce(EnforceRequest(token=token.token, tool_name="anything"))
        assert not r6.granted
        assert r6.deny_reason == "rate_limit_exceeded"

    def test_multiple_team_memberships_union(self, db, gate):
        """User in two teams gets the union of all team role allowed_tools."""
        profile = db.create_profile(name="base2", allowed_tools=["base_*"])
        role1 = db.create_role(name="r1", allowed_tools=["alpha_*"])
        role2 = db.create_role(name="r2", allowed_tools=["beta_*"])
        t1 = db.create_team(name="team-alpha", role_id=role1.id)
        t2 = db.create_team(name="team-beta", role_id=role2.id)
        u = db.create_user(name="Leo", email="leo@x.com", profile_id=profile.id)
        db.add_team_member(t1.id, u.id)
        db.add_team_member(t2.id, u.id)

        perms = gate.resolve_effective_permissions(u)
        assert "base_*" in perms.allowed_tools
        assert "alpha_*" in perms.allowed_tools
        assert "beta_*" in perms.allowed_tools
        assert len(perms.source_team_ids) == 2

    def test_no_rate_limit_if_no_sources_set(self, db, gate):
        """If neither profile nor team roles set rate limits, effective limit is 0 (unlimited)."""
        profile = db.create_profile(name="free", allowed_tools=["*"], rate_limit_per_hour=0)
        role = db.create_role(name="free-role", allowed_tools=["*"], rate_limit_per_hour=0)
        team = db.create_team(name="free-team", role_id=role.id)
        u = db.create_user(name="Max", email="max@x.com", profile_id=profile.id)
        db.add_team_member(team.id, u.id)

        perms = gate.resolve_effective_permissions(u)
        assert perms.rate_limit_per_hour == 0  # 0 means unlimited

    def test_team_removal_removes_permissions(self, db, gate, basic_profile, role_analytics):
        """After removing user from team, they lose the team's extra permissions."""
        team = db.create_team(name="temp-team", role_id=role_analytics.id)
        u = db.create_user(name="Nina", email="nina@x.com", profile_id=basic_profile.id)
        db.add_team_member(team_id=team.id, user_id=u.id)

        # Can access analytics tools
        perms_before = gate.resolve_effective_permissions(u)
        assert "analytics_*" in perms_before.allowed_tools

        # Remove from team
        db.remove_team_member(team_id=team.id, user_id=u.id)

        # Analytics tools gone
        perms_after = gate.resolve_effective_permissions(u)
        assert "analytics_*" not in perms_after.allowed_tools
        assert "crm_*" in perms_after.allowed_tools  # profile tools still there
