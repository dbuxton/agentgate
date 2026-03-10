"""
AgentGate — the enforcement engine.

This is the heart of agentgate: given a token and a tool name,
answer "allowed?" and record the decision in the audit log.

Enforcement order:
  1. Token signature valid?
  2. Token not expired?
  3. Token not revoked?
  4. User still active (not offboarded)?
  5. Tool name matches allowed_tools globs?
  6. Tool name not in denied_tools globs?
  7. Hourly rate limit not exceeded?
  8. Daily token quota not exceeded?
  → GRANT, increment usage counters, log.
"""

from __future__ import annotations

import fnmatch
from typing import Optional, Dict, Any

from .db import AgentGateDB
from .models import EnforceRequest, EnforceResult, User, Profile, SessionToken
from .tokens import TokenManager


class AgentGate:
    def __init__(self, db: AgentGateDB, token_manager: TokenManager):
        self.db = db
        self.tm = token_manager

    # ── Token lifecycle ───────────────────────────────────────────────────────

    def issue_token(
        self,
        user_id: str,
        conversation_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SessionToken:
        user = self.db.get_user(user_id)
        if not user:
            raise ValueError(f"User {user_id!r} not found")
        if not user.active:
            raise ValueError(f"User {user_id!r} is revoked — cannot issue token")

        token = self.tm.issue(
            user_id=user_id,
            profile_id=user.profile_id,
            conversation_id=conversation_id,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        self.db.store_token(token)
        self.db.log_event(
            event_type="token_issued",
            user_id=user_id,
            token_id=token.token_id,
            conversation_id=token.conversation_id,
            profile_id=token.profile_id,
        )
        return token

    def revoke_token(self, token_id: str) -> bool:
        ok = self.db.revoke_token(token_id)
        if ok:
            self.db.log_event(event_type="token_revoked", token_id=token_id)
        return ok

    def revoke_user(self, user_id: str) -> Dict[str, Any]:
        """
        Offboard a user: deactivate the user record and revoke all active tokens.
        Returns a summary of what was revoked.
        """
        tokens_revoked = self.db.revoke_all_user_tokens(user_id)
        user_revoked = self.db.revoke_user(user_id)
        self.db.log_event(
            event_type="user_revoked",
            user_id=user_id,
            metadata={"tokens_revoked": tokens_revoked},
        )
        return {"user_revoked": user_revoked, "tokens_revoked": tokens_revoked}

    # ── Enforcement ───────────────────────────────────────────────────────────

    def enforce(self, request: EnforceRequest) -> EnforceResult:
        """
        Check whether a tool call is allowed.
        This is the hot path — called on every agent tool invocation.
        """
        # 1. Verify token signature + expiry
        payload = self.tm.verify(request.token)
        if not payload:
            return self._deny("invalid_token", request)

        # 2. Load token record (needed to look up user_id)
        token = self.db.get_token(request.token)
        if not token:
            return self._deny("token_not_found", request)

        # 3. Check user is still active BEFORE token revocation check.
        #    User offboarding is the root cause — report that even if token
        #    was also revoked as part of the offboarding flow.
        user = self.db.get_user(token.user_id)
        if not user:
            return self._deny("user_not_found", request, token)
        if not user.active:
            return self._deny("user_revoked", request, token)

        # 4. Check token revocation and expiry
        if token.revoked:
            return self._deny("token_revoked", request, token)
        if not token.is_valid:
            return self._deny("token_expired", request, token)

        # 4. Load profile
        profile = self.db.get_profile(token.profile_id)
        if not profile:
            return self._deny("profile_not_found", request, token)

        # 5. Tool allow/deny matching
        if not self._tool_allowed(request.tool_name, profile):
            return self._deny("tool_not_allowed", request, token, profile, user)
        if self._tool_denied(request.tool_name, profile):
            return self._deny("tool_explicitly_denied", request, token, profile, user)

        # 6. Rate limiting (per hour)
        if profile.rate_limit_per_hour > 0:
            hourly_calls = self.db.get_hourly_tool_calls(user.id)
            if hourly_calls >= profile.rate_limit_per_hour:
                return self._deny("rate_limit_exceeded", request, token, profile, user)

        # 7. Daily token quota
        if profile.max_tokens_per_day > 0 and request.token_count > 0:
            daily_tokens = self.db.get_daily_tokens(user.id)
            if daily_tokens + request.token_count > profile.max_tokens_per_day:
                return self._deny("daily_token_quota_exceeded", request, token, profile, user)

        # ✅ GRANT
        self.db.increment_usage(user.id, request.token_count)
        self.db.log_event(
            event_type="tool_call",
            user_id=user.id,
            token_id=token.token_id,
            tool_name=request.tool_name,
            granted=True,
            conversation_id=token.conversation_id,
            profile_id=profile.id,
        )

        # Compute remaining headroom
        rate_remaining: Optional[int] = None
        tokens_remaining: Optional[int] = None
        if profile.rate_limit_per_hour > 0:
            rate_remaining = max(0, profile.rate_limit_per_hour - self.db.get_hourly_tool_calls(user.id))
        if profile.max_tokens_per_day > 0:
            tokens_remaining = max(0, profile.max_tokens_per_day - self.db.get_daily_tokens(user.id))

        return EnforceResult(
            granted=True,
            user_id=user.id,
            profile_id=profile.id,
            conversation_id=token.conversation_id,
            rate_limit_remaining=rate_remaining,
            daily_tokens_remaining=tokens_remaining,
        )

    def _deny(
        self,
        reason: str,
        request: EnforceRequest,
        token: Optional[SessionToken] = None,
        profile: Optional[Profile] = None,
        user: Optional[User] = None,
    ) -> EnforceResult:
        self.db.log_event(
            event_type="tool_call",
            user_id=user.id if user else None,
            token_id=token.token_id if token else None,
            tool_name=request.tool_name,
            granted=False,
            deny_reason=reason,
            conversation_id=token.conversation_id if token else None,
            profile_id=profile.id if profile else None,
        )
        return EnforceResult(
            granted=False,
            deny_reason=reason,
            user_id=user.id if user else None,
            profile_id=profile.id if profile else None,
            conversation_id=token.conversation_id if token else None,
        )

    def _tool_allowed(self, tool_name: str, profile: Profile) -> bool:
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in profile.allowed_tools)

    def _tool_denied(self, tool_name: str, profile: Profile) -> bool:
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in profile.denied_tools)
