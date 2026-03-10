"""
Core Pydantic models for agentgate.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import time


@dataclass
class Profile:
    """
    An agent permission profile — a named set of tool access rules.

    Tool matching uses glob patterns:
      allowed_tools: ["*"]          — all tools allowed
      allowed_tools: ["crm_*"]      — only CRM tools
      denied_tools: ["crm_delete_*"] — block destructive CRM ops
      Deny takes precedence over allow.

    rate_limit_per_hour: max tool calls per hour per user (0 = unlimited)
    max_tokens_per_day: max LLM tokens per day per user (0 = unlimited)
    """
    id: str
    name: str
    description: str = ""
    allowed_tools: List[str] = field(default_factory=lambda: ["*"])
    denied_tools: List[str] = field(default_factory=list)
    rate_limit_per_hour: int = 0
    max_tokens_per_day: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class User:
    """
    An agent user — a person whose AI session is access-controlled.

    external_id can map to a Django auth.User pk, Slack user ID, etc.
    profile_id links to the Profile that governs their agent.
    """
    id: str
    name: str
    email: str
    profile_id: str
    external_id: str = ""
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    revoked_at: Optional[float] = None


@dataclass
class SessionToken:
    """
    A short-lived token issued per conversation, bound to a user + profile.

    Think of it like an OAuth access token for an AI session:
      - Carry it in X-AgentGate-Token header on every tool call
      - Expires (default 8h), revocable instantly
      - Stores conversation_id for grouping audit events
    """
    token_id: str
    token: str  # HMAC-signed opaque string
    user_id: str
    profile_id: str
    conversation_id: str
    issued_at: float
    expires_at: float
    revoked: bool = False
    revoked_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return not self.revoked and time.time() < self.expires_at


@dataclass
class AuditEvent:
    """
    One audit log entry — a tool call enforcement decision.
    """
    id: str
    event_type: str          # "tool_call", "token_issued", "token_revoked", "user_revoked"
    user_id: Optional[str]
    token_id: Optional[str]
    tool_name: Optional[str]
    granted: Optional[bool]
    deny_reason: Optional[str]
    conversation_id: Optional[str]
    profile_id: Optional[str]
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnforceRequest:
    """
    An enforcement check request: 'can this token call this tool?'
    """
    token: str
    tool_name: str
    token_count: int = 0        # LLM tokens consumed so far this call (optional)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnforceResult:
    """
    The enforcement decision returned to the caller.
    """
    granted: bool
    deny_reason: Optional[str] = None
    user_id: Optional[str] = None
    profile_id: Optional[str] = None
    conversation_id: Optional[str] = None
    rate_limit_remaining: Optional[int] = None
    daily_tokens_remaining: Optional[int] = None
