"""
agentgate — Identity-aware access control for AI agent tool permissions.

When you deploy AI agents to many users, each user should have a profile
defining which tools their agent can access, rate limits, and quotas.
agentgate is the enforcement layer: issue session tokens per user, check
every tool call against that user's profile, revoke access instantly.
"""

__version__ = "0.1.0"

from .db import AgentGateDB
from .models import User, Profile, SessionToken, AuditEvent, EnforceRequest, EnforceResult
from .tokens import TokenManager
from .gate import AgentGate

__all__ = [
    "AgentGateDB",
    "User",
    "Profile",
    "SessionToken",
    "AuditEvent",
    "EnforceRequest",
    "EnforceResult",
    "TokenManager",
    "AgentGate",
]
