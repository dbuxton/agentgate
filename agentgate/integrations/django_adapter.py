"""
Django integration for agentgate.

Provides:
  - AgentGateMiddleware: injects an AgentGate instance into request.agentgate
  - AgentProfile: Django model that maps auth.User → agentgate profile name
  - get_or_create_token(): helper that issues/caches a session token for a Django request
  - enforce_tool(): decorator for Django views that checks tool access

Usage in settings.py:
  MIDDLEWARE = [
      ...
      'agentgate.integrations.django_adapter.AgentGateMiddleware',
  ]
  AGENTGATE_DB = '/var/lib/agentgate/agentgate.db'
  AGENTGATE_SECRET = 'your-secret'

Usage in views.py:
  from agentgate.integrations.django_adapter import enforce_tool

  @enforce_tool('crm_create_contact')
  def create_contact(request, ...):
      ...  # only reachable if user's agent profile allows crm_create_contact
"""

from __future__ import annotations

import os
from typing import Optional

try:
    from django.conf import settings
    from django.http import JsonResponse
    from django.db import models
    from django.contrib.auth import get_user_model
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False


def _get_gate():
    """Lazy singleton — avoids import-time DB connection."""
    from agentgate.db import AgentGateDB
    from agentgate.gate import AgentGate
    from agentgate.tokens import TokenManager

    db_path = getattr(settings, "AGENTGATE_DB", os.environ.get("AGENTGATE_DB", "agentgate.db"))
    secret = getattr(settings, "AGENTGATE_SECRET", os.environ.get("AGENTGATE_SECRET", "change-me"))
    db = AgentGateDB(db_path)
    return AgentGate(db=db, token_manager=TokenManager(secret=secret))


_gate_instance = None


def get_gate():
    global _gate_instance
    if _gate_instance is None:
        _gate_instance = _get_gate()
    return _gate_instance


if DJANGO_AVAILABLE:
    class AgentProfile(models.Model):
        """
        Maps a Django auth.User to an agentgate profile name.

        The agentgate profile name is resolved at token-issuance time,
        so you can change a user's profile without re-issuing tokens
        (new tokens pick up the new profile; old ones keep the old one).
        """
        user = models.OneToOneField(
            get_user_model(),
            on_delete=models.CASCADE,
            related_name="agent_profile",
        )
        agentgate_profile_name = models.CharField(
            max_length=100,
            default="default",
            help_text="agentgate profile name — controls which tools this user's agent can call",
        )
        agentgate_user_id = models.CharField(
            max_length=36,
            blank=True,
            help_text="Cached agentgate user UUID (set on first token issuance)",
        )
        created_at = models.DateTimeField(auto_now_add=True)
        updated_at = models.DateTimeField(auto_now=True)

        class Meta:
            app_label = "agentgate"
            verbose_name = "Agent Profile"
            verbose_name_plural = "Agent Profiles"

        def __str__(self):
            return f"{self.user} → {self.agentgate_profile_name}"

        def get_or_create_agentgate_user(self):
            """
            Sync this Django user to agentgate, creating them if needed.
            Returns the agentgate user object.
            """
            gate = get_gate()
            if self.agentgate_user_id:
                user = gate.db.get_user(self.agentgate_user_id)
                if user:
                    return user

            # Resolve the profile
            profile = gate.db.get_profile_by_name(self.agentgate_profile_name)
            if not profile:
                raise ValueError(
                    f"agentgate profile {self.agentgate_profile_name!r} not found. "
                    "Create it with: agentgate profile create --name ..."
                )

            # Check if already exists by external_id
            django_user = self.user
            ext_id = f"django:{django_user.pk}"
            existing = gate.db.get_user_by_external_id(ext_id)
            if existing:
                self.agentgate_user_id = existing.id
                self.save(update_fields=["agentgate_user_id"])
                return existing

            # Create new agentgate user
            ag_user = gate.db.create_user(
                name=django_user.get_full_name() or django_user.username,
                email=django_user.email or f"{django_user.username}@django.local",
                profile_id=profile.id,
                external_id=ext_id,
            )
            self.agentgate_user_id = ag_user.id
            self.save(update_fields=["agentgate_user_id"])
            return ag_user

    class AgentGateMiddleware:
        """
        Attaches gate and optional session token to every request.

        Reads X-AgentGate-Token header if present and attaches enforcement
        context to request.agentgate_token.
        """
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            request.agentgate = get_gate()
            token_str = request.headers.get("X-AgentGate-Token", "")
            request.agentgate_token = token_str or None
            return self.get_response(request)

    def get_or_create_token(request, conversation_id: Optional[str] = None):
        """
        Issue (or reuse) a session token for the authenticated Django user.

        Stores the token in the Django session for reuse across requests
        within the same conversation. The token is re-issued if expired.
        """
        if not request.user.is_authenticated:
            raise ValueError("User is not authenticated")

        gate = get_gate()
        session_key = f"agentgate_token_{conversation_id or 'default'}"

        # Check existing session token
        existing_token_str = request.session.get(session_key)
        if existing_token_str:
            token = gate.db.get_token(existing_token_str)
            if token and token.is_valid:
                return token

        # Issue new token
        try:
            ap = request.user.agent_profile
        except Exception:
            raise ValueError(
                f"User {request.user} has no AgentProfile. "
                "Create one via Django admin or AgentProfile.objects.create(user=..., profile_name=...)"
            )

        ag_user = ap.get_or_create_agentgate_user()
        token = gate.issue_token(
            user_id=ag_user.id,
            conversation_id=conversation_id,
        )
        request.session[session_key] = token.token
        return token

    def enforce_tool(tool_name: str):
        """
        View decorator: deny access if the requesting user's agent profile
        doesn't allow this tool.

        @enforce_tool('crm_delete_contact')
        def delete_contact(request, contact_id):
            ...
        """
        import functools
        def decorator(view_fn):
            @functools.wraps(view_fn)
            def wrapper(request, *args, **kwargs):
                token_str = getattr(request, "agentgate_token", None)
                if not token_str:
                    return JsonResponse(
                        {"error": "No agentgate token provided", "hint": "Include X-AgentGate-Token header"},
                        status=403,
                    )
                from agentgate.models import EnforceRequest
                gate = get_gate()
                result = gate.enforce(EnforceRequest(token=token_str, tool_name=tool_name))
                if not result.granted:
                    return JsonResponse(
                        {"error": "Access denied", "reason": result.deny_reason},
                        status=403,
                    )
                return view_fn(request, *args, **kwargs)
            return wrapper
        return decorator

else:
    class AgentGateMiddleware:  # type: ignore
        def __init__(self, *a, **kw):
            raise ImportError("Django is required for AgentGateMiddleware")

    class AgentProfile:  # type: ignore
        pass
