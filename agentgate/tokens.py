"""
Token issuance and verification for agentgate session tokens.

Uses HMAC-SHA256 to sign tokens — no external JWT library required.
Token format: base64url(payload_json).base64url(hmac_signature)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Optional, Dict, Any

from .models import SessionToken

DEFAULT_SECRET = os.environ.get("AGENTGATE_SECRET", "change-me-in-production")
DEFAULT_TTL_SECONDS = int(os.environ.get("AGENTGATE_TOKEN_TTL", str(8 * 3600)))  # 8 hours


class TokenManager:
    def __init__(self, secret: str = DEFAULT_SECRET, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        if secret == "change-me-in-production":
            import warnings
            warnings.warn(
                "Using default AGENTGATE_SECRET. Set the AGENTGATE_SECRET environment variable in production.",
                stacklevel=2,
            )
        self.secret = secret.encode()
        self.ttl_seconds = ttl_seconds

    def issue(
        self,
        user_id: str,
        profile_id: str,
        conversation_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SessionToken:
        token_id = str(uuid.uuid4())
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        payload = {
            "tid": token_id,
            "uid": user_id,
            "pid": profile_id,
            "cid": conversation_id or str(uuid.uuid4()),
            "iat": now,
            "exp": now + ttl,
        }
        token_str = self._sign(payload)
        return SessionToken(
            token_id=token_id,
            token=token_str,
            user_id=user_id,
            profile_id=profile_id,
            conversation_id=payload["cid"],
            issued_at=now,
            expires_at=now + ttl,
            metadata=metadata or {},
        )

    def verify(self, token_str: str) -> Optional[Dict[str, Any]]:
        """
        Verify token signature and expiry.
        Returns the payload dict on success, None on failure.
        """
        try:
            parts = token_str.split(".")
            if len(parts) != 2:
                return None
            payload_b64, sig_b64 = parts
            expected_sig = self._hmac(payload_b64)
            if not hmac.compare_digest(expected_sig, sig_b64):
                return None
            payload = json.loads(self._b64decode(payload_b64))
            if time.time() > payload["exp"]:
                return None
            return payload
        except Exception:
            return None

    def _sign(self, payload: Dict[str, Any]) -> str:
        payload_b64 = self._b64encode(json.dumps(payload, separators=(",", ":")))
        sig_b64 = self._hmac(payload_b64)
        return f"{payload_b64}.{sig_b64}"

    def _hmac(self, data: str) -> str:
        mac = hmac.new(self.secret, data.encode(), hashlib.sha256)
        return self._b64encode(mac.digest())

    def _b64encode(self, data) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _b64decode(self, s: str) -> bytes:
        # Add padding
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        return base64.urlsafe_b64decode(s)
