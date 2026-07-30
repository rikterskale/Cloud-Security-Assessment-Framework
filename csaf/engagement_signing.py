"""HMAC-based signing/verification for engagement authorization files.

The engagement file alone grants active-validation authorization: a JSON
``activeValidationApproved: true`` flag anyone with filesystem access could
edit unnoticed. Signing binds the content an approver actually reviewed to a
shared secret, so a silent edit after signing is detectable and verification
fails closed.

This is HMAC (shared-secret) signing, not asymmetric/PKI signing - it fits
CSAF's scope (an approver and an operator sharing one key out of band for a
single engagement), not third-party public verification. Use a real PKI-based
scheme if engagements need to be verified by parties without the shared key.
"""

from __future__ import annotations

import hashlib
import hmac
import json


def canonical_bytes(data: dict) -> bytes:
    """Deterministic serialization used for both signing and verification."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign(data: dict, key: bytes) -> str:
    """Return a hex HMAC-SHA256 digest of ``data`` under ``key``."""
    if not key:
        raise ValueError("Engagement signing key must not be empty.")
    return hmac.new(key, canonical_bytes(data), hashlib.sha256).hexdigest()


def verify(data: dict, signature: str | None, key: bytes) -> bool:
    """Constant-time verification; a missing/empty signature never verifies."""
    if not signature or not key:
        return False
    expected = sign(data, key)
    return hmac.compare_digest(expected, signature)
