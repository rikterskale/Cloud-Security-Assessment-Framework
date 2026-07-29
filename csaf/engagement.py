"""Engagement authorization: profiles, scope, window, and stop conditions.

The engagement configuration binds an assessment to an authorized scope. The
``Validation`` profile (which enables non-destructive active validation such as
``iam:SimulatePrincipalPolicy``) requires an engagement that explicitly approves
active validation and that is inside its authorized time window.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from pathlib import Path

from .engagement_signing import verify as verify_signature


def _parse_utc(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Engagement:
    engagement_id: str = "UNSCOPED"
    customer: str = ""
    cloud: str = "AWS"
    authorized_accounts: list[str] = field(default_factory=list)
    authorized_regions: list[str] = field(default_factory=list)
    window_start_utc: str | None = None
    window_end_utc: str | None = None
    operator_contacts: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(default_factory=list)
    active_validation_approved: bool = False
    attestations: dict = field(default_factory=dict)
    signature: str | None = None
    _signed_content: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str | Path | None) -> "Engagement":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        signature = data.get("signature")
        signed_content = {k: v for k, v in data.items() if k != "signature"}
        return cls(
            engagement_id=data.get("engagementId", "UNSCOPED"),
            customer=data.get("customer", ""),
            cloud=data.get("cloud", "AWS"),
            authorized_accounts=data.get("authorizedAccounts", []),
            authorized_regions=data.get("authorizedRegions", []),
            window_start_utc=data.get("windowStartUtc"),
            window_end_utc=data.get("windowEndUtc"),
            operator_contacts=data.get("operatorContacts", []),
            stop_conditions=data.get("stopConditions", []),
            prohibited_actions=data.get("prohibitedActions", []),
            active_validation_approved=bool(data.get("activeValidationApproved", False)),
            attestations=data.get("attestations", {}),
            signature=signature,
            _signed_content=signed_content,
        )

    def verify_signature(self, key: bytes) -> bool:
        """Verify the loaded file's content against ``key``.

        Returns ``False`` for an unsigned file (an unscoped/default
        ``Engagement()`` has no ``_signed_content`` either, and also fails).
        """
        return bool(self._signed_content) and verify_signature(self._signed_content, self.signature, key)

    def in_window(self, now: datetime.datetime | None = None) -> bool:
        now = now or datetime.datetime.now(datetime.timezone.utc)
        start = _parse_utc(self.window_start_utc)
        end = _parse_utc(self.window_end_utc)
        if start and now < start:
            return False
        if end and now > end:
            return False
        return True

    def account_authorized(self, account_id: str) -> bool:
        return not self.authorized_accounts or account_id in self.authorized_accounts

    def authorize_profile(self, profile: str, signing_key: bytes | None = None) -> tuple[bool, str]:
        """Return (allowed, reason) for running a profile under this engagement.

        Inventory and Assessment are read-only and always allowed. Validation
        and AdversarySimulation require explicit approval and an active window.

        ``signing_key`` is opt-in: when supplied, the engagement file's content
        must verify against it (see ``engagement_signing``) or authorization is
        refused, so a silent edit to ``activeValidationApproved`` after
        signing is caught rather than trusted.
        """
        if profile in ("Inventory", "Assessment"):
            return True, "Read-only profile; no active-validation authorization required."
        if not self.active_validation_approved:
            return False, "Engagement does not approve active validation (activeValidationApproved=false)."
        if not self.in_window():
            return False, "Current time is outside the engagement's authorized window."
        if signing_key is not None and not self.verify_signature(signing_key):
            return False, "Engagement signature verification failed; the file may have been altered after signing."
        return True, "Active validation approved and within the authorized window."
