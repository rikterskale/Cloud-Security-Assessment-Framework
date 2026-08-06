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
from .schema_validation import validate_instance

ACTIVE_PROFILES = {"Validation", "AdversarySimulation"}


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
    authorized_source_addresses: list[str] = field(default_factory=list)
    window_start_utc: str | None = None
    window_end_utc: str | None = None
    operator_contacts: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    prohibited_actions: list[str] = field(default_factory=list)
    active_validation_approved: bool = False
    secret_discovery_approved: bool = False
    attestations: dict = field(default_factory=dict)
    signature: str | None = None
    configured: bool = False
    _signed_content: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str | Path | None) -> "Engagement":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        validate_instance(data, "engagement.schema.json", path)
        signature = data.get("signature")
        signed_content = {k: v for k, v in data.items() if k != "signature"}
        return cls(
            engagement_id=data.get("engagementId", "UNSCOPED"),
            customer=data.get("customer", ""),
            cloud=data.get("cloud", "AWS"),
            authorized_accounts=data.get("authorizedAccounts", []),
            authorized_regions=data.get("authorizedRegions", []),
            authorized_source_addresses=data.get("authorizedSourceAddresses", []),
            window_start_utc=data.get("windowStartUtc"),
            window_end_utc=data.get("windowEndUtc"),
            operator_contacts=data.get("operatorContacts", []),
            stop_conditions=data.get("stopConditions", []),
            prohibited_actions=data.get("prohibitedActions", []),
            active_validation_approved=bool(data.get("activeValidationApproved", False)),
            secret_discovery_approved=bool(data.get("secretDiscoveryApproved", False)),
            attestations=data.get("attestations", {}),
            signature=signature,
            configured=True,
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

    def authorize_scope(
        self,
        cloud: str,
        regions: list[str],
        account_id: str | None = None,
        *,
        active: bool = False,
    ) -> tuple[bool, str]:
        """Authorize the normalized provider scope before a run starts."""
        if not self.configured:
            if active:
                return False, "Active profiles require an explicit engagement file."
            return True, "No engagement supplied; read-only assessment is unscoped."
        if self.cloud != cloud:
            return False, f"Engagement cloud {self.cloud!r} does not authorize {cloud!r}."
        if active and not self.authorized_accounts:
            return False, "Active profiles require at least one authorized account or context."
        if account_id is not None and not self.account_authorized(account_id):
            return False, f"Account or context {account_id!r} is not in authorizedAccounts."
        if cloud == "AWS":
            requested_regions = set(regions)
            authorized_regions = set(self.authorized_regions)
            if active and not authorized_regions:
                return False, "Active AWS profiles require at least one authorized region."
            unauthorized = sorted(requested_regions - authorized_regions) if authorized_regions else []
            if unauthorized:
                return False, f"Requested AWS regions are outside authorizedRegions: {unauthorized}."
        if active and self.authorized_source_addresses:
            return (
                False,
                "authorizedSourceAddresses cannot be enforced by this local CLI; "
                "enforce source restrictions externally or remove that field.",
            )
        return True, "Cloud, account/context, and applicable region scope are authorized."

    def authorize_profile(self, profile: str, signing_key: bytes | None = None) -> tuple[bool, str]:
        """Return (allowed, reason) for running a profile under this engagement.

        Inventory and Assessment are read-only and always allowed. Validation
        and AdversarySimulation require explicit approval and an active window.

        Active profiles require ``signing_key`` and the engagement file's
        content must verify against it (see ``engagement_signing``), so a
        silent edit to ``activeValidationApproved`` after signing is caught
        rather than trusted.
        """
        if profile not in ACTIVE_PROFILES:
            return True, "Read-only profile; no active-validation authorization required."
        if signing_key is None:
            return False, "Active profiles require --engagement-key-file and a signed engagement."
        if not self.active_validation_approved:
            return False, "Engagement does not approve active validation (activeValidationApproved=false)."
        if not self.window_start_utc or not self.window_end_utc:
            return False, "Active profiles require both windowStartUtc and windowEndUtc."
        if not self.in_window():
            return False, "Current time is outside the engagement's authorized window."
        if not self.verify_signature(signing_key):
            return False, "Engagement signature verification failed; the file may have been altered after signing."
        return True, "Active validation approved and within the authorized window."

    def authorize_secret_discovery(self, signing_key: bytes | None = None) -> tuple[bool, str]:
        """Authorize the metadata-only Azure secret-discovery workflow.

        This is intentionally a separate affirmative approval from general
        validation. The workflow inventories locations that can contain
        secrets, but never requests or persists secret values.
        """
        allowed, reason = self.authorize_profile("Validation", signing_key)
        if not allowed:
            return False, reason
        if not self.secret_discovery_approved:
            return False, "Engagement does not approve secret discovery (secretDiscoveryApproved=false)."
        return True, "Signed engagement explicitly approves metadata-only secret discovery."
