"""Cloud KMS key-management controls (project scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

KMS_V1 = "https://cloudkms.googleapis.com/v1"


class KmsModule(AssessmentModule):
    name = "kms"

    def _key_rings(self, ctx: CheckContext) -> list[dict]:
        session = ctx.session
        try:
            # The '-' wildcard aggregates key rings across every location.
            return session.get_list(f"{KMS_V1}/projects/{ctx.account_id}/locations/-/keyRings", "keyRings")
        except Exception:  # noqa: BLE001 - fall back to per-location listing
            rings: list[dict] = []
            locations = session.get_list(f"{KMS_V1}/projects/{ctx.account_id}/locations", "locations")
            for location in locations:
                rings.extend(session.get_list(f"{KMS_V1}/{location['name']}/keyRings", "keyRings"))
            return rings

    def kms_key_rotation(self, control, ctx: CheckContext):
        session = ctx.session
        max_days = int(ctx.baseline.get("kmsRotationMaxDays", 90))
        max_seconds = max_days * 86400
        evaluated = 0
        offenders = []
        for ring in self._key_rings(ctx):
            keys = session.get_list(f"{KMS_V1}/{ring['name']}/cryptoKeys", "cryptoKeys")
            for key in keys:
                if key.get("purpose") != "ENCRYPT_DECRYPT":
                    continue
                if key.get("primary", {}).get("state") not in ("ENABLED", None):
                    continue
                evaluated += 1
                rotation = key.get("rotationPeriod", "")
                seconds = int(rotation.rstrip("s")) if rotation.rstrip("s").isdigit() else None
                if not key.get("nextRotationTime") or seconds is None or seconds > max_seconds:
                    detail = f"rotationPeriod={rotation or 'unset'}"
                    offenders.append((key.get("name", "unknown"), detail))
        if evaluated == 0:
            return self.result(control, ctx, "NotApplicable", "No enabled symmetric CMEK keys in project.")
        if not offenders:
            return self.result(
                control, ctx, "Pass", f"All {evaluated} symmetric key(s) rotate within {max_days} days."
            )
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"rotation missing or too slow ({detail}): {name.rsplit('/', 1)[-1]}",
                resource_type="kms-key",
                resource_id=name,
            )
            for name, detail in offenders
        ]
