"""KMS key-management controls (per-region scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext


class KmsModule(AssessmentModule):
    name = "kms"

    def kms_key_rotation(self, control, ctx: CheckContext):
        kms = ctx.session.client("kms", ctx.region)
        offenders = []
        evaluated = 0
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                key_id = key["KeyId"]
                meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                if meta.get("KeyState") != "Enabled":
                    continue
                if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue
                evaluated += 1
                rotation = kms.get_key_rotation_status(KeyId=key_id)
                if not rotation.get("KeyRotationEnabled"):
                    offenders.append(key_id)
        if evaluated == 0:
            return self.result(control, ctx, "NotApplicable", "No customer-managed symmetric keys in region.")
        if not offenders:
            return self.result(control, ctx, "Pass", "All customer-managed symmetric keys rotate.")
        return [
            self.result(control, ctx, "Fail", f"rotation disabled: {kid}", resource_type="kms-key", resource_id=kid)
            for kid in offenders
        ]
