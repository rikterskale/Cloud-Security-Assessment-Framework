"""AWS Secrets Manager data-protection controls (per-region scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext


class SecretsModule(AssessmentModule):
    name = "secrets"

    def _secrets(self, ctx: CheckContext) -> list[dict]:
        key = f"secretsmanager_secrets_{ctx.region}"
        if key in ctx.cache:
            return ctx.cache[key]
        client = ctx.session.client("secretsmanager", ctx.region)
        secrets = []
        for page in client.get_paginator("list_secrets").paginate():
            secrets.extend(page.get("SecretList", []))
        ctx.cache[key] = secrets
        return secrets

    def secret_rotation_enabled(self, control, ctx: CheckContext):
        secrets = self._secrets(ctx)
        if not secrets:
            return self.result(control, ctx, "NotApplicable", "No Secrets Manager secrets in region.")
        offenders = [s["Name"] for s in secrets if not s.get("RotationEnabled")]
        if not offenders:
            return self.result(control, ctx, "Pass", f"All {len(secrets)} secret(s) have rotation enabled.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"rotation not enabled: {name}",
                resource_type="secretsmanager-secret",
                resource_id=name,
            )
            for name in offenders
        ]

    def secret_cmk_encryption(self, control, ctx: CheckContext):
        secrets = self._secrets(ctx)
        if not secrets:
            return self.result(control, ctx, "NotApplicable", "No Secrets Manager secrets in region.")
        offenders = [s["Name"] for s in secrets if not s.get("KmsKeyId")]
        if not offenders:
            return self.result(control, ctx, "Pass", f"All {len(secrets)} secret(s) use a customer-managed KMS key.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"uses the default AWS-managed key, not a customer-managed KMS key: {name}",
                resource_type="secretsmanager-secret",
                resource_id=name,
            )
            for name in offenders
        ]
