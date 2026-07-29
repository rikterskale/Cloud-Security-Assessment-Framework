"""Storage-account data-protection controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_STORAGE = "2023-01-01"
ACCEPTABLE_TLS = {"TLS1_2", "TLS1_3"}


class StorageModule(AssessmentModule):
    name = "storage"

    def _accounts(self, ctx: CheckContext) -> list[dict]:
        if "storage_accounts" not in ctx.cache:
            sub = f"/subscriptions/{ctx.account_id}"
            ctx.cache["storage_accounts"] = ctx.session.get_value(
                f"{sub}/providers/Microsoft.Storage/storageAccounts", API_STORAGE
            )
        return ctx.cache["storage_accounts"]

    def _per_account(self, control, ctx: CheckContext, is_offender, describe: str, all_ok: str):
        accounts = self._accounts(ctx)
        if not accounts:
            return self.result(control, ctx, "NotApplicable", "No storage accounts in subscription.")
        offenders = [a.get("name", "unknown") for a in accounts if is_offender(a.get("properties", {}))]
        if not offenders:
            return self.result(control, ctx, "Pass", all_ok)
        return [
            self.result(control, ctx, "Fail", f"{describe}: {name}", resource_type="storage-account", resource_id=name)
            for name in offenders
        ]

    def secure_transfer(self, control, ctx: CheckContext):
        return self._per_account(
            control,
            ctx,
            lambda p: not p.get("supportsHttpsTrafficOnly", False),
            "secure transfer (HTTPS-only) not required",
            "All storage accounts require secure transfer.",
        )

    def blob_public_access(self, control, ctx: CheckContext):
        # A missing property cannot be proven disabled, so it is treated as an offender.
        return self._per_account(
            control,
            ctx,
            lambda p: p.get("allowBlobPublicAccess", True),
            "blob public access is not disabled",
            "All storage accounts disallow blob public access.",
        )

    def minimum_tls(self, control, ctx: CheckContext):
        return self._per_account(
            control,
            ctx,
            lambda p: p.get("minimumTlsVersion", "TLS1_0") not in ACCEPTABLE_TLS,
            "minimum TLS version below 1.2",
            "All storage accounts enforce TLS 1.2 or higher.",
        )

    def default_network_deny(self, control, ctx: CheckContext):
        return self._per_account(
            control,
            ctx,
            lambda p: p.get("networkAcls", {}).get("defaultAction", "Allow") != "Deny",
            "network default action is not Deny",
            "All storage accounts default-deny network access.",
        )
