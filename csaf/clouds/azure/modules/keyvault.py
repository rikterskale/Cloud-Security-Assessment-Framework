"""Key Vault recoverability controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_KEYVAULT = "2023-07-01"


class KeyVaultModule(AssessmentModule):
    name = "keyvault"

    def purge_protection(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        vaults = arm.get_value(f"{sub}/providers/Microsoft.KeyVault/vaults", API_KEYVAULT)
        if not vaults:
            return self.result(control, ctx, "NotApplicable", "No key vaults in subscription.")
        offenders = []
        for vault in vaults:
            props = vault.get("properties", {})
            # Soft delete defaults to on for current vaults; purge protection must be explicit.
            soft_delete = props.get("enableSoftDelete", True)
            purge = props.get("enablePurgeProtection", False)
            if not (soft_delete and purge):
                offenders.append((vault.get("name", "unknown"), soft_delete, purge))
        if not offenders:
            return self.result(control, ctx, "Pass", f"All {len(vaults)} key vault(s) are recoverable.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{name}: softDelete={soft}, purgeProtection={purge}",
                resource_type="key-vault",
                resource_id=name,
            )
            for name, soft, purge in offenders
        ]
