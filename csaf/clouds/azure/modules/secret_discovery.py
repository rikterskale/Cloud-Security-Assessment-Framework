"""Azure secret-location discovery with strict metadata-only handling.

This module never calls value-bearing ``list`` operations and never writes
evidence. It identifies resource locations whose configuration commonly holds
credentials, while preserving CSAF's no-secret-persistence guarantee.
"""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_WEB = "2024-04-01"
API_AUTOMATION = "2023-11-01"
API_KEYVAULT = "2023-07-01"


class SecretDiscoveryModule(AssessmentModule):
    name = "secret_discovery"

    def secret_bearing_locations(self, control, ctx: CheckContext):
        if not ctx.secret_discovery_enabled:
            return self.result(
                control,
                ctx,
                "NotApplicable",
                "Secret discovery was not requested; pass --allow-secret-discovery with a signed, explicitly approving engagement.",
                confidence="LOW",
            )

        arm = ctx.session
        subscription = f"/subscriptions/{ctx.account_id}"
        locations = []
        for path, api_version, resource_type, classifier in (
            (f"{subscription}/providers/Microsoft.Web/sites", API_WEB, "app-service", self._site_type),
            (f"{subscription}/providers/Microsoft.Automation/automationAccounts", API_AUTOMATION, "automation-account", None),
            (f"{subscription}/providers/Microsoft.KeyVault/vaults", API_KEYVAULT, "key-vault", None),
        ):
            for resource in arm.get_value(path, api_version):
                locations.append((classifier(resource) if classifier else resource_type, resource.get("name", "unknown")))

        ctx.logger.info(
            self.name,
            f"Metadata-only secret discovery completed: {len(locations)} eligible resource location(s); no values requested or stored.",
            controlId=control.id,
        )
        if not locations:
            return self.result(
                control,
                ctx,
                "Pass",
                "No supported secret-bearing resource locations were found. No secret values were requested or stored.",
            )
        return [
            self.result(
                control,
                ctx,
                "Review",
                f"Potential secret-bearing {resource_type} location discovered. No value was requested, displayed, or persisted.",
                confidence="MEDIUM",
                resource_type=resource_type,
                resource_id=name,
            )
            for resource_type, name in locations
        ]

    @staticmethod
    def _site_type(resource: dict) -> str:
        kind = str(resource.get("kind", "")).lower()
        return "function-app" if "functionapp" in kind else "app-service"
