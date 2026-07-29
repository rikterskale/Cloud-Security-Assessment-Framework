"""Microsoft Defender for Cloud controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_PRICINGS = "2023-01-01"
API_CONTACTS = "2020-01-01-preview"


class DefenderModule(AssessmentModule):
    name = "defender"

    def defender_plans(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        pricings = arm.get(f"{sub}/providers/Microsoft.Security/pricings", API_PRICINGS).get("value", [])
        tiers = {p.get("name", ""): p.get("properties", {}).get("pricingTier", "Free") for p in pricings}
        required = ctx.baseline.get("requiredDefenderPlans", ["VirtualMachines", "StorageAccounts", "SqlServers"])
        missing = [plan for plan in required if tiers.get(plan) != "Standard"]
        if not missing:
            return self.result(control, ctx, "Pass", f"Required Defender plans on Standard tier: {required}.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"Defender plan '{plan}' is {tiers.get(plan, 'absent')}, not Standard.",
                resource_type="defender-plan",
                resource_id=plan,
            )
            for plan in missing
        ]

    def security_contact(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        contacts = arm.get_value(f"{sub}/providers/Microsoft.Security/securityContacts", API_CONTACTS)
        emails = []
        for contact in contacts:
            props = contact.get("properties", {})
            value = props.get("emails") or props.get("email") or ""
            emails.extend(e.strip() for e in str(value).replace(";", ",").split(",") if e.strip())
        if emails:
            return self.result(control, ctx, "Pass", f"Security contact email(s) configured: {len(emails)}.")
        return self.result(control, ctx, "Fail", "No Defender for Cloud security contact email is configured.")
