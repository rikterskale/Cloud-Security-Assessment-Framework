"""Azure RBAC identity controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_AUTHORIZATION = "2022-04-01"
# Well-known built-in Owner role definition GUID (constant across tenants).
OWNER_ROLE_DEFINITION_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


class IdentityModule(AssessmentModule):
    name = "identity"

    def custom_owner_roles(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        roles = arm.get_value(
            f"{sub}/providers/Microsoft.Authorization/roleDefinitions",
            API_AUTHORIZATION,
            params={"$filter": "type eq 'CustomRole'"},
        )
        offenders = []
        for role in roles:
            props = role.get("properties", {})
            scopes = props.get("assignableScopes", [])
            broad = any(s == "/" or (s.startswith("/subscriptions/") and s.count("/") == 2) for s in scopes)
            grants_star = any("*" in perm.get("actions", []) for perm in props.get("permissions", []))
            if broad and grants_star:
                offenders.append(props.get("roleName") or role.get("name", "unknown"))
        if not offenders:
            return self.result(
                control, ctx, "Pass", f"{len(roles)} custom role(s); none grant '*' at subscription scope."
            )
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"custom role grants Actions:* at subscription scope: {name}",
                resource_type="role-definition",
                resource_id=name,
            )
            for name in offenders
        ]

    def subscription_owner_count(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        assignments = arm.get_value(
            f"{sub}/providers/Microsoft.Authorization/roleAssignments",
            API_AUTHORIZATION,
            params={"$filter": "atScope()"},
        )
        owners = [
            a
            for a in assignments
            if a.get("properties", {}).get("roleDefinitionId", "").lower().endswith(OWNER_ROLE_DEFINITION_ID)
            and a.get("properties", {}).get("scope", "").lower() == sub.lower()
        ]
        max_owners = int(ctx.baseline.get("subscriptionOwnerMaxCount", 3))
        observed = f"{len(owners)} Owner assignment(s) at subscription scope (threshold {max_owners})."
        if len(owners) <= max_owners:
            return self.result(control, ctx, "Pass", observed)
        # Principal types are not resolvable without Graph access, so this is a Review.
        return self.result(control, ctx, "Review", observed, confidence="MEDIUM")
