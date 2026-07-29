"""GCP IAM identity controls (project scope)."""

from __future__ import annotations

import datetime

from ...base import AssessmentModule, CheckContext

CRM_V1 = "https://cloudresourcemanager.googleapis.com/v1"
IAM_V1 = "https://iam.googleapis.com/v1"

BASIC_PRIVILEGED_ROLES = {"roles/owner", "roles/editor"}
DEFAULT_COMPUTE_SA_SUFFIX = "-compute@developer.gserviceaccount.com"


def project_iam_policy(ctx: CheckContext) -> dict:
    """Fetch (and cache) the project IAM policy via the read-only getIamPolicy POST."""
    if "gcp_iam_policy" not in ctx.cache:
        ctx.cache["gcp_iam_policy"] = ctx.session.post(
            f"{CRM_V1}/projects/{ctx.account_id}:getIamPolicy",
            json_body={"options": {"requestedPolicyVersion": 3}},
        )
    return ctx.cache["gcp_iam_policy"]


def _user_managed_keys(ctx: CheckContext) -> dict[str, list[dict]]:
    """Map service-account email -> user-managed keys, cached per run."""
    if "gcp_sa_keys" not in ctx.cache:
        session = ctx.session
        accounts = session.get_list(f"{IAM_V1}/projects/{ctx.account_id}/serviceAccounts", "accounts")
        keys: dict[str, list[dict]] = {}
        for account in accounts:
            email = account.get("email", "")
            data = session.get(
                f"{IAM_V1}/projects/{ctx.account_id}/serviceAccounts/{email}/keys",
                params={"keyTypes": "USER_MANAGED"},
            )
            keys[email] = data.get("keys", []) or []
        ctx.cache["gcp_sa_keys"] = keys
    return ctx.cache["gcp_sa_keys"]


class IdentityModule(AssessmentModule):
    name = "identity"

    def sa_admin_roles(self, control, ctx: CheckContext):
        policy = project_iam_policy(ctx)
        project_suffixes = (f"@{ctx.account_id}.iam.gserviceaccount.com", DEFAULT_COMPUTE_SA_SUFFIX)
        offenders = []
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            privileged = role in BASIC_PRIVILEGED_ROLES or "admin" in role.rsplit("/", 1)[-1].lower()
            if not privileged:
                continue
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:") and member.endswith(project_suffixes):
                    offenders.append((member.split(":", 1)[1], role))
        if not offenders:
            return self.result(control, ctx, "Pass", "No project service account holds owner/editor/admin roles.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{email} holds privileged role {role}",
                resource_type="service-account",
                resource_id=email,
            )
            for email, role in offenders
        ]

    def user_managed_sa_keys(self, control, ctx: CheckContext):
        keys = _user_managed_keys(ctx)
        if not keys:
            return self.result(control, ctx, "NotApplicable", "No service accounts in project.")
        offenders = [(email, len(sa_keys)) for email, sa_keys in keys.items() if sa_keys]
        if not offenders:
            return self.result(control, ctx, "Pass", "No service account has user-managed keys.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{email} has {count} user-managed key(s)",
                resource_type="service-account",
                resource_id=email,
            )
            for email, count in offenders
        ]

    def sa_key_rotation(self, control, ctx: CheckContext):
        keys = _user_managed_keys(ctx)
        max_age = int(ctx.baseline.get("saKeyMaxAgeDays", 90))
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=max_age)
        evaluated = 0
        offenders = []
        for email, sa_keys in keys.items():
            for key in sa_keys:
                evaluated += 1
                created = key.get("validAfterTime", "")
                try:
                    created_at = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
                except ValueError:
                    offenders.append((email, key.get("name", ""), f"unparseable validAfterTime {created!r}"))
                    continue
                if created_at < cutoff:
                    age = (datetime.datetime.now(datetime.timezone.utc) - created_at).days
                    offenders.append((email, key.get("name", ""), f"{age} days old"))
        if evaluated == 0:
            return self.result(control, ctx, "NotApplicable", "No user-managed service-account keys in project.")
        if not offenders:
            return self.result(control, ctx, "Pass", f"All {evaluated} user-managed key(s) within {max_age} days.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{email} key exceeds rotation threshold: {detail}",
                resource_type="service-account-key",
                resource_id=key_name,
            )
            for email, key_name, detail in offenders
        ]

    def basic_roles_on_users(self, control, ctx: CheckContext):
        policy = project_iam_policy(ctx)
        offenders = []
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            if role not in BASIC_PRIVILEGED_ROLES:
                continue
            for member in binding.get("members", []):
                if member.startswith(("user:", "group:", "domain:")):
                    offenders.append((member, role))
        if not offenders:
            return self.result(control, ctx, "Pass", "No user/group/domain principal holds a basic owner/editor role.")
        # Basic roles may be intentional for small projects; flag for review.
        return [
            self.result(
                control,
                ctx,
                "Review",
                f"{member} holds basic role {role}",
                confidence="MEDIUM",
                resource_type="iam-binding",
                resource_id=member,
            )
            for member, role in offenders
        ]
