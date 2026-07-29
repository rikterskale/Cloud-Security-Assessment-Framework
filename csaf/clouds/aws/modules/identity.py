"""IAM identity and privileged-access controls (account-global)."""

from __future__ import annotations

import csv
import datetime
import io
import time

from ...base import AssessmentModule, CheckContext

# Actions whose grant to a non-admin principal enables IAM privilege escalation.
# Sourced from the Rhino Security Labs AWS privesc matrix.
PRIVESC_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "glue:UpdateDevEndpoint",
    "sagemaker:CreateNotebookInstance",
}


def _age_days(timestamp: str) -> float | None:
    if not timestamp or timestamp in ("N/A", "no_information", "not_supported"):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - parsed).total_seconds() / 86400.0


class IdentityModule(AssessmentModule):
    name = "identity"

    # --- shared collection -------------------------------------------------

    def _credential_report(self, ctx: CheckContext) -> list[dict]:
        if "credential_report" in ctx.cache:
            return ctx.cache["credential_report"]
        iam = ctx.session.client("iam")
        for _ in range(10):
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
            time.sleep(1)
        report = iam.get_credential_report()
        rows = list(csv.DictReader(io.StringIO(report["Content"].decode("utf-8"))))
        ctx.evidence.write_text("01_identity", "credential-report.csv", report["Content"].decode("utf-8"))
        ctx.cache["credential_report"] = rows
        return rows

    def _root_row(self, ctx: CheckContext) -> dict | None:
        for row in self._credential_report(ctx):
            if row.get("user") == "<root_account>":
                return row
        return None

    # --- checks ------------------------------------------------------------

    def root_mfa(self, control, ctx: CheckContext):
        root = self._root_row(ctx)
        if not root:
            return self.result(control, ctx, "Error", "Root row absent from credential report.")
        enabled = root.get("mfa_active", "false") == "true"
        status = "Pass" if enabled else "Fail"
        return self.result(control, ctx, status, f"root mfa_active={enabled}", resource_type="iam-root")

    def root_access_keys(self, control, ctx: CheckContext):
        root = self._root_row(ctx)
        if not root:
            return self.result(control, ctx, "Error", "Root row absent from credential report.")
        active = root.get("access_key_1_active") == "true" or root.get("access_key_2_active") == "true"
        status = "Fail" if active else "Pass"
        return self.result(control, ctx, status, f"root active access keys={active}", resource_type="iam-root")

    def root_last_used(self, control, ctx: CheckContext):
        root = self._root_row(ctx)
        if not root:
            return self.result(control, ctx, "Error", "Root row absent from credential report.")
        threshold = ctx.baseline.get("rootActivityThresholdDays", 30)
        candidates = [
            _age_days(root.get("password_last_used", "")),
            _age_days(root.get("access_key_1_last_used_date", "")),
            _age_days(root.get("access_key_2_last_used_date", "")),
        ]
        ages = [a for a in candidates if a is not None]
        if not ages:
            return self.result(control, ctx, "Pass", "No recorded root activity.", resource_type="iam-root")
        most_recent = min(ages)
        status = "Fail" if most_recent <= threshold else "Pass"
        return self.result(
            control,
            ctx,
            status,
            f"root last used {most_recent:.1f} days ago (threshold {threshold})",
            resource_type="iam-root",
        )

    def password_policy(self, control, ctx: CheckContext):
        iam = ctx.session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except Exception as exc:  # noqa: BLE001
            if "NoSuchEntity" in type(exc).__name__ or "NoSuchEntity" in str(exc):
                return self.result(control, ctx, "Fail", "No account password policy is configured.")
            raise
        ctx.evidence.write_json("01_identity", "password-policy.json", policy)
        min_len = ctx.baseline.get("passwordMinLength", 14)
        issues = []
        if policy.get("MinimumPasswordLength", 0) < min_len:
            issues.append(f"length {policy.get('MinimumPasswordLength', 0)}<{min_len}")
        if ctx.baseline.get("passwordRequireSymbols") and not policy.get("RequireSymbols"):
            issues.append("no symbols")
        if ctx.baseline.get("passwordRequireNumbers") and not policy.get("RequireNumbers"):
            issues.append("no numbers")
        if ctx.baseline.get("passwordRequireUppercase") and not policy.get("RequireUppercaseCharacters"):
            issues.append("no uppercase")
        if ctx.baseline.get("passwordRequireLowercase") and not policy.get("RequireLowercaseCharacters"):
            issues.append("no lowercase")
        status = "Pass" if not issues else "Fail"
        observed = "meets policy" if not issues else "; ".join(issues)
        return self.result(control, ctx, status, observed)

    def user_mfa(self, control, ctx: CheckContext):
        results = []
        offenders = []
        for row in self._credential_report(ctx):
            if row.get("user") == "<root_account>":
                continue
            if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
                offenders.append(row.get("user"))
        if offenders:
            for user in offenders:
                results.append(
                    self.result(
                        control,
                        ctx,
                        "Fail",
                        f"console user without MFA: {user}",
                        resource_type="iam-user",
                        resource_id=user,
                    )
                )
        else:
            results.append(self.result(control, ctx, "Pass", "All console users have MFA."))
        return results

    def access_key_rotation(self, control, ctx: CheckContext):
        threshold = ctx.baseline.get("accessKeyMaxAgeDays", 90)
        offenders = []
        for row in self._credential_report(ctx):
            for idx in ("1", "2"):
                if row.get(f"access_key_{idx}_active") == "true":
                    age = _age_days(row.get(f"access_key_{idx}_last_rotated", ""))
                    if age is not None and age > threshold:
                        offenders.append((row.get("user"), idx, age))
        if not offenders:
            return self.result(control, ctx, "Pass", f"All active keys rotated within {threshold} days.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{user} key {idx} age {age:.0f}d > {threshold}d",
                resource_type="iam-access-key",
                resource_id=f"{user}:key{idx}",
            )
            for user, idx, age in offenders
        ]

    def unused_credentials(self, control, ctx: CheckContext):
        threshold = ctx.baseline.get("credentialInactivityDays", 90)
        offenders = []
        for row in self._credential_report(ctx):
            user = row.get("user")
            if user == "<root_account>":
                continue
            if row.get("password_enabled") == "true":
                age = _age_days(row.get("password_last_used", ""))
                if age is not None and age > threshold:
                    offenders.append(f"{user}:password({age:.0f}d)")
            for idx in ("1", "2"):
                if row.get(f"access_key_{idx}_active") == "true":
                    age = _age_days(row.get(f"access_key_{idx}_last_used_date", ""))
                    if age is not None and age > threshold:
                        offenders.append(f"{user}:key{idx}({age:.0f}d)")
        if not offenders:
            return self.result(control, ctx, "Pass", f"No credentials unused beyond {threshold} days.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"unused credential: {item}",
                resource_type="iam-credential",
                resource_id=item.split(":")[0],
            )
            for item in offenders
        ]

    def _local_policy_documents(self, ctx: CheckContext):
        if "local_policies" in ctx.cache:
            return ctx.cache["local_policies"]
        iam = ctx.session.client("iam")
        docs = []
        for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=False):
            for policy in page.get("Policies", []):
                version = iam.get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])[
                    "PolicyVersion"
                ]["Document"]
                docs.append((policy["PolicyName"], policy["Arn"], version))
        ctx.cache["local_policies"] = docs
        return docs

    def star_admin_policies(self, control, ctx: CheckContext):
        offenders = []
        for name, arn, document in self._local_policy_documents(ctx):
            statements = document.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources
                if "*" in actions and "*" in resources:
                    offenders.append((name, arn))
                    break
        if not offenders:
            return self.result(control, ctx, "Pass", "No customer policy grants Action:* on Resource:*.")
        return [
            self.result(
                control, ctx, "Fail", f"policy grants full admin: {name}", resource_type="iam-policy", resource_id=arn
            )
            for name, arn in offenders
        ]

    def access_analyzer(self, control, ctx: CheckContext):
        analyzer = ctx.session.client("accessanalyzer")
        analyzers = analyzer.list_analyzers().get("analyzers", [])
        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        status = "Pass" if active else "Fail"
        return self.result(control, ctx, status, f"active analyzers={len(active)}")

    def privesc_permissions(self, control, ctx: CheckContext):
        """Validation-only: static detection of privesc-enabling grants."""
        offenders = []
        for name, arn, document in self._local_policy_documents(ctx):
            statements = document.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            granted = set()
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                actions = [actions] if isinstance(actions, str) else actions
                for action in actions:
                    for dangerous in PRIVESC_ACTIONS:
                        if action == dangerous or action == "*" or _wildcard_match(action, dangerous):
                            granted.add(dangerous)
            if granted and "*" not in _all_actions(document):
                offenders.append((name, arn, sorted(granted)))
        if not offenders:
            return self.result(control, ctx, "Pass", "No non-admin policy grants known privesc actions.")
        results = []
        for name, arn, granted in offenders:
            results.append(
                self.result(
                    control,
                    ctx,
                    "Review",
                    f"{name} grants {', '.join(granted[:4])}",
                    confidence="MEDIUM",
                    resource_type="iam-policy",
                    resource_id=arn,
                )
            )
        return results


def _all_actions(document: dict) -> set[str]:
    out: set[str] = set()
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        out.update(actions)
    return out


def _wildcard_match(pattern: str, action: str) -> bool:
    """IAM-style wildcard match: 'iam:Pass*' matches 'iam:PassRole' (case-insensitive)."""
    if "*" not in pattern:
        return False
    if pattern == "*":
        return True
    pattern_service, _, pattern_action = pattern.partition(":")
    action_service, _, action_name = action.partition(":")
    if pattern_service.lower() not in ("*", action_service.lower()):
        return False
    prefix = pattern_action.split("*", 1)[0].lower()
    return action_name.lower().startswith(prefix)
