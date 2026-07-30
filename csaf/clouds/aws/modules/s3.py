"""S3 data-protection controls (account + per-bucket, global scope)."""

from __future__ import annotations

import json

from ...base import AssessmentModule, CheckContext

PUBLIC_GRANT_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)

NO_BUCKET_POLICY_CODES = {"NoSuchBucketPolicy"}


def _error_code(exc: Exception) -> str:
    """Return a structured AWS error code when available, else its text."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    return str(exc)


class S3Module(AssessmentModule):
    name = "s3"

    def _buckets(self, ctx: CheckContext) -> list[str]:
        if "s3_buckets" in ctx.cache:
            return ctx.cache["s3_buckets"]
        s3 = ctx.session.client("s3")
        names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        ctx.cache["s3_buckets"] = names
        return names

    def account_public_access_block(self, control, ctx: CheckContext):
        client = ctx.session.client("s3control")
        try:
            cfg = client.get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
        except Exception as exc:  # noqa: BLE001
            if "NoSuchPublicAccessBlockConfiguration" in str(exc):
                return self.result(control, ctx, "Fail", "No account-level public access block configured.")
            raise
        all_on = all(
            cfg.get(k) for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        )
        status = "Pass" if all_on else "Fail"
        return self.result(control, ctx, status, f"account public-access-block settings={cfg}")

    def bucket_public_access(self, control, ctx: CheckContext):
        s3 = ctx.session.client("s3")
        offenders = []
        for name in self._buckets(ctx):
            public = False
            reason = ""
            try:
                status = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
                if status.get("IsPublic"):
                    public, reason = True, "policy public"
            except Exception as exc:  # noqa: BLE001 - only an explicitly absent policy is fine
                if _error_code(exc) not in NO_BUCKET_POLICY_CODES:
                    raise
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    if grant.get("Grantee", {}).get("URI") in PUBLIC_GRANT_URIS:
                        public, reason = True, (reason + " acl public").strip()
            except Exception:
                # A bucket always has an ACL. Failure to inspect it means public
                # access was not established and must never be reported Pass.
                raise
            if public:
                offenders.append((name, reason))
        if not offenders:
            return self.result(control, ctx, "Pass", "No publicly accessible buckets detected.")
        return [
            self.result(control, ctx, "Fail", f"{name}: {reason}", resource_type="s3-bucket", resource_id=name)
            for name, reason in offenders
        ]

    def bucket_encryption(self, control, ctx: CheckContext):
        s3 = ctx.session.client("s3")
        offenders = []
        for name in self._buckets(ctx):
            try:
                s3.get_bucket_encryption(Bucket=name)
            except Exception as exc:  # noqa: BLE001
                if "ServerSideEncryptionConfigurationNotFoundError" in str(exc):
                    offenders.append(name)
                elif "AccessDenied" in str(exc):
                    offenders.append(f"{name}(access-denied)")
                else:
                    # Unexpected errors surface as a module-level Error result,
                    # never as a silent pass for the affected bucket.
                    raise
        if not offenders:
            return self.result(control, ctx, "Pass", "All buckets have default encryption.")
        return [
            self.result(
                control, ctx, "Fail", f"no default encryption: {name}", resource_type="s3-bucket", resource_id=name
            )
            for name in offenders
        ]

    def bucket_tls_policy(self, control, ctx: CheckContext):
        s3 = ctx.session.client("s3")
        offenders = []
        for name in self._buckets(ctx):
            enforced = False
            try:
                doc = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    cond = stmt.get("Condition", {})
                    secure = cond.get("Bool", {}).get("aws:SecureTransport")
                    if stmt.get("Effect") == "Deny" and str(secure).lower() == "false":
                        enforced = True
            except Exception:  # noqa: BLE001 - no policy => not enforced
                enforced = False
            if not enforced:
                offenders.append(name)
        if not offenders:
            return self.result(control, ctx, "Pass", "All buckets enforce TLS-only access.")
        return [
            self.result(
                control, ctx, "Fail", f"no TLS-only deny policy: {name}", resource_type="s3-bucket", resource_id=name
            )
            for name in offenders
        ]
