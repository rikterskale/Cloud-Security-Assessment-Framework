"""Cloud Storage data-protection controls (project scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

GCS_V1 = "https://storage.googleapis.com/storage/v1"
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class StorageModule(AssessmentModule):
    name = "storage"

    def _buckets(self, ctx: CheckContext) -> list[dict]:
        if "gcs_buckets" not in ctx.cache:
            ctx.cache["gcs_buckets"] = ctx.session.get_list(f"{GCS_V1}/b", "items", params={"project": ctx.account_id})
        return ctx.cache["gcs_buckets"]

    def bucket_public_iam(self, control, ctx: CheckContext):
        buckets = self._buckets(ctx)
        if not buckets:
            return self.result(control, ctx, "NotApplicable", "No Cloud Storage buckets in project.")
        offenders = []
        for bucket in buckets:
            name = bucket.get("name", "unknown")
            policy = ctx.session.get(f"{GCS_V1}/b/{name}/iam")
            for binding in policy.get("bindings", []):
                public = sorted(set(binding.get("members", [])) & PUBLIC_MEMBERS)
                if public:
                    offenders.append((name, binding.get("role", ""), public))
        if not offenders:
            return self.result(control, ctx, "Pass", f"No public IAM grants on {len(buckets)} bucket(s).")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{name} grants {role} to {members}",
                resource_type="gcs-bucket",
                resource_id=name,
            )
            for name, role, members in offenders
        ]

    def uniform_bucket_access(self, control, ctx: CheckContext):
        buckets = self._buckets(ctx)
        if not buckets:
            return self.result(control, ctx, "NotApplicable", "No Cloud Storage buckets in project.")
        offenders = [
            b.get("name", "unknown")
            for b in buckets
            if not b.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled")
        ]
        if not offenders:
            return self.result(control, ctx, "Pass", "All buckets enforce uniform bucket-level access.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"uniform bucket-level access disabled: {name}",
                resource_type="gcs-bucket",
                resource_id=name,
            )
            for name in offenders
        ]
