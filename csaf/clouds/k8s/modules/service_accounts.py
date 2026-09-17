"""Kubernetes service-account controls (cluster scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

EXCLUDED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


class ServiceAccountsModule(AssessmentModule):
    name = "service_accounts"

    def default_sa_automount(self, control, ctx: CheckContext):
        core = ctx.session.api("core_v1")
        accounts = core.list_service_account_for_all_namespaces().items
        offenders = []
        for account in accounts:
            if account.metadata.namespace in EXCLUDED_NAMESPACES:
                continue
            if account.metadata.name != "default":
                continue
            automount = getattr(account, "automount_service_account_token", None)
            if automount is not False:
                offenders.append(account.metadata.namespace)
        if not offenders:
            return self.result(control, ctx, "Pass", "Default service accounts disable automountServiceAccountToken.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"default service account in namespace {namespace} automounts its token",
                resource_type="serviceaccount",
                resource_id=f"{namespace}/default",
            )
            for namespace in sorted(offenders)
        ]
