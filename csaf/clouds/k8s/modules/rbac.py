"""Kubernetes RBAC controls (cluster scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

# Subjects considered part of the cluster's own control plane, not an
# operator-managed principal, and therefore not flagged.
SYSTEM_SUBJECT_NAMESPACES = {"kube-system"}
SYSTEM_GROUPS = {"system:masters"}


class RbacModule(AssessmentModule):
    name = "rbac"

    def cluster_admin_bindings(self, control, ctx: CheckContext):
        rbac = ctx.session.api("rbac_v1")
        bindings = rbac.list_cluster_role_binding().items
        offenders = []
        for binding in bindings:
            if binding.role_ref.name != "cluster-admin":
                continue
            for subject in binding.subjects or []:
                if subject.kind == "ServiceAccount" and subject.namespace in SYSTEM_SUBJECT_NAMESPACES:
                    continue
                if subject.kind == "Group" and subject.name in SYSTEM_GROUPS:
                    continue
                offenders.append((binding.metadata.name, subject.kind, subject.name))
        if not offenders:
            return self.result(control, ctx, "Pass", "No non-system subject is bound to cluster-admin.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{kind} '{name}' is bound to cluster-admin via {binding_name}",
                resource_type="clusterrolebinding",
                resource_id=binding_name,
            )
            for binding_name, kind, name in offenders
        ]

    def wildcard_verbs(self, control, ctx: CheckContext):
        rbac = ctx.session.api("rbac_v1")
        roles = {role.metadata.name: role for role in rbac.list_cluster_role().items}
        bindings = rbac.list_cluster_role_binding().items
        offenders = []
        for binding in bindings:
            role = roles.get(binding.role_ref.name)
            if role is None:
                continue
            wild = False
            for rule in role.rules or []:
                verbs = list(getattr(rule, "verbs", None) or [])
                resources = list(getattr(rule, "resources", None) or [])
                if "*" in verbs or "*" in resources:
                    wild = True
                    break
            if not wild:
                continue
            for subject in binding.subjects or []:
                if subject.kind == "ServiceAccount" and subject.namespace in SYSTEM_SUBJECT_NAMESPACES:
                    continue
                if subject.kind == "Group" and subject.name in SYSTEM_GROUPS:
                    continue
                offenders.append((binding.metadata.name, binding.role_ref.name, subject.kind, subject.name))
        if not offenders:
            return self.result(control, ctx, "Pass", "No non-system subject is bound to a wildcard ClusterRole.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{kind} '{name}' is bound to wildcard ClusterRole {role_name} via {binding_name}",
                resource_type="clusterrolebinding",
                resource_id=binding_name,
            )
            for binding_name, role_name, kind, name in offenders
        ]
