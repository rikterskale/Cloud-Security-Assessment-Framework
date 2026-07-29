"""Kubernetes network-segmentation controls (cluster scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

EXCLUDED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


class NetworkModule(AssessmentModule):
    name = "network"

    def namespace_without_network_policy(self, control, ctx: CheckContext):
        core = ctx.session.api("core_v1")
        namespaces = [
            ns.metadata.name for ns in core.list_namespace().items if ns.metadata.name not in EXCLUDED_NAMESPACES
        ]
        if not namespaces:
            return self.result(control, ctx, "NotApplicable", "No workload namespaces in the cluster.")

        networking = ctx.session.api("networking_v1")
        policies = networking.list_network_policy_for_all_namespaces().items
        namespaces_with_policy = {p.metadata.namespace for p in policies}

        offenders = sorted(ns for ns in namespaces if ns not in namespaces_with_policy)
        if not offenders:
            return self.result(
                control, ctx, "Pass", f"All {len(namespaces)} workload namespace(s) have a NetworkPolicy."
            )
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"namespace has no NetworkPolicy: {namespace}",
                resource_type="namespace",
                resource_id=namespace,
            )
            for namespace in offenders
        ]
