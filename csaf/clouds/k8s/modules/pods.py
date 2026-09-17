"""Kubernetes pod-security controls (cluster scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

EXCLUDED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


class PodsModule(AssessmentModule):
    name = "pods"

    def _pods(self, ctx: CheckContext) -> list:
        if "k8s_pods" not in ctx.cache:
            core = ctx.session.api("core_v1")
            ctx.cache["k8s_pods"] = core.list_pod_for_all_namespaces().items
        return ctx.cache["k8s_pods"]

    def _workload_pods(self, ctx: CheckContext) -> list:
        return [p for p in self._pods(ctx) if p.metadata.namespace not in EXCLUDED_NAMESPACES]

    def privileged_containers(self, control, ctx: CheckContext):
        pods = self._workload_pods(ctx)
        if not pods:
            return self.result(control, ctx, "NotApplicable", "No workload pods in the cluster.")
        offenders = []
        for pod in pods:
            containers = list(pod.spec.containers or []) + list(pod.spec.init_containers or [])
            for container in containers:
                security_context = container.security_context
                if security_context is not None and security_context.privileged:
                    offenders.append((pod.metadata.namespace, pod.metadata.name, container.name))
        if not offenders:
            return self.result(control, ctx, "Pass", f"No privileged containers among {len(pods)} pod(s).")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"container '{container}' runs privileged in pod {namespace}/{name}",
                resource_type="pod",
                resource_id=f"{namespace}/{name}",
            )
            for namespace, name, container in offenders
        ]

    def _flag_pods(self, control, ctx: CheckContext, predicate, observed_pass: str, observed_fail):
        pods = self._workload_pods(ctx)
        if not pods:
            return self.result(control, ctx, "NotApplicable", "No workload pods in the cluster.")
        offenders = [(pod.metadata.namespace, pod.metadata.name) for pod in pods if predicate(pod)]
        if not offenders:
            return self.result(control, ctx, "Pass", observed_pass.format(count=len(pods)))
        return [
            self.result(
                control,
                ctx,
                "Fail",
                observed_fail.format(namespace=namespace, name=name),
                resource_type="pod",
                resource_id=f"{namespace}/{name}",
            )
            for namespace, name in offenders
        ]

    def host_network_pods(self, control, ctx: CheckContext):
        pods = self._workload_pods(ctx)
        if not pods:
            return self.result(control, ctx, "NotApplicable", "No workload pods in the cluster.")
        offenders = [
            (pod.metadata.namespace, pod.metadata.name) for pod in pods if getattr(pod.spec, "host_network", False)
        ]
        if not offenders:
            return self.result(control, ctx, "Pass", f"No pod uses the host network among {len(pods)} pod(s).")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"pod {namespace}/{name} uses hostNetwork",
                resource_type="pod",
                resource_id=f"{namespace}/{name}",
            )
            for namespace, name in offenders
        ]

    def host_pid_pods(self, control, ctx: CheckContext):
        return self._flag_pods(
            control,
            ctx,
            lambda pod: bool(getattr(pod.spec, "host_pid", False)),
            "No pod uses hostPID among {count} pod(s).",
            "pod {namespace}/{name} uses hostPID",
        )

    def host_ipc_pods(self, control, ctx: CheckContext):
        return self._flag_pods(
            control,
            ctx,
            lambda pod: bool(getattr(pod.spec, "host_ipc", False)),
            "No pod uses hostIPC among {count} pod(s).",
            "pod {namespace}/{name} uses hostIPC",
        )

    def host_path_volumes(self, control, ctx: CheckContext):
        def uses_host_path(pod) -> bool:
            for volume in getattr(pod.spec, "volumes", None) or []:
                if getattr(volume, "host_path", None) is not None:
                    return True
            return False

        return self._flag_pods(
            control,
            ctx,
            uses_host_path,
            "No pod mounts hostPath volumes among {count} pod(s).",
            "pod {namespace}/{name} mounts a hostPath volume",
        )

    def privilege_escalation(self, control, ctx: CheckContext):
        pods = self._workload_pods(ctx)
        if not pods:
            return self.result(control, ctx, "NotApplicable", "No workload pods in the cluster.")
        offenders = []
        for pod in pods:
            containers = list(pod.spec.containers or []) + list(pod.spec.init_containers or [])
            for container in containers:
                security_context = container.security_context
                if (
                    security_context is not None
                    and getattr(security_context, "allow_privilege_escalation", None) is True
                ):
                    offenders.append((pod.metadata.namespace, pod.metadata.name, container.name))
        if not offenders:
            return self.result(
                control, ctx, "Pass", f"No container allows privilege escalation among {len(pods)} pod(s)."
            )
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"container '{container}' allows privilege escalation in pod {namespace}/{name}",
                resource_type="pod",
                resource_id=f"{namespace}/{name}",
            )
            for namespace, name, container in offenders
        ]
