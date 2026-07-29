"""Read-only Kubernetes cluster session.

Talks to the cluster via the official ``kubernetes`` Python client (an
optional dependency, imported lazily) using the operator's kubeconfig. The
guardrail is structural: every API object handed out is wrapped in
``ReadOnlyApiClient``, which only permits methods named ``list_*`` or
``read_*`` (the client's generated read-only operations); every mutating verb
(``create_*``, ``replace_*``, ``patch_*``, ``delete_*``, and especially
``connect_*`` — which covers exec/attach/port-forward) raises
``ReadOnlyViolation``. This sits on top of the read-only RBAC role (e.g. a
ClusterRole aggregated from ``view``) the operator is expected to use.
"""

from __future__ import annotations

READ_ONLY_PREFIXES = ("list_", "read_", "get_api_resources", "get_code")


class ReadOnlyViolation(RuntimeError):
    """Raised if a non-read-only Kubernetes API call is attempted."""


class ReadOnlyApiClient:
    """Proxy that only exposes read-only operations of a generated k8s API client."""

    def __init__(self, api):
        self._api = api

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        attr = getattr(self._api, name)
        if not callable(attr):
            return attr
        if not name.startswith(READ_ONLY_PREFIXES):
            raise ReadOnlyViolation(
                f"Blocked non-read-only Kubernetes operation '{name}'. CSAF performs read-only assessment."
            )
        return attr


# Maps a short API name (what check modules ask for) to the generated
# client's API class. Modules never import ``kubernetes`` themselves - only
# this session does, and only when a real API proxy is actually requested -
# mirroring how AWS modules pass a plain service-name string to
# ``AwsSession.client()`` rather than importing boto3.
_API_CLASS_NAMES = {
    "core_v1": "CoreV1Api",
    "rbac_v1": "RbacAuthorizationV1Api",
    "networking_v1": "NetworkingV1Api",
    "apps_v1": "AppsV1Api",
}


class K8sSession:
    """Thin wrapper over the kubernetes client that hands out read-only API proxies.

    ``api_client`` and ``context`` are injectable for tests; by default the
    API client is built from the operator's kubeconfig via
    ``kubernetes.config.load_kube_config``.
    """

    def __init__(self, kubeconfig_path: str | None = None, context: str | None = None, api_client=None):
        if api_client is None:
            from kubernetes import client, config  # imported lazily; optional dependency

            config.load_kube_config(config_file=kubeconfig_path, context=context)
            api_client = client.ApiClient()
            if context is None:
                _, active = config.list_kube_config_contexts(config_file=kubeconfig_path)
                context = active["name"]
        self._api_client = api_client
        self._context = context or "default"
        self._apis: dict[str, ReadOnlyApiClient] = {}

    def api(self, api_name: str) -> ReadOnlyApiClient:
        """Return a read-only proxy for a named API group (e.g. ``"rbac_v1"``)."""
        if api_name not in self._apis:
            if api_name not in _API_CLASS_NAMES:
                raise KeyError(f"Unknown Kubernetes API group {api_name!r}")
            from kubernetes import client  # imported lazily; optional dependency

            api_class = getattr(client, _API_CLASS_NAMES[api_name])
            self._apis[api_name] = ReadOnlyApiClient(api_class(self._api_client))
        return self._apis[api_name]

    @property
    def cluster_context(self) -> str:
        """The kubeconfig context name — the closest k8s analogue to an account/subscription/project ID."""
        return self._context
