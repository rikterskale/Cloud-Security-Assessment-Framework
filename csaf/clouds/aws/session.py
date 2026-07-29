"""Read-only AWS session wrapper.

boto3 is an optional dependency so the framework imports and its tests run in
environments without it. The ``ReadOnlyClient`` proxy enforces that only
non-mutating API operations are ever invoked, giving a hard guardrail on top of
the read-only IAM policy an operator is expected to use.
"""

from __future__ import annotations

# Verb prefixes considered non-mutating. ``simulate`` is read-only policy
# evaluation used by the Validation profile.
READ_ONLY_PREFIXES = (
    "describe_",
    "list_",
    "get_",
    "head_",
    "lookup_",
    "batch_get_",
    "generate_credential_report",
    "generate_service_last_accessed_details",
    "simulate_principal_policy",
    "simulate_custom_policy",
)


class ReadOnlyViolation(RuntimeError):
    """Raised if a mutating API operation is attempted."""


class ReadOnlyClient:
    """Proxy that only exposes read-only operations of a boto3 client."""

    def __init__(self, client):
        self._client = client

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr
        if not name.startswith(READ_ONLY_PREFIXES):
            raise ReadOnlyViolation(
                f"Blocked non-read-only AWS operation '{name}'. CSAF performs read-only assessment."
            )
        return attr

    def get_paginator(self, operation_name: str):
        if not operation_name.startswith(READ_ONLY_PREFIXES):
            raise ReadOnlyViolation(f"Blocked paginator for non-read-only operation '{operation_name}'.")
        return self._client.get_paginator(operation_name)


class AwsSession:
    """Thin wrapper over a boto3 Session that hands out read-only clients."""

    def __init__(self, profile: str | None = None, region: str | None = None):
        import boto3  # imported lazily; optional dependency

        self._session = boto3.Session(profile_name=profile, region_name=region)
        self._clients: dict[tuple[str, str | None], ReadOnlyClient] = {}
        self._account_id: str | None = None

    def client(self, service: str, region: str | None = None) -> ReadOnlyClient:
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = ReadOnlyClient(self._session.client(service, region_name=region))
        return self._clients[key]

    @property
    def account_id(self) -> str:
        if self._account_id is None:
            self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id

    def caller_arn(self) -> str:
        return self.client("sts").get_caller_identity()["Arn"]

    def available_regions(self, service: str = "ec2") -> list[str]:
        return self._session.get_available_regions(service)
