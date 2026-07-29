"""Read-only Azure Resource Manager (ARM) session.

Talks to the ARM REST API directly with a bearer token from ``azure-identity``
(an optional dependency, imported lazily). The guardrail is structural: every
request funnels through :meth:`ArmSession.request`, which only permits the GET
verb, so no mutating ARM operation (PUT/PATCH/POST/DELETE) can ever be issued.
This sits on top of the read-only RBAC role (e.g. ``Reader``) an operator is
expected to use.
"""

from __future__ import annotations

import time

ARM_BASE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"

# The only HTTP verb CSAF is allowed to send to ARM. Some Azure "list" data
# operations (e.g. storage listKeys) are POST precisely because they expose
# secrets; blocking every non-GET verb also keeps those out of scope.
READ_ONLY_METHODS = ("GET",)


class ReadOnlyViolation(RuntimeError):
    """Raised if a non-read-only ARM request is attempted."""


class ArmApiError(RuntimeError):
    """Raised when ARM returns an error response."""


class ArmSession:
    """Minimal, GET-only ARM REST client.

    ``credential`` and ``http`` are injectable for tests; by default they are
    built from ``azure.identity.DefaultAzureCredential`` and ``requests``.
    """

    def __init__(self, subscription_id: str | None = None, credential=None, http=None):
        if credential is None:
            from azure.identity import DefaultAzureCredential  # lazy; optional dependency

            credential = DefaultAzureCredential()
        if http is None:
            import requests  # lazy; optional dependency

            http = requests.Session()
        self._credential = credential
        self._http = http
        self._subscription_id = subscription_id
        self._token: str | None = None
        self._token_expires: float = 0.0

    # --- Auth ---------------------------------------------------------------

    def _bearer(self) -> str:
        if self._token is None or time.time() > self._token_expires - 300:
            token = self._credential.get_token(ARM_SCOPE)
            self._token = token.token
            self._token_expires = float(getattr(token, "expires_on", time.time() + 900))
        return self._token

    # --- Guarded transport ---------------------------------------------------

    def request(self, method: str, path: str, api_version: str | None = None, params: dict | None = None) -> dict:
        """Single choke point for every ARM call; only GET is permitted."""
        if method.upper() not in READ_ONLY_METHODS:
            raise ReadOnlyViolation(
                f"Blocked non-read-only ARM request '{method} {path}'. CSAF performs read-only assessment."
            )
        url = path if path.startswith("https://") else f"{ARM_BASE}{path}"
        query = dict(params or {})
        if api_version:
            query["api-version"] = api_version
        response = self._http.get(url, headers={"Authorization": f"Bearer {self._bearer()}"}, params=query, timeout=60)
        if response.status_code >= 400:
            raise ArmApiError(f"ARM GET {path} failed: HTTP {response.status_code}: {response.text[:300]}")
        return response.json()

    def get(self, path: str, api_version: str, params: dict | None = None) -> dict:
        return self.request("GET", path, api_version, params)

    def get_value(self, path: str, api_version: str, params: dict | None = None) -> list[dict]:
        """GET a collection endpoint, following ``nextLink`` pagination."""
        data = self.get(path, api_version, params)
        items = list(data.get("value", []))
        next_link = data.get("nextLink")
        while next_link:
            data = self.request("GET", next_link)  # nextLink already carries the api-version
            items.extend(data.get("value", []))
            next_link = data.get("nextLink")
        return items

    # --- Identity -------------------------------------------------------------

    @property
    def subscription_id(self) -> str:
        """Resolve the target subscription, discovering it when unambiguous."""
        if not self._subscription_id:
            subscriptions = self.get_value("/subscriptions", "2022-12-01")
            enabled = [s for s in subscriptions if s.get("state") == "Enabled"]
            if not enabled:
                raise RuntimeError("No enabled Azure subscription is visible to these credentials.")
            if len(enabled) > 1:
                ids = ", ".join(s.get("subscriptionId", "?") for s in enabled)
                raise RuntimeError(f"Multiple subscriptions visible ({ids}); pass --subscription to choose one.")
            self._subscription_id = enabled[0]["subscriptionId"]
        return self._subscription_id
