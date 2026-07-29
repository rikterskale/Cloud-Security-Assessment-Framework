"""Read-only Google Cloud REST session.

Talks to the Google Cloud REST APIs directly using Application Default
Credentials from ``google-auth`` (an optional dependency, imported lazily).
The guardrail is structural: every request funnels through
:meth:`GcpSession.request`, which permits GET plus an explicit allow-list of
read-only POST endpoints (``:getIamPolicy`` / ``:testIamPermissions``), which
Google exposes as POST but which only read state. This sits on top of the
read-only IAM role (e.g. ``roles/viewer``) an operator is expected to use.
"""

from __future__ import annotations

# POST endpoints that are read-only by contract despite the verb.
READ_ONLY_POST_SUFFIXES = (":getIamPolicy", ":testIamPermissions", ":searchAll")


class ReadOnlyViolation(RuntimeError):
    """Raised if a non-read-only GCP request is attempted."""


class GcpApiError(RuntimeError):
    """Raised when a Google Cloud API returns an error response."""


class GcpSession:
    """Minimal read-only Google Cloud REST client.

    ``http`` is injectable for tests; by default it is an
    ``google.auth.transport.requests.AuthorizedSession`` built from Application
    Default Credentials.
    """

    def __init__(self, project_id: str | None = None, http=None):
        if http is None:
            import google.auth  # lazy; optional dependency
            from google.auth.transport.requests import AuthorizedSession

            credentials, default_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            http = AuthorizedSession(credentials)
            if not project_id:
                project_id = default_project
        self._http = http
        self._project_id = project_id

    @property
    def project_id(self) -> str:
        if not self._project_id:
            raise RuntimeError(
                "No GCP project resolved; pass --project or configure a default project for "
                "Application Default Credentials."
            )
        return self._project_id

    # --- Guarded transport ---------------------------------------------------

    def request(self, method: str, url: str, params: dict | None = None, json_body: dict | None = None) -> dict:
        """Single choke point for every GCP call; GET plus read-only POSTs only."""
        method = method.upper()
        if method == "POST":
            path = url.split("?", 1)[0]
            if not path.endswith(READ_ONLY_POST_SUFFIXES):
                raise ReadOnlyViolation(
                    f"Blocked non-read-only GCP POST to '{path}'. CSAF performs read-only assessment."
                )
        elif method != "GET":
            raise ReadOnlyViolation(
                f"Blocked non-read-only GCP request '{method} {url}'. CSAF performs read-only assessment."
            )
        response = self._http.request(method, url, params=params, json=json_body, timeout=60)
        if response.status_code >= 400:
            raise GcpApiError(f"GCP {method} {url} failed: HTTP {response.status_code}: {response.text[:300]}")
        return response.json()

    def get(self, url: str, params: dict | None = None) -> dict:
        return self.request("GET", url, params=params)

    def post(self, url: str, json_body: dict | None = None) -> dict:
        return self.request("POST", url, json_body=json_body)

    def get_list(self, url: str, item_key: str, params: dict | None = None) -> list[dict]:
        """GET a collection endpoint, following ``nextPageToken`` pagination."""
        params = dict(params or {})
        items: list[dict] = []
        while True:
            data = self.get(url, params)
            items.extend(data.get(item_key, []) or [])
            token = data.get("nextPageToken")
            if not token:
                return items
            params["pageToken"] = token

    def get_aggregated(self, url: str, item_key: str, params: dict | None = None) -> list[dict]:
        """GET a compute ``aggregatedList`` endpoint, flattening per-scope items."""
        params = dict(params or {})
        items: list[dict] = []
        while True:
            data = self.get(url, params)
            for scope in (data.get("items") or {}).values():
                items.extend(scope.get(item_key, []) or [])
            token = data.get("nextPageToken")
            if not token:
                return items
            params["pageToken"] = token
