"""Shared test doubles for exercising AWS check modules without boto3.

``FakeClient`` serves canned responses per API operation; a value may be a
plain dict, an ``Exception`` instance (raised on call), or a callable taking
the call kwargs (for per-resource behaviour). Paginated operations are
registered separately as lists of pages (or a callable returning pages).

``make_ctx`` builds a fully-populated ``CheckContext`` backed by a real
``Baseline`` and ``EvidenceStore`` so evidence writes and threshold lookups
behave exactly as in production.
"""

from __future__ import annotations

from pathlib import Path

from csaf.baseline import Baseline
from csaf.catalog import Control
from csaf.clouds.base import CheckContext
from csaf.engagement import Engagement
from csaf.evidence import EvidenceStore


class NullLogger:
    """Logger stand-in that swallows everything."""

    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def close(self):
        pass


class FakePaginator:
    def __init__(self, pages, operation_name="", calls=None):
        self._pages = pages
        self._operation_name = operation_name
        self._calls = calls if calls is not None else []

    def paginate(self, **kwargs):
        self._calls.append((self._operation_name, kwargs))
        pages = self._pages(kwargs) if callable(self._pages) else self._pages
        return iter(pages)


class FakeClient:
    """Duck-typed boto3 client serving canned responses.

    ``responses`` maps operation name -> dict | Exception | callable(kwargs).
    ``pages`` maps paginated operation name -> list-of-pages | callable(kwargs).
    Every call is recorded in ``self.calls`` for assertion.
    """

    def __init__(self, responses=None, pages=None):
        self._responses = dict(responses or {})
        self._pages = dict(pages or {})
        self.calls = []

    def get_paginator(self, operation_name):
        return FakePaginator(self._pages[operation_name], operation_name, self.calls)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._responses:
            raise AttributeError(f"FakeClient has no canned response for operation {name!r}")
        value = self._responses[name]

        def call(**kwargs):
            self.calls.append((name, kwargs))
            outcome = value(kwargs) if callable(value) else value
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return call


class FakeSession:
    """Hands out FakeClients by service name, mirroring AwsSession.client()."""

    account_id = "111122223333"

    def __init__(self, clients=None):
        self._clients = dict(clients or {})

    def client(self, service, region=None):
        if service not in self._clients:
            raise KeyError(f"FakeSession has no client registered for service {service!r}")
        return self._clients[service]


def make_control(
    control_id="CSAF-AWS-TST-001",
    title="Test control",
    category="Test",
    module="test",
    check="check",
    severity="HIGH",
    expected="expected state",
    mappings=None,
    profiles=None,
    validation_only=False,
) -> Control:
    return Control(
        id=control_id,
        title=title,
        category=category,
        module=module,
        check=check,
        default_severity=severity,
        expected_state=expected,
        profiles=profiles or ["Assessment", "Validation"],
        mappings=mappings or [],
        references=[],
        validation_only=validation_only,
    )


def make_ctx(
    root: str | Path,
    clients=None,
    thresholds=None,
    baseline=None,
    engagement=None,
    region="global",
    profile="Assessment",
    cache=None,
) -> CheckContext:
    baseline = baseline or Baseline({"thresholds": thresholds or {}})
    return CheckContext(
        cloud="AWS",
        account_id=FakeSession.account_id,
        region=region,
        profile=profile,
        baseline=baseline,
        evidence=EvidenceStore(Path(root)),
        logger=NullLogger(),
        engagement=engagement or Engagement(),
        session=FakeSession(clients),
        cache=cache if cache is not None else {},
    )


def _resolve(value, arg):
    """Shared response resolution: Exception instances raise, callables receive arg."""
    if isinstance(value, Exception):
        raise value
    return value(arg) if callable(value) else value


class FakeArmSession:
    """Fake ArmSession serving canned responses keyed by exact request path.

    Mirrors ``csaf.clouds.azure.session.ArmSession``'s public surface
    (``get``/``get_value``) without any HTTP or credential dependency.
    """

    subscription_id = "sub-1"

    def __init__(self, get=None, get_value=None):
        self._get = dict(get or {})
        self._get_value = dict(get_value or {})
        self.calls = []

    def get(self, path, api_version=None, params=None):
        self.calls.append(("get", path, params))
        if path not in self._get:
            raise KeyError(f"FakeArmSession has no canned response for GET {path!r}")
        return _resolve(self._get[path], params)

    def get_value(self, path, api_version=None, params=None):
        self.calls.append(("get_value", path, params))
        if path not in self._get_value:
            raise KeyError(f"FakeArmSession has no canned response for get_value {path!r}")
        return _resolve(self._get_value[path], params)


class FakeGcpSession:
    """Fake GcpSession serving canned responses keyed by exact request URL.

    Mirrors ``csaf.clouds.gcp.session.GcpSession``'s public surface
    (``get``/``get_list``/``get_aggregated``/``post``) without any HTTP or
    credential dependency.
    """

    project_id = "proj-1"

    def __init__(self, get=None, get_list=None, get_aggregated=None, post=None):
        self._get = dict(get or {})
        self._get_list = dict(get_list or {})
        self._get_aggregated = dict(get_aggregated or {})
        self._post = dict(post or {})
        self.calls = []

    def get(self, url, params=None):
        self.calls.append(("get", url, params))
        if url not in self._get:
            raise KeyError(f"FakeGcpSession has no canned response for GET {url!r}")
        return _resolve(self._get[url], params)

    def get_list(self, url, item_key, params=None):
        self.calls.append(("get_list", url, params))
        if url not in self._get_list:
            raise KeyError(f"FakeGcpSession has no canned response for get_list {url!r}")
        return _resolve(self._get_list[url], params)

    def get_aggregated(self, url, item_key, params=None):
        self.calls.append(("get_aggregated", url, params))
        if url not in self._get_aggregated:
            raise KeyError(f"FakeGcpSession has no canned response for get_aggregated {url!r}")
        return _resolve(self._get_aggregated[url], params)

    def post(self, url, json_body=None):
        self.calls.append(("post", url, json_body))
        if url not in self._post:
            raise KeyError(f"FakeGcpSession has no canned response for POST {url!r}")
        return _resolve(self._post[url], json_body)


def make_azure_ctx(
    root: str | Path,
    get=None,
    get_value=None,
    thresholds=None,
    engagement=None,
    cache=None,
) -> CheckContext:
    return CheckContext(
        cloud="Azure",
        account_id=FakeArmSession.subscription_id,
        region="global",
        profile="Assessment",
        baseline=Baseline({"thresholds": thresholds or {}}),
        evidence=EvidenceStore(Path(root)),
        logger=NullLogger(),
        engagement=engagement or Engagement(),
        session=FakeArmSession(get=get, get_value=get_value),
        cache=cache if cache is not None else {},
    )


def make_gcp_ctx(
    root: str | Path,
    get=None,
    get_list=None,
    get_aggregated=None,
    post=None,
    thresholds=None,
    engagement=None,
    cache=None,
) -> CheckContext:
    return CheckContext(
        cloud="GCP",
        account_id=FakeGcpSession.project_id,
        region="global",
        profile="Assessment",
        baseline=Baseline({"thresholds": thresholds or {}}),
        evidence=EvidenceStore(Path(root)),
        logger=NullLogger(),
        engagement=engagement or Engagement(),
        session=FakeGcpSession(get=get, get_list=get_list, get_aggregated=get_aggregated, post=post),
        cache=cache if cache is not None else {},
    )


class FakeK8sApiGroup:
    """Fake Kubernetes API group (e.g. ``rbac_v1``) serving canned responses.

    ``responses`` maps method name -> object | Exception | callable(kwargs).
    Every call is recorded in ``self.calls`` for assertion.
    """

    def __init__(self, responses=None):
        self._responses = dict(responses or {})
        self.calls = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._responses:
            raise AttributeError(f"FakeK8sApiGroup has no canned response for {name!r}")
        value = self._responses[name]

        def call(**kwargs):
            self.calls.append((name, kwargs))
            outcome = value(kwargs) if callable(value) else value
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return call


class FakeK8sSession:
    """Fake K8sSession handing out FakeK8sApiGroups by name, mirroring K8sSession.api()."""

    cluster_context = "test-cluster"

    def __init__(self, apis=None):
        self._apis = dict(apis or {})

    def api(self, name):
        if name not in self._apis:
            raise KeyError(f"FakeK8sSession has no API group registered for {name!r}")
        return self._apis[name]


def make_k8s_ctx(
    root: str | Path,
    apis=None,
    thresholds=None,
    engagement=None,
    cache=None,
) -> CheckContext:
    return CheckContext(
        cloud="K8s",
        account_id=FakeK8sSession.cluster_context,
        region="global",
        profile="Assessment",
        baseline=Baseline({"thresholds": thresholds or {}}),
        evidence=EvidenceStore(Path(root)),
        logger=NullLogger(),
        engagement=engagement or Engagement(),
        session=FakeK8sSession(apis=apis),
        cache=cache if cache is not None else {},
    )
