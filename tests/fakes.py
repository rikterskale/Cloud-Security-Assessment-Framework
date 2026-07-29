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
