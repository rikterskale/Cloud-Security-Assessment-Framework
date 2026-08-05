"""Continuous drift monitoring (OFF-FEAT-006).

Turns two CSAF runs into an actionable signal: given a previous and a current
``findings.json``, compute which findings are **new**, **resolved**, or
**persisted**, and decide whether to raise an alert. Because finding IDs are
deterministic and resource-aware (:func:`csaf.model.finding_id`), the same
weakness on the same resource correlates across runs.

This is a pure post-processing tool over artifacts CSAF already writes — no
cloud calls, no new trust boundary. The ``csaf-drift`` command exits non-zero
when the alert condition is met, so it drops straight into cron or CI:

    csaf-assess --self-check --output-dir today
    csaf-drift --previous yesterday/<run>/findings.json \\
               --current today/<run>/findings.json --alert-on new
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .console import next_steps
from .model import FINDING_SEVERITIES

_SEVERITY_RANK = {sev: rank for rank, sev in enumerate(FINDING_SEVERITIES)}  # LOW=0 .. CRITICAL=3


def _index(records: list[dict]) -> dict[str, dict]:
    return {record["FindingId"]: record for record in records if "FindingId" in record}


def compute_drift(previous: list[dict], current: list[dict]) -> dict:
    """Return a drift report comparing two findings lists by FindingId."""
    prev = _index(previous)
    curr = _index(current)
    prev_ids = set(prev)
    curr_ids = set(curr)

    def summarize(record: dict) -> dict:
        return {
            "FindingId": record.get("FindingId", ""),
            "ControlId": record.get("ControlId", ""),
            "Title": record.get("Title", ""),
            "Severity": record.get("Severity", ""),
            "ResourceId": record.get("ResourceId", ""),
        }

    new = [summarize(curr[i]) for i in sorted(curr_ids - prev_ids)]
    resolved = [summarize(prev[i]) for i in sorted(prev_ids - curr_ids)]
    persisted = sorted(curr_ids & prev_ids)

    def highest(items: list[dict]) -> str:
        return max((i["Severity"] for i in items), key=lambda s: _SEVERITY_RANK.get(s, -1), default="")

    return {
        "new": new,
        "resolved": resolved,
        "persistedCount": len(persisted),
        "counts": {"new": len(new), "resolved": len(resolved), "persisted": len(persisted)},
        "highestNewSeverity": highest(new),
        "highestResolvedSeverity": highest(resolved),
    }


def should_alert(drift: dict, alert_on: str) -> bool:
    """Decide whether to alert. ``alert_on`` in {new, resolved, any, none}."""
    counts = drift["counts"]
    if alert_on == "none":
        return False
    if alert_on == "new":
        return counts["new"] > 0
    if alert_on == "resolved":
        return counts["resolved"] > 0
    if alert_on == "any":
        return counts["new"] > 0 or counts["resolved"] > 0
    raise ValueError(f"alert_on must be one of new/resolved/any/none, got {alert_on!r}")


def _load(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def append_history(path: str | Path, drift: dict) -> None:
    """Append an immutable, line-oriented drift summary for time-series use."""
    record = {
        "observedAtUtc": datetime.now(timezone.utc).isoformat(),
        "counts": drift["counts"],
        "highestNewSeverity": drift["highestNewSeverity"],
    }
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def deliver_webhook(url: str, payload: dict, *, auth: str, secret: bytes, dry_run: bool = False) -> dict:
    """Deliver an explicit, minimal JSON alert using HMAC or bearer auth."""
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "CSAF-Drift-Monitor/1.0"}
    if auth == "hmac":
        headers["X-CSAF-Signature-256"] = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    else:
        headers["Authorization"] = "Bearer " + secret.decode("utf-8")
    if dry_run:
        return {"delivered": False, "headers": {key: "<redacted>" for key in headers}, "payload": payload}
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310 - explicit operator endpoint
        return {"delivered": True, "status": response.status}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two CSAF findings.json files and alert on drift (new/resolved findings)."
    )
    parser.add_argument("--previous", required=True, help="Path to the baseline run's findings.json.")
    parser.add_argument("--current", required=True, help="Path to the latest run's findings.json.")
    parser.add_argument("--alert-on", choices=["new", "resolved", "any", "none"], default="new")
    parser.add_argument("--out", default=None, help="Optional path to write the drift report JSON.")
    parser.add_argument("--quiet", action="store_true", help="Suppress the human-readable summary.")
    parser.add_argument("--history", default=None, help="Append a timestamped summary to this JSONL time-series file.")
    parser.add_argument(
        "--webhook-url", default=None, help="Explicit SIEM webhook URL; no network call is made without this flag."
    )
    parser.add_argument("--webhook-auth", choices=["hmac", "bearer"], default="hmac")
    parser.add_argument(
        "--webhook-secret-file", default=None, help="HMAC key or bearer token file (required with --webhook-url)."
    )
    parser.add_argument(
        "--webhook-dry-run", action="store_true", help="Print redacted webhook metadata without sending it."
    )
    args = parser.parse_args(argv)

    drift = compute_drift(_load(args.previous), _load(args.current))
    if args.out:
        Path(args.out).write_text(json.dumps(drift, indent=2) + "\n", encoding="utf-8")

    alert = should_alert(drift, args.alert_on)
    if args.history:
        append_history(args.history, drift)
    if args.webhook_url:
        if not args.webhook_secret_file:
            parser.error("--webhook-secret-file is required with --webhook-url")
        secret = Path(args.webhook_secret_file).read_bytes().strip()
        if not secret:
            parser.error("--webhook-secret-file is empty")
        delivery = deliver_webhook(
            args.webhook_url,
            {"event": "csaf.drift", "alert": alert, "alertOn": args.alert_on, "drift": drift},
            auth=args.webhook_auth,
            secret=secret,
            dry_run=args.webhook_dry_run,
        )
        if not args.quiet:
            print(
                "[WEBHOOK] dry run; no request sent."
                if args.webhook_dry_run
                else f"[WEBHOOK] delivered (HTTP {delivery['status']})."
            )
    if not args.quiet:
        counts = drift["counts"]
        print(f"Drift: {counts['new']} new, {counts['resolved']} resolved, {counts['persisted']} persisted.")
        for item in drift["new"]:
            print(f"  + NEW [{item['Severity']}] {item['ControlId']} {item['ResourceId']}")
        for item in drift["resolved"]:
            print(f"  - RESOLVED [{item['Severity']}] {item['ControlId']} {item['ResourceId']}")
        print(f"[{'ALERT' if alert else 'OK'}] alert-on={args.alert_on}")
        print(
            next_steps(
                "Review the listed findings, then retain this report as the next comparison baseline.",
                "The two run artifacts were compared locally.",
            )
        )
    return 1 if alert else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
