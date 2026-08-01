"""Signed, replayable assessment campaigns (OFF-FEAT-001).

A *campaign* is a small, versioned JSON document that captures everything a run
needs — cloud, profile, regions, catalog/baseline overrides, scope references,
exports — so an authorized assessment can be reproduced later, by another
operator, with a single command instead of a long, error-prone flag list.

Campaigns can be HMAC-signed (reusing :mod:`csaf.engagement_signing`) so the
exact parameters an approver reviewed are bound to a shared key: an edit after
signing is detected and ``csaf-campaign run`` fails closed. This is the same
shared-secret model as engagement signing, not third-party PKI.

The command surface is a dedicated ``csaf-campaign`` script (``create``,
``sign``, ``verify``, ``run``) so the primary ``csaf-assess`` CLI stays
unchanged. ``run`` builds a :class:`csaf.runner.RunConfig` and executes it,
verifying the signature first when a key is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engagement_signing import sign, verify
from .model import utcnow_iso

CAMPAIGN_SCHEMA_VERSION = 1
VALID_CLOUDS = ["aws", "azure", "gcp", "k8s"]
VALID_PROFILES = ["Inventory", "Assessment", "Validation", "AdversarySimulation"]
VALID_EXPORTS = ["sarif", "oscal"]

# Campaign keys that map onto RunConfig fields.
_CONFIG_FIELDS = (
    "cloud",
    "profile",
    "regions",
    "catalog_path",
    "baseline_path",
    "engagement_path",
    "engagement_key_path",
    "aws_profile",
    "subscription_id",
    "project_id",
    "kube_context",
    "kubeconfig_path",
    "max_workers",
    "export",
    "self_check",
)


def build_campaign(
    *,
    campaign_id: str,
    cloud: str = "aws",
    profile: str = "Assessment",
    regions: list[str] | None = None,
    description: str = "",
    self_check: bool = False,
    export: list[str] | None = None,
    **config_overrides,
) -> dict:
    """Create an unsigned campaign document."""
    cloud = cloud.lower()
    if cloud not in VALID_CLOUDS:
        raise ValueError(f"cloud must be one of {VALID_CLOUDS}")
    if profile not in VALID_PROFILES:
        raise ValueError(f"profile must be one of {VALID_PROFILES}")
    for fmt in export or []:
        if fmt not in VALID_EXPORTS:
            raise ValueError(f"export must be a subset of {VALID_EXPORTS}")
    campaign = {
        "campaignSchemaVersion": CAMPAIGN_SCHEMA_VERSION,
        "campaignId": campaign_id,
        "description": description,
        "createdAtUtc": utcnow_iso(),
        "cloud": cloud,
        "profile": profile,
        "regions": list(regions or ["us-east-1"]),
        "selfCheck": bool(self_check),
        "export": list(export or []),
    }
    # Optional scope/override references, only included when provided.
    for key, value in config_overrides.items():
        if value is not None:
            campaign[key] = value
    return campaign


def _signable(campaign: dict) -> dict:
    return {k: v for k, v in campaign.items() if k != "signature"}


def sign_campaign(campaign: dict, key: bytes) -> dict:
    """Return a copy of ``campaign`` with an HMAC ``signature``."""
    signed = dict(campaign)
    signed["signature"] = sign(_signable(campaign), key)
    return signed


def verify_campaign(campaign: dict, key: bytes) -> bool:
    """Verify a signed campaign. Unsigned campaigns never verify."""
    return verify(_signable(campaign), campaign.get("signature"), key)


def validate_campaign(campaign: dict) -> list[str]:
    """Return a list of structural problems (empty == valid)."""
    problems: list[str] = []
    if campaign.get("campaignSchemaVersion") != CAMPAIGN_SCHEMA_VERSION:
        problems.append(f"campaignSchemaVersion must be {CAMPAIGN_SCHEMA_VERSION}")
    if not campaign.get("campaignId"):
        problems.append("campaignId is required")
    if campaign.get("cloud") not in VALID_CLOUDS:
        problems.append(f"cloud must be one of {VALID_CLOUDS}")
    if campaign.get("profile") not in VALID_PROFILES:
        problems.append(f"profile must be one of {VALID_PROFILES}")
    if not isinstance(campaign.get("regions", []), list):
        problems.append("regions must be a list")
    for fmt in campaign.get("export", []):
        if fmt not in VALID_EXPORTS:
            problems.append(f"export entry {fmt!r} is not one of {VALID_EXPORTS}")
    return problems


def to_run_config(campaign: dict, *, output_dir: str, log_level: str = "INFO", previous_findings: str | None = None):
    """Build a RunConfig from a campaign document."""
    from .runner import RunConfig

    kwargs = {
        "cloud": campaign.get("cloud", "aws"),
        "profile": campaign.get("profile", "Assessment"),
        "regions": list(campaign.get("regions", ["us-east-1"])),
        "self_check": bool(campaign.get("selfCheck", False)),
        "export": list(campaign.get("export", [])),
        "output_dir": output_dir,
        "log_level": log_level,
        "previous_findings_path": previous_findings,
    }
    for key in _CONFIG_FIELDS:
        if key in campaign and key not in kwargs:
            kwargs[key] = campaign[key]
    return RunConfig(**kwargs)


def load_campaign(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_campaign(campaign: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(campaign, indent=2) + "\n", encoding="utf-8")


# --- Console-script entry point --------------------------------------------


def _load_key(path: str) -> bytes:
    key = Path(path).read_bytes().strip()
    if not key:
        raise ValueError("Campaign key file is empty.")
    return key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create, sign, verify, or run a CSAF assessment campaign.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Write a new campaign file.")
    create.add_argument("output", help="Path to write the campaign JSON.")
    create.add_argument("--campaign-id", required=True)
    create.add_argument("--cloud", choices=VALID_CLOUDS, default="aws")
    create.add_argument("--profile", choices=VALID_PROFILES, default="Assessment")
    create.add_argument("--regions", nargs="+", default=["us-east-1"])
    create.add_argument("--description", default="")
    create.add_argument("--self-check", action="store_true")
    create.add_argument("--export", nargs="+", choices=VALID_EXPORTS, default=[])
    create.add_argument("--key-file", default=None, help="If given, sign the new campaign with this key.")

    sign_p = sub.add_parser("sign", help="Sign an existing campaign in place.")
    sign_p.add_argument("campaign")
    sign_p.add_argument("--key-file", required=True)

    verify_p = sub.add_parser("verify", help="Verify a campaign's signature and structure.")
    verify_p.add_argument("campaign")
    verify_p.add_argument("--key-file", required=True)

    run_p = sub.add_parser("run", help="Run an assessment from a campaign.")
    run_p.add_argument("campaign")
    run_p.add_argument("--key-file", default=None, help="Verify the signature before running (recommended).")
    run_p.add_argument("--output-dir", default="csaf-output")
    run_p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARN", "ERROR"])
    run_p.add_argument("--previous-findings", default=None)

    args = parser.parse_args(argv)

    if args.command == "create":
        campaign = build_campaign(
            campaign_id=args.campaign_id,
            cloud=args.cloud,
            profile=args.profile,
            regions=args.regions,
            description=args.description,
            self_check=args.self_check,
            export=args.export,
        )
        if args.key_file:
            campaign = sign_campaign(campaign, _load_key(args.key_file))
        save_campaign(campaign, args.output)
        print(f"[OK] Wrote campaign {args.output}" + (" (signed)" if args.key_file else " (unsigned)"))
        return 0

    campaign = load_campaign(args.campaign)
    problems = validate_campaign(campaign)
    if problems:
        for problem in problems:
            print(f"[FAIL] {problem}")
        return 1

    if args.command == "sign":
        signed = sign_campaign(campaign, _load_key(args.key_file))
        save_campaign(signed, args.campaign)
        print(f"[OK] Signed {args.campaign}")
        return 0

    if args.command == "verify":
        ok = verify_campaign(campaign, _load_key(args.key_file))
        print("[OK] Signature verifies." if ok else "[FAIL] Signature does not verify.")
        return 0 if ok else 1

    # run
    if args.key_file is not None:
        if not verify_campaign(campaign, _load_key(args.key_file)):
            print("[FAIL] Campaign signature does not verify; refusing to run.")
            return 1
    elif "signature" in campaign:
        print("[WARN] Campaign is signed but no --key-file was given; running without verifying.")

    from .runner import run_assessment

    config = to_run_config(
        campaign,
        output_dir=args.output_dir,
        log_level=args.log_level,
        previous_findings=args.previous_findings,
    )
    result = run_assessment(config)
    print(
        f"[{'OK' if result.exit_code == 0 else 'INCOMPLETE' if result.exit_code == 2 else 'FATAL'}] {result.message}"
    )
    print(f"[*] Output written to {result.output_dir}")
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
