#!/usr/bin/env python3
"""Sign an engagement authorization file with a shared-secret key.

The signature binds the engagement's content (scope, window, approval flag,
attestations) to a key held by the approver, so a later silent edit to
``activeValidationApproved`` is detectable: verification fails and CSAF
refuses to run Validation/AdversarySimulation (see
``csaf/engagement_signing.py`` and ``Engagement.verify_signature``).

This does not encrypt or restrict who can *read* the file - it only lets
CSAF detect whether the content changed after an approver signed it.

Usage
-----
Generate a key once and keep it secret (share out of band with the operator):
    python3 -c "import secrets; open('engagement.key','wb').write(secrets.token_bytes(32))"

Sign (or re-sign after an approved edit) an engagement file in place:
    python3 sign_engagement.py --engagement engagement.json --key-file engagement.key

Verify without running an assessment:
    python3 sign_engagement.py --engagement engagement.json --key-file engagement.key --verify-only
"""

from __future__ import annotations

import argparse
import json
import sys

from csaf.engagement_signing import sign, verify


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engagement", required=True, help="Path to the engagement JSON file.")
    parser.add_argument("--key-file", required=True, help="Path to the shared-secret key file.")
    parser.add_argument(
        "--output", default=None, help="Write the signed file here instead of overwriting --engagement."
    )
    parser.add_argument(
        "--verify-only", action="store_true", help="Only verify the existing signature; do not sign or write."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    with open(args.key_file, "rb") as handle:
        key = handle.read().strip()
    if not key:
        print("[FAIL] Engagement signing key file is empty.", file=sys.stderr)
        return 1
    with open(args.engagement, encoding="utf-8") as handle:
        data = json.load(handle)

    existing_signature = data.get("signature")
    content = {k: v for k, v in data.items() if k != "signature"}

    if args.verify_only:
        ok = verify(content, existing_signature, key)
        print(f"[{'OK' if ok else 'FAIL'}] Signature {'verifies' if ok else 'does not verify'} against this key.")
        return 0 if ok else 1

    data["signature"] = sign(content, key)
    output_path = args.output or args.engagement
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    print(f"[OK] Signed {args.engagement} -> {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
