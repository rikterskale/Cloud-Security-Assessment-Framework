"""Attested evidence bundles (OFF-FEAT-007).

The run ``manifest.json`` already records a SHA-256 of every artifact, so it is
a tamper-evident *inventory*. This module adds an optional **attestation**: an
HMAC-SHA256 signature over that manifest, written as ``attestation.json``. With
it, a reviewer who holds the shared key can prove two things at once:

1. the manifest itself was not altered after the run (signature check), and
2. no artifact was changed after the run (every recorded hash still matches).

This reuses CSAF's existing HMAC primitives (:mod:`csaf.engagement_signing`)
and its scope is the same: an approver and an operator sharing one key out of
band, not third-party PKI verification. Use sigstore/cosign or an X.509 scheme
if bundles must be verified by parties without the shared key.

The attestation is created *after* the manifest and is therefore intentionally
not one of the manifest's hashed artifacts; it signs the manifest, so it cannot
be inside it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engagement_signing import sign, verify
from .evidence import sha256_file
from .io_utils import atomic_text_writer
from .model import utcnow_iso

ATTESTATION_NAME = "attestation.json"
MANIFEST_NAME = "manifest.json"
ATTESTATION_VERSION = 1


def _load_key(path: str | Path) -> bytes:
    key = Path(path).read_bytes().strip()
    if not key:
        raise ValueError("Attestation key file is empty.")
    return key


def build_attestation(manifest: dict, manifest_sha256: str, key: bytes) -> dict:
    """Return the attestation object signing ``manifest``."""
    return {
        "AttestationVersion": ATTESTATION_VERSION,
        "Algorithm": "HMAC-SHA256",
        "ManifestName": MANIFEST_NAME,
        "ManifestSha256": manifest_sha256,
        "ArtifactCount": manifest.get("ArtifactCount", len(manifest.get("Artifacts", []))),
        "SignedAtUtc": utcnow_iso(),
        "Signature": sign(manifest, key),
        "Note": (
            "HMAC-SHA256 over the canonicalized manifest.json. Verifies manifest integrity "
            "and, via the manifest's per-artifact hashes, the whole run bundle."
        ),
    }


def write_attestation(root: Path, key: bytes) -> Path:
    """Read ``manifest.json`` under ``root`` and write ``attestation.json``."""
    root = Path(root)
    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    attestation = build_attestation(manifest, sha256_file(manifest_path), key)
    path = root / ATTESTATION_NAME
    with atomic_text_writer(path) as handle:
        json.dump(attestation, handle, indent=2)
    return path


def verify_bundle(root: Path, key: bytes) -> tuple[bool, list[str]]:
    """Verify a run directory's attestation and every artifact hash.

    Returns ``(ok, messages)``. ``ok`` is True only when the manifest signature
    verifies, the manifest file hash matches, and every artifact's current hash
    equals the manifest's recorded hash.
    """
    root = Path(root)
    messages: list[str] = []
    manifest_path = root / MANIFEST_NAME
    attestation_path = root / ATTESTATION_NAME
    if not manifest_path.is_file():
        return False, [f"missing {MANIFEST_NAME}"]
    if not attestation_path.is_file():
        return False, [f"missing {ATTESTATION_NAME}"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))

    ok = True

    # 1. Manifest file integrity (fast check independent of the signature).
    current_manifest_hash = sha256_file(manifest_path)
    if current_manifest_hash != attestation.get("ManifestSha256"):
        ok = False
        messages.append("manifest.json hash does not match the attestation")

    # 2. Signature over the manifest content.
    if not verify(manifest, attestation.get("Signature"), key):
        ok = False
        messages.append("attestation signature does not verify against this key")

    # 3. Every recorded artifact still matches.
    for artifact in manifest.get("Artifacts", []):
        rel = artifact.get("RelativePath", artifact.get("FileName", ""))
        artifact_path = root / rel
        if not artifact_path.is_file():
            ok = False
            messages.append(f"missing artifact: {rel}")
            continue
        if sha256_file(artifact_path) != artifact.get("SHA256"):
            ok = False
            messages.append(f"artifact changed since the run: {rel}")

    if ok:
        messages.append(
            f"verified: manifest signature OK and all {len(manifest.get('Artifacts', []))} artifacts match"
        )
    return ok, messages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign or verify a CSAF run's evidence bundle (attestation.json).")
    sub = parser.add_subparsers(dest="command", required=True)

    sign_p = sub.add_parser("sign", help="Write attestation.json over a run's manifest.json.")
    sign_p.add_argument("run_dir", help="Path to a completed assessment run directory.")
    sign_p.add_argument("--key-file", required=True, help="Path to the shared-secret key file.")

    verify_p = sub.add_parser("verify", help="Verify a run's attestation and every artifact hash.")
    verify_p.add_argument("run_dir", help="Path to a completed assessment run directory.")
    verify_p.add_argument("--key-file", required=True, help="Path to the shared-secret key file.")

    external_sign_p = sub.add_parser("external-sign", help="Create a keyless Cosign signature and run SBOM.")
    external_sign_p.add_argument("run_dir")
    external_sign_p.add_argument("--cosign", default="cosign", help="Cosign executable (default: cosign).")
    external_verify_p = sub.add_parser("external-verify", help="Verify a Cosign-signed bundle without an HMAC key.")
    external_verify_p.add_argument("run_dir")
    external_verify_p.add_argument("--certificate-identity", required=True)
    external_verify_p.add_argument("--certificate-oidc-issuer", required=True)
    external_verify_p.add_argument("--cosign", default="cosign", help="Cosign executable (default: cosign).")

    args = parser.parse_args(argv)
    if args.command.startswith("external-"):
        from .external_verification import external_sign, external_verify

        if args.command == "external-sign":
            paths = external_sign(args.run_dir, cosign=args.cosign)
            print(f"[OK] Wrote external verification bundle: {paths['bundle']}")
            return 0
        ok, messages = external_verify(
            args.run_dir, identity=args.certificate_identity, issuer=args.certificate_oidc_issuer, cosign=args.cosign
        )
        for message in messages:
            print(("[OK] " if ok else "[FAIL] ") + message)
        return 0 if ok else 1

    key = _load_key(args.key_file)

    if args.command == "sign":
        path = write_attestation(Path(args.run_dir), key)
        print(f"[OK] Wrote {path}")
        return 0

    ok, messages = verify_bundle(Path(args.run_dir), key)
    for message in messages:
        print(("[OK] " if ok else "[FAIL] ") + message)
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
