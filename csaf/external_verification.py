"""Cosign-backed, third-party verification for completed evidence bundles.

This is deliberately an opt-in companion feature.  It never contacts Sigstore
unless the operator explicitly invokes ``csaf-attest external-sign``.
"""

from __future__ import annotations

import importlib.metadata
import json
import subprocess
import uuid
from pathlib import Path

from .evidence import sha256_file
from .io_utils import atomic_text_writer
from .model import utcnow_iso

DESCRIPTOR = "external-verification.json"
SIGNATURE = "evidence-signature.sig"
BUNDLE = "evidence-signature.bundle"
SBOM = "run-sbom.cdx.json"


def write_run_sbom(root: str | Path) -> Path:
    """Write a CycloneDX JSON inventory of the runtime that produced a bundle."""
    root = Path(root)
    components = [
        {"type": "library", "name": dist.metadata["Name"], "version": dist.version}
        for dist in importlib.metadata.distributions()
        if dist.metadata.get("Name")
    ]
    components.sort(key=lambda item: item["name"].lower())
    manifest = root / "manifest.json"
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, sha256_file(manifest))}",
        "version": 1,
        "metadata": {"timestamp": utcnow_iso(), "component": {"type": "application", "name": "CSAF assessment run"}},
        "components": components,
    }
    path = root / SBOM
    with atomic_text_writer(path) as handle:
        json.dump(payload, handle, indent=2)
    return path


def write_descriptor(root: str | Path) -> Path:
    """Bind the manifest and run SBOM together before external signing."""
    root = Path(root)
    manifest, sbom = root / "manifest.json", root / SBOM
    if not manifest.is_file():
        raise FileNotFoundError(f"missing {manifest}")
    if not sbom.is_file():
        write_run_sbom(root)
    payload = {
        "VerificationVersion": 1,
        "CreatedAtUtc": utcnow_iso(),
        "Artifacts": [
            {"path": "manifest.json", "sha256": sha256_file(manifest)},
            {"path": SBOM, "sha256": sha256_file(sbom)},
        ],
        "Note": "Cosign signs this descriptor; manifest.json binds all assessment artifacts.",
    }
    path = root / DESCRIPTOR
    with atomic_text_writer(path) as handle:
        json.dump(payload, handle, indent=2)
    return path


def external_sign(root: str | Path, *, cosign: str = "cosign") -> dict:
    """Create a keyless Cosign signature and bundle over the verification descriptor."""
    root = Path(root)
    descriptor = write_descriptor(root)
    signature, bundle = root / SIGNATURE, root / BUNDLE
    subprocess.run(
        [cosign, "sign-blob", "--yes", "--output-signature", str(signature), "--bundle", str(bundle), str(descriptor)],
        check=True,
    )
    return {
        "descriptor": str(descriptor),
        "signature": str(signature),
        "bundle": str(bundle),
        "sbom": str(root / SBOM),
    }


def external_verify(root: str | Path, *, identity: str, issuer: str, cosign: str = "cosign") -> tuple[bool, list[str]]:
    """Verify local descriptor hashes and the Cosign identity-bound signature."""
    root = Path(root)
    descriptor, bundle = root / DESCRIPTOR, root / BUNDLE
    if not descriptor.is_file() or not bundle.is_file():
        return False, [f"missing {DESCRIPTOR} or {BUNDLE}"]
    data = json.loads(descriptor.read_text(encoding="utf-8"))
    messages, ok = [], True
    for artifact in data.get("Artifacts", []):
        path = root / artifact["path"]
        if not path.is_file() or sha256_file(path) != artifact["sha256"]:
            ok = False
            messages.append(f"artifact does not match descriptor: {artifact['path']}")
    try:
        subprocess.run(
            [
                cosign,
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                issuer,
                str(descriptor),
            ],
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        ok = False
        messages.append(f"Cosign verification failed: {exc}")
    if ok:
        messages.append("verified: Cosign identity, descriptor, manifest, and run SBOM match")
    return ok, messages
