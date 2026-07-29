"""Evidence store and tamper-evident SHA-256 artifact manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import FRAMEWORK_VERSION, SCHEMA_VERSION
from .model import utcnow_iso


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


class EvidenceStore:
    """Namespaced, on-disk store for raw collector evidence."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, namespace: str, name: str, data) -> str:
        target_dir = self.evidence_dir / namespace
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / name
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, default=str)
        return str(path.relative_to(self.root))

    def write_text(self, namespace: str, name: str, text: str) -> str:
        target_dir = self.evidence_dir / namespace
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / name
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return str(path.relative_to(self.root))


def write_manifest(root: Path, cloud: str, account_scope: str, profile: str) -> Path:
    """Hash every artifact under ``root`` (except the manifest itself)."""
    root = Path(root)
    manifest_path = root / "manifest.json"
    artifacts = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            stat = path.stat()
            artifacts.append(
                {
                    "FileName": path.name,
                    "RelativePath": str(path.relative_to(root)).replace("\\", "/"),
                    "SHA256": sha256_file(path),
                    "ByteLength": stat.st_size,
                    "LastWriteTimeUtc": utcnow_iso(),
                }
            )
    manifest = {
        "SchemaVersion": SCHEMA_VERSION,
        "FrameworkVersion": FRAMEWORK_VERSION,
        "GeneratedAtUtc": utcnow_iso(),
        "Cloud": cloud,
        "AccountScope": account_scope,
        "AssessmentProfile": profile,
        "HashAlgorithm": "SHA256",
        "ConfidentialityNotice": (
            "This manifest proves artifact integrity only. It does not encrypt assessment evidence."
        ),
        "ArtifactCount": len(artifacts),
        "Artifacts": artifacts,
    }
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    return manifest_path
