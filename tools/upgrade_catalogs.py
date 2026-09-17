#!/usr/bin/env python3
"""One-shot 2026 catalog/baseline refresh. Safe to re-run (idempotent mappings)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = ROOT / "controls"

CATEGORY_EXTRA = {
    "Identity": ("PR.AA", "CC6.1", "SEC"),
    "PrivilegedAccess": ("PR.AA", "CC6.3", "SEC"),
    "DataProtection": ("PR.DS", "CC6.7", "SEC"),
    "Compute": ("PR.PS", "CC6.1", "SEC"),
    "Network": ("PR.IR", "CC6.6", "SEC"),
    "Logging": ("DE.CM", "CC7.2", "OPS"),
    "Detection": ("DE.CM", "CC7.2", "SEC"),
    "Secrets": ("PR.DS", "CC6.1", "SEC"),
    "Operations": ("GV.OC", "CC9.1", "REL"),
    "RBAC": ("PR.AA", "CC6.3", "SEC"),
    "Pod Security": ("PR.PS", "CC6.1", "SEC"),
}

WA_PREFIX = {"AWS": "WA-AWS", "Azure": "WA-Azure", "GCP": "WA-GCP"}

NEW_AWS = [
    {
        "id": "CSAF-AWS-LOG-006",
        "title": "Security Hub CSPM is enabled",
        "category": "Detection",
        "module": "logging",
        "check": "securityhub_enabled",
        "defaultSeverity": "HIGH",
        "expectedState": "AWS Security Hub CSPM is enabled in the assessed region.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": [
            "CIS-AWS:1.2",
            "NIST-800-53:SI-4",
            "NIST-CSF-2.0:DE.CM",
            "SOC2:CC7.2",
            "WA-AWS:SEC",
            "MITRE:DS0015",
        ],
        "references": ["https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html"],
    },
    {
        "id": "CSAF-AWS-EC2-004",
        "title": "EBS volumes are encrypted",
        "category": "Compute",
        "module": "compute",
        "check": "ebs_volumes_encrypted",
        "defaultSeverity": "HIGH",
        "expectedState": "Every EBS volume is encrypted at rest.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": [
            "CIS-AWS:2.2.1",
            "NIST-800-53:SC-28",
            "NIST-CSF-2.0:PR.DS",
            "SOC2:CC6.7",
            "WA-AWS:SEC",
        ],
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
    },
]

NEW_K8S = [
    {
        "id": "CSAF-K8S-POD-003",
        "title": "Workloads do not use hostPID",
        "category": "Pod Security",
        "module": "pods",
        "check": "host_pid_pods",
        "defaultSeverity": "HIGH",
        "expectedState": "No workload pod sets hostPID: true.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": ["CIS-Kubernetes:5.2.2", "NIST-CSF-2.0:PR.PS", "SOC2:CC6.1", "MITRE:T1611"],
        "references": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    },
    {
        "id": "CSAF-K8S-POD-004",
        "title": "Workloads do not use hostIPC",
        "category": "Pod Security",
        "module": "pods",
        "check": "host_ipc_pods",
        "defaultSeverity": "MEDIUM",
        "expectedState": "No workload pod sets hostIPC: true.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": ["CIS-Kubernetes:5.2.3", "NIST-CSF-2.0:PR.PS", "SOC2:CC6.1"],
        "references": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    },
    {
        "id": "CSAF-K8S-POD-005",
        "title": "Workloads do not mount hostPath volumes",
        "category": "Pod Security",
        "module": "pods",
        "check": "host_path_volumes",
        "defaultSeverity": "HIGH",
        "expectedState": "No workload pod mounts a hostPath volume.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": ["CIS-Kubernetes:5.2.6", "NIST-CSF-2.0:PR.PS", "SOC2:CC6.1", "MITRE:T1611"],
        "references": ["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"],
    },
    {
        "id": "CSAF-K8S-POD-006",
        "title": "Containers do not allow privilege escalation",
        "category": "Pod Security",
        "module": "pods",
        "check": "privilege_escalation",
        "defaultSeverity": "HIGH",
        "expectedState": "No container sets allowPrivilegeEscalation: true.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": ["CIS-Kubernetes:5.2.5", "NIST-CSF-2.0:PR.PS", "SOC2:CC6.1", "MITRE:T1548"],
        "references": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    },
    {
        "id": "CSAF-K8S-SA-001",
        "title": "Default service accounts do not automount tokens",
        "category": "RBAC",
        "module": "service_accounts",
        "check": "default_sa_automount",
        "defaultSeverity": "MEDIUM",
        "expectedState": "The default service account in every workload namespace sets automountServiceAccountToken: false.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": ["CIS-Kubernetes:5.1.5", "NIST-CSF-2.0:PR.AA", "SOC2:CC6.1", "MITRE:T1078.004"],
        "references": ["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"],
    },
    {
        "id": "CSAF-K8S-RBAC-002",
        "title": "No non-system subject is bound to a wildcard ClusterRole",
        "category": "RBAC",
        "module": "rbac",
        "check": "wildcard_verbs",
        "defaultSeverity": "HIGH",
        "expectedState": "ClusterRoleBindings for non-system subjects do not reference ClusterRoles that grant * verbs or * resources.",
        "profiles": ["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        "mappings": ["CIS-Kubernetes:5.1.1", "NIST-CSF-2.0:PR.AA", "SOC2:CC6.3", "MITRE:T1078.004"],
        "references": ["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
    },
]


def _extra_mappings(cloud: str, category: str) -> list[str]:
    csf, soc, pillar = CATEGORY_EXTRA.get(category, ("PR.PS", "CC6.1", "SEC"))
    extra = [f"NIST-CSF-2.0:{csf}", f"SOC2:{soc}"]
    prefix = WA_PREFIX.get(cloud)
    if prefix:
        extra.append(f"{prefix}:{pillar}")
    return extra


def _refresh_control(cloud: str, control: dict) -> None:
    if "Assessment" in control.get("profiles", []) and "Inventory" not in control["profiles"]:
        if not control.get("validationOnly"):
            control["profiles"] = ["Inventory", *control["profiles"]]
    mappings = list(control.get("mappings") or [])
    for item in _extra_mappings(cloud, control.get("category", "")):
        if item not in mappings:
            mappings.append(item)
    control["mappings"] = mappings


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _append_new(controls: list[dict], newcomers: list[dict]) -> None:
    existing = {c["id"] for c in controls}
    for item in newcomers:
        if item["id"] not in existing:
            controls.append(item)


def refresh_catalogs() -> None:
    mapping = {
        "control-catalog.json": ("AWS", NEW_AWS),
        "control-catalog-azure.json": ("Azure", []),
        "control-catalog-gcp.json": ("GCP", []),
        "control-catalog-k8s.json": ("K8s", NEW_K8S),
    }
    for name, (cloud, newcomers) in mapping.items():
        path = CONTROLS / name
        data = _load(path)
        data["catalogVersion"] = "2026.2"
        for control in data["controls"]:
            _refresh_control(cloud, control)
        _append_new(data["controls"], newcomers)
        _dump(path, data)
        print(f"{name}: {len(data['controls'])} controls")


def refresh_baselines() -> None:
    renames = {
        "aws-cis-1.5.json": ("aws-cis-5.0.json", "aws-cis-5.0", "AWS CIS Foundations Benchmark v5.0 aligned baseline"),
        "azure-cis-2.0.json": (
            "azure-cis-6.0.json",
            "azure-cis-6.0",
            "CIS Microsoft Azure Foundations Benchmark v6.0 aligned baseline",
        ),
        "gcp-cis-1.3.json": (
            "gcp-cis-5.0.json",
            "gcp-cis-5.0",
            "CIS Google Cloud Platform Foundations Benchmark v5.0 aligned baseline",
        ),
        "k8s-cis-1.8.json": ("k8s-cis-1.11.json", "k8s-cis-1.11", "CIS Kubernetes Benchmark v1.11 aligned baseline"),
    }
    base = ROOT / "baselines"
    for old_name, (new_name, baseline_id, title) in renames.items():
        src = base / old_name
        dest = base / new_name
        if src.exists() and not dest.exists():
            shutil.move(str(src), str(dest))
        elif dest.exists() and src.exists() and src != dest:
            src.unlink()
        data = _load(dest)
        data["baselineId"] = baseline_id
        data["title"] = title
        data["version"] = "2026.2"
        _dump(dest, data)
        print(f"baseline {new_name}")


def refresh_schema_ids() -> None:
    prefix = "https://raw.githubusercontent.com/rikterskale/Cloud-Security-Assessment-Framework/main/schemas/"
    for path in (ROOT / "schemas").glob("*.json"):
        text = path.read_text(encoding="utf-8")
        if "example.invalid" in text:
            text = text.replace("https://example.invalid/csaf/", prefix)
            path.write_text(text, encoding="utf-8")
            print(f"schema $id {path.name}")


def main() -> None:
    refresh_catalogs()
    refresh_baselines()
    refresh_schema_ids()


if __name__ == "__main__":
    main()
