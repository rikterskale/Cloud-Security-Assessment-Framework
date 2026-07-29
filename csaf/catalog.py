"""Declarative control catalog loading and profile filtering."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .model import SEVERITIES

VALID_PROFILES = ["Inventory", "Assessment", "Validation", "AdversarySimulation"]


@dataclass
class Control:
    id: str
    title: str
    category: str
    module: str
    check: str
    default_severity: str
    expected_state: str
    profiles: list[str]
    mappings: list[str]
    references: list[str]
    validation_only: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Control":
        severity = data.get("defaultSeverity", "INFO")
        if severity not in SEVERITIES:
            raise ValueError(f"Control {data.get('id')} has invalid severity {severity!r}")
        return cls(
            id=data["id"],
            title=data["title"],
            category=data["category"],
            module=data["module"],
            check=data["check"],
            default_severity=severity,
            expected_state=data.get("expectedState", ""),
            profiles=data.get("profiles", []),
            mappings=data.get("mappings", []),
            references=data.get("references", []),
            validation_only=bool(data.get("validationOnly", False)),
        )


@dataclass
class Catalog:
    catalog_version: str
    cloud: str
    controls: list[Control]

    @classmethod
    def load(cls, path: str | Path) -> "Catalog":
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        controls = [Control.from_dict(item) for item in data.get("controls", [])]
        ids = [c.id for c in controls]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"Duplicate control IDs in catalog: {sorted(duplicates)}")
        return cls(
            catalog_version=data.get("catalogVersion", "unknown"),
            cloud=data.get("cloud", "AWS"),
            controls=controls,
        )

    def for_profile(self, profile: str) -> list[Control]:
        """Controls selected for a profile.

        Validation-only controls are excluded from Assessment and Inventory.
        AdversarySimulation further narrows Validation's set to only controls
        mapped to a MITRE ATT&CK technique: it exists to prioritize what an
        adversary-emulation exercise cares about, not to duplicate Validation
        under a different name.
        """
        if profile not in VALID_PROFILES:
            raise ValueError(f"Unknown profile: {profile!r}")
        selected = [c for c in self.controls if profile in c.profiles]
        if profile in ("Inventory", "Assessment"):
            selected = [c for c in selected if not c.validation_only]
        if profile == "AdversarySimulation":
            selected = [c for c in selected if any(m.startswith("MITRE:") for m in c.mappings)]
        return selected

    def by_module(self, controls: list[Control]) -> dict[str, list[Control]]:
        grouped: dict[str, list[Control]] = {}
        for control in controls:
            grouped.setdefault(control.module, []).append(control)
        return grouped
