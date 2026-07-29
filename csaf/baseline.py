"""Baseline thresholds consumed by check functions."""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_THRESHOLDS = {
    "passwordMinLength": 14,
    "passwordRequireSymbols": True,
    "passwordRequireNumbers": True,
    "passwordRequireUppercase": True,
    "passwordRequireLowercase": True,
    "passwordMaxAgeDays": 90,
    "passwordReusePrevention": 24,
    "accessKeyMaxAgeDays": 90,
    "credentialInactivityDays": 90,
    "rootActivityThresholdDays": 30,
    "sensitiveIngressPorts": [22, 3389],
    "requireImdsV2": True,
    "requireEbsDefaultEncryption": True,
    "requireMultiRegionCloudTrail": True,
    "requireGuardDuty": True,
    "requireConfig": True,
    "requireKmsKeyRotation": True,
}


class Baseline:
    def __init__(self, data: dict | None = None) -> None:
        data = data or {}
        self.baseline_id = data.get("baselineId", "default")
        self.thresholds = {**DEFAULT_THRESHOLDS, **data.get("thresholds", {})}
        self.severity_overrides = data.get("severityOverrides", {})
        self.not_applicable_controls = set(data.get("notApplicableControls", []))

    @classmethod
    def load(cls, path: str | Path | None) -> "Baseline":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    def get(self, key: str, default=None):
        return self.thresholds.get(key, default)

    def severity_for(self, control_id: str, default_severity: str) -> str:
        return self.severity_overrides.get(control_id, default_severity)
