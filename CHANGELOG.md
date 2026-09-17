# Changelog

All notable changes to CSAF are documented here.

The Python distribution name is **cloud-saf**. The import package remains `csaf`.
Do not `pip install csaf` — that is the OASIS Common Security Advisory Framework.

## 1.1.0 — Unreleased

`pyproject.toml` declares version `1.1.0`. Tag `v1.1.0` when cutting the GitHub
Release, PyPI publish, and GHCR image.

### Added

- Cross-platform installer `scripts/install.py` (venv, locked deps, preflight, first assessment).
- Live read-only credential/API preflight (`--preflight --live`; automatic on live scans).
- Structured errors (`csaf/errors.py`) with cause, resource, and exact fix command.
- Optional extras: `cloud-saf[aws]`, `[azure]`, `[gcp]`, `[k8s]`, `[all]`. Core install is `jsonschema` only.
- Console-script alias `cloud-saf`.
- Inventory profile now selects Assessment controls and writes control results without findings.
- 2026 mappings: NIST CSF 2.0, SOC 2 TSC, AWS/Azure/GCP Well-Architected.
- CIS-aligned baselines retargeted: AWS 5.0, Azure 6.0, GCP 5.0, Kubernetes 1.11.
- New controls: Security Hub enabled, EBS volume encryption, six automated Kubernetes pod/RBAC/SA checks.
- Multi-scope Azure `--subscriptions`, GCP `--projects`, and campaign `targets` with automatic aggregate.
- `tools/sync_resources.py` packaged-resource drift gate, mypy CI job, GHCR publish, PyPI Trusted Publishing, Homebrew formula.

### Changed

- Distribution name renamed from `csaf` to `cloud-saf` to avoid the PyPI collision with OASIS CSAF.
- `--preflight` treats the selected cloud's SDK as required rather than optional.

### Deprecated

- None.

### Fixed

- `test_dependencies.py` now uses packaged catalogs so an installed wheel preflight succeeds.
