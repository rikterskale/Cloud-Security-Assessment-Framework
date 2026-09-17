# Changelog

All notable changes to CSAF are documented here.

The Python distribution name is **cloud-saf**. The import package remains `csaf`.
Do not `pip install csaf` — that is the OASIS Common Security Advisory Framework.

## 1.1.0 — 2026-09-17

First tagged GitHub Release, PyPI publish (`cloud-saf`), and GHCR image
`ghcr.io/rikterskale/cloud-saf:1.1.0`.

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
- README five-minute path leads with `scripts/install.py`; packaged installers are `pipx install cloud-saf==1.1.0` and `ghcr.io/rikterskale/cloud-saf:1.1.0`.
- AWS `CIS-AWS:*` mappings retargeted to CIS Foundations Benchmark v5.0.0 recommendation numbers.
- Live AWS preflight probes the read APIs the scan uses (S3, EC2, CloudTrail, Config, GuardDuty, Security Hub, KMS, RDS, Secrets Manager), not only STS and IAM summary.
- CLI prints severity-ranked findings with remediation after a run.
- `scripts/install.py` bootstraps pip, uses text preflight, and verifies `csaf-assess --version` before the demo run.
- Live Azure/GCP/Kubernetes preflight probes the read APIs the scan uses (ARM storage/NSG/VM/Key Vault/SQL/RBAC/diagnostics; GCP IAM/storage/compute/logging/KMS/SQL; Kubernetes pods/RBAC/NetworkPolicy), not only identity.
- Runner fatals (unauthorized profile/scope, unknown cloud, multi-account AWS, secret-discovery) emit `CsafError` cause, resource, and fix.

### Deprecated

- None.

### Fixed

- `test_dependencies.py` now uses packaged catalogs so an installed wheel preflight succeeds.
- Shell completions are UTF-8 LF (they had been committed as UTF-16 LE, which failed the CI completions gate).
- Homebrew formula includes `Language::Python::Virtualenv`.
- Live preflight Azure/GCP/Kubernetes grant steps point at `--guide` instead of a mutating one-liner as the only fix.
