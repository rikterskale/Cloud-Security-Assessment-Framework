# Changelog

All notable changes to CSAF are documented here.

## Unreleased

### Added

- Packaged catalogs, baselines, and JSON Schemas for installed-wheel execution.
- Runtime JSON Schema validation for catalogs, baselines, and engagements.
- Unique run directories and atomic report/evidence/config writes.
- Hash-pinned dependency lockfile, installed-wheel CI smoke test, and tag-driven
  release workflow with checksums, CycloneDX SBOM, and GitHub attestations.

### Changed

- Active profiles now require a valid signed engagement, complete time window,
  explicit account/context scope, and explicit AWS region scope.
- Engagement cloud, account/context, and AWS region scope is enforced before
  provider evaluation; discovered provider identity is checked again afterward.
- `--output-dir` is now a parent directory containing one immutable run
  subdirectory per assessment.

### Fixed

- Kubernetes catalog metadata and control-ID schema patterns now conform to the
  same runtime contracts as AWS, Azure, and GCP.
