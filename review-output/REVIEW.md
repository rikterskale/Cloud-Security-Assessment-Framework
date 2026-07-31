# CSAF Repository Review

Review date: 2026-07-30  
Reviewer: Codex  
Mode: `REVIEW_ONLY`  
Checkout: `main`, `02bd67dd3761ca49db3b5416c9e2151bdf6cfe83`  
Declared release: `1.0.0`; no local tags were present, so the latest release could not be independently verified.

## 1. Executive Summary

CSAF is a read-only, multi-cloud security posture assessment framework. It loads declarative control catalogs and baselines, dispatches checks through AWS, Azure, GCP, or Kubernetes providers, writes findings/coverage/detection/report artifacts, and uses signed engagements for active validation profiles. The implementation is substantial and safety-oriented: provider transports enforce read-only verbs, active profiles require signed scoped engagements, artifacts are SHA-256 manifested, and CI builds/tests/audits/packages the project.

The checkout identifies itself as `1.0.0` in `pyproject.toml` and `csaf/__init__.py`. No tag or release metadata was available locally, so release parity is **Blocked**. The documented installation path was not runnable in this host because the bundled Python environment lacks declared dependencies (`jsonschema`, `coverage`, `build`, and `twine`). The primary offline workflow was therefore **Blocked** at schema validation; historical cloud snapshots dated 2026-07-29 are not current runtime proof. The command reference is broad and maps to `invoke_assessment.py` and `sign_engagement.py`, but release documentation still calls migration material “unreleased.” Overall maturity: **strong pre-release / release-candidate engineering foundation, not release-verified in this environment**.

| Area | Result |
|---|---|
| Identity | Confirmed — Static — `pyproject.toml`, `csaf/__init__.py` |
| Working tree | Confirmed — Static — clean before review and unchanged after review commands |
| Safe runtime | Blocked — missing declared dependencies |
| Test suite | Partial — 429 discovered; 17 failures and 20 errors, dominated by missing `jsonschema` plus resource/output drift |
| Cloud mutation safety | Confirmed — Static — provider session guards and tests |
| Release parity | Blocked — no local tags/releases |
| Most important strength | Read-only transport guardrails plus signed scope authorization |
| Most important risk | Release confidence is overstated by stale execution snapshots and an unverified package/resource contract |

Top actions: (1) make the locked environment reproducibly runnable and require a clean full-suite/self-check gate; (2) eliminate source-vs-packaged resource drift and reconcile coverage field names; (3) publish a release manifest with tag, artifacts, SBOM, attestations, and refreshed execution evidence. First offensive feature: signed, replayable ATT&CK validation campaigns, because the repository already has profiles, MITRE mappings, evidence, manifests, and read-only validation primitives. Highest UX enhancement: a dependency-aware guided preflight, because current first-run failure is an opaque missing-module failure rather than an actionable install/recovery path. Governance and release controls are directionally strong in repository workflows, but cannot be judged sufficient without repository settings, protected-branch rules, and a verifiable published release.

## 2. Review Scope, Mode, Assumptions, and Safety Boundaries

Defaults from the supplied master prompt were applied: read-only review, authorized penetration-testing/purple-team/lab use cases, safe local execution only, no cloud credentials, no target interaction, no dependency installation, and current commit as target ref. No tracked files were changed. Runtime attempts were limited to version/help, dependency preflight, unit tests, local package/build checks, and offline self-check commands. No network, cloud, Kubernetes, credential, listener, mutation, or persistence action was attempted.

## 3. Review Coverage, Method, Manifest, and Limitations

Inspected repository source, tests, catalogs, baselines, schemas, README, execution docs, migration notes, changelog, security policy, packaging, CI/release workflows, Dependabot configuration, Git metadata, and provider transport guards. Inventory: 124 Python files under `csaf/` and `tests/`; 139 repository files reported by `rg --files` excluding generated review output. Generated/ignored build/cache directories were not treated as first-party source. Limitations: no network verification, no GitHub API/settings access, no clean-room dependency installation, no live-cloud validation, no local release tags, and no current artifact attestation verification.

## 4. Repository Identity and Baseline

`pyproject.toml` declares package `csaf`, version `1.0.0`, Python `>=3.10`, and console scripts `csaf-assess` and `csaf-sign-engagement`. `csaf/__init__.py` declares framework `1.0.0`, schema `3.0`, catalog schema `1.0`. The commit subject is “Implement repository hardening fixes.” Four provider families are present: AWS, Azure, GCP, and K8s. Four source catalogs exist; AWS/Azure/GCP catalog versions are `2026.1`, while K8s is `1.0`.

## 5. GitHub Governance and Project-Health Baseline

Repository-file evidence shows read-only CI permissions, pinned action SHAs, concurrency cancellation, timeouts, dependency auditing, SBOM generation, Python 3.10/3.12/3.14 testing, a 90% coverage gate, package smoke tests, Dependabot for pip/actions, and a security policy requesting private reporting. Local refs include `origin/main` at the reviewed commit and feature branches, but no tags. GitHub settings, required checks, branch protection, CODEOWNERS, issue history, PR review state, vulnerability alerts, and published release records were not available; governance sufficiency is therefore **Partial/Blocked**, not confirmed.

## 6. Release, Artifact, and Version Consistency

Package/framework versions agree at `1.0.0`; schema versions are intentionally separate. Baselines and most catalogs use catalog version `2026.1`; K8s uses `1.0`, which should be explained as provider-specific or normalized before release. `CHANGELOG.md` begins with `Unreleased`; `docs/migration-unreleased.md` describes current hardening as a future release. `dist/` contains `csaf-1.0.0` artifacts from 2026-07-30, but they were not rebuilt or verified during this review because `build`/`twine` are absent. `tests/test_resources.py` found byte-level CRLF/LF differences between `controls/`, `baselines/`, `schemas/` and `csaf/resources/...` copies. This is a release/package reproducibility defect, even if parsed JSON is semantically equal.

## 7. Repository Inventory, Ownership, and Change Hotspots

Hotspots are `invoke_assessment.py`/`csaf/runner.py` (CLI and orchestration), `csaf/clouds/*/session.py` (trust boundary), `csaf/clouds/*/provider.py` and modules (provider behavior), `csaf/catalog.py`/`baseline.py`/`schema_validation.py` (operator-controlled configuration), `csaf/reporting.py`/`evidence.py` (artifact integrity), and `.github/workflows/*.yml` (quality/release gates). No CODEOWNERS file was present; ownership is inferred from structure only.

## 8. Project Understanding and Persona Coverage

The architecture serves authorized cloud assessors, purple-team engineers, detection engineers, maintainers, integration developers, and release engineers. `Assessment` is default read-only posture evaluation; `Validation` and `AdversarySimulation` add approved non-destructive validation selection, with the latter narrowed to MITRE-mapped controls. The framework does not execute exploitation. Operators receive JSONL/CSV findings and control results, coverage, remediation roadmap, detection coverage, technical JSON, executive HTML, structured logs, and a manifest.

## 9. Architecture, Data Flows, and Trust Boundaries

CLI → `RunConfig` → resource/schema/catalog/baseline loading → engagement authorization → provider session → module dispatch → `ControlResult`/evidence → coverage/risk/compliance/detection calculations → report writers → final manifest. Operator-supplied engagement/baseline/catalog data is a trust boundary and is schema-validated. Cloud SDKs are lazily imported. AWS allows read-only operation prefixes; Azure permits only GET and pins absolute URLs to `management.azure.com`; GCP permits GET plus exact read-only POST suffixes; K8s wraps generated APIs and blocks CRUD and `connect_*` operations. Remaining boundary risk is dependency/plugin code and the fact that manifest hashes provide integrity evidence but not authenticity or encryption.

## 10. Capability-to-Code-to-Test-to-Documentation-to-Release Traceability

| Capability | Implementation | Tests/docs | Status |
|---|---|---|---|
| CLI assessment | `invoke_assessment.py:build_parser`, `csaf/runner.py:run_assessment` | `tests/test_cli.py`, README CLI table | Confirmed — Static; runtime blocked |
| AWS checks | `csaf/clouds/aws/modules/*`, `AwsProvider` | `tests/test_module_*.py`, docs/aws.md | Partial — historical runtime only |
| Azure checks | `csaf/clouds/azure/modules/*`, `AzureProvider` | Azure module tests/docs | Partial — historical runtime only |
| GCP checks | `csaf/clouds/gcp/modules/*`, `GcpProvider` | GCP module tests/docs | Partial — historical runtime only |
| K8s checks | `csaf/clouds/k8s/modules/*`, `K8sProvider` | K8s tests/docs | Partial — historical runtime only |
| Engagement signing | `sign_engagement.py`, `csaf/engagement_signing.py` | signing/authorization tests, README | Partial — schema dependency blocked |
| Plugin discovery | `csaf/plugins.py`, pyproject entry-point groups | `tests/test_plugins.py`, README | Confirmed — Static; supply-chain controls incomplete |
| Manifest/evidence | `csaf/evidence.py`, `csaf/reporting.py` | `tests/test_evidence.py`, docs | Confirmed — Static |

## 11. Baseline Build, Test, Clean-Room, and Runtime Results

Executed with the bundled Python 3.12.13: `test_dependencies.py`, `invoke_assessment.py --version`, `--help`, `python -m unittest discover -s tests -v`, four offline self-check attempts, and `python -m build --no-isolation`. The suite discovered 429 tests, with 17 failures and 20 errors; missing `jsonschema` caused the dominant failures and prevented reports/self-checks. Resource tests also failed on byte-level newline drift, and some assertions expect `SelectedControls` while current `coverage-report.json` is produced from `Coverage.to_dict()` without that key. `build` was unavailable. Ruff is present only as an importable module in the bundled environment but not as a command; lint/format were not completed. Clean-room install, uninstall, upgrade, rollback, and artifact verification are **Blocked**.

## 12. Current Capability and Safety/Telemetry Map

Current safety controls include explicit profile selection, signed HMAC engagement authorization, time windows, account/region/context scope, fail-closed source-address handling for active runs, read-only transport proxies, bounded HTTP timeouts, structured logs, evidence references, SHA-256 manifests, HTML escaping, and coverage-incomplete exit code `2`. Telemetry is primarily local artifacts and JSONL logs; there is no confirmed centralized event stream, durable campaign identity, operator decision log, or signed manifest authenticity mechanism.

## 13. Complete Command, Module, API, Configuration, Schema, Integration, and Automation Reference

User-facing commands are `csaf-assess`/`python invoke_assessment.py` with `--cloud {aws,azure,gcp,k8s}`, `--profile {Inventory,Assessment,Validation,AdversarySimulation}`, `--regions`, `--catalog`, `--baseline`, `--engagement`, `--engagement-key-file`, `--previous-findings`, provider target selectors (`--aws-profile`, `--subscription`, `--project`, `--kube-context`, `--kubeconfig`), `--max-workers`, `--output-dir`, `--log-level`, `--self-check`, and `--version`; and `csaf-sign-engagement`/`python sign_engagement.py` with `--engagement`, `--key-file`, and verification/write options defined in that file. Configuration files are catalog, baseline, engagement, and manifest/finding/control-result schemas. Plugin groups are `csaf.modules.aws`, `.azure`, `.gcp`, and `.k8s`. CI and release automations are `.github/workflows/ci.yml` and `release.yml`.

## 14. Documentation Accuracy, Executable Examples, and Current-Release Matrix

README examples match the parser at a static level. Execution docs claim successful 2026-07-29 runs, exact artifact counts, and 94% coverage; those are dated snapshots and are not reproducible in the current environment. The README claims “more than 400 tests” and 94% coverage, while the current run has 429 discovered tests but no coverage measurement. `docs/migration-unreleased.md` should be renamed/released or clearly marked as unreleased before publication. Add a generated command/help snapshot and a release matrix that records commit, dependency lock hash, interpreter, test count, self-check exit/result, and artifact hashes.

## 15. Repository-Specific Strengths

1. Read-only transport guards are explicit and provider-specific.
2. Active validation is gated by signed, scoped, time-bounded engagements.
3. Declarative catalogs, profiles, mappings, baselines, schemas, and plugins provide extensibility.
4. Evidence manifests, structured logs, delta findings, detection coverage, and HTML/CSV/JSON outputs support audit workflows.
5. CI includes pinned actions, dependency hashes, pip-audit, SBOM, matrix tests, coverage, package smoke tests, and provenance/SBOM attestations.

## 16. Weaknesses and Architectural Constraints

The duplicate resource tree can drift; plugin entry points are discovered from any installed distribution without a trust/allowlist policy; manifests hash artifacts but do not authenticate the manifest; the CLI has no generated command schema or machine-readable `--help`; cloud runtime and release artifact validation are not available locally; provider checks are broad but mostly posture-oriented rather than campaign-oriented; and current output contracts have evidence of field-name drift.

## 17. Secure Software, Abuse-Resistance, Evidence-Safety, and Operator-Safety Findings

### REV-REL-001 — Runtime and release evidence cannot be reproduced from the declared environment

- Category: release engineering / reproducibility; Severity: High; Release blocking: Yes
- Evidence status: Confirmed — Runtime for environment failure; Confidence: High
- Evidence: `requirements.txt`, `requirements-lock.txt`, `test_dependencies.py`, `.github/workflows/ci.yml`; command `python -m unittest discover -s tests -v` with bundled Python 3.12.13; `jsonschema`, `coverage`, `build`, and `twine` unavailable.
- Impact: self-check, schema validation, coverage gate, package build, and release verification cannot be confirmed locally; historical docs may overstate current readiness.
- Recommendation: provide a reproducible bootstrap/venv path or CI container, run dependency preflight before test discovery, and publish current evidence keyed to lockfile hash.
- Acceptance: clean isolated environment installs lockfile; full suite, four self-checks, coverage gate, build, twine check, and wheel smoke test pass; evidence includes exit codes and hashes.

### REV-REL-002 — Source and packaged JSON resources differ byte-for-byte

- Category: release/package correctness; Severity: High; Release blocking: Yes
- Evidence status: Confirmed — Runtime; Confidence: High
- Evidence: `tests/test_resources.py::test_packaged_json_exactly_matches_source_directories` reports CRLF packaged bytes versus LF source bytes for controls, baselines, and schemas.
- Impact: package consumers and manifest/reproducibility checks can receive artifacts that do not equal reviewed source files.
- Recommendation: generate packaged resources from one canonical tree or normalize line endings in a checked build step and test semantic plus byte equality intentionally.
- Acceptance: resource parity test passes on Windows/Linux; wheel contents are reproducible from the same commit.

### REV-COR-001 — Coverage output contract is inconsistent with tests

- Category: correctness; Severity: Medium; Release blocking: Yes
- Evidence status: Confirmed — Runtime; Confidence: High
- Evidence: `tests/test_runner_paths.py::test_not_applicable_controls_removed_from_selection` expects `coverage["SelectedControls"]`; `csaf/reporting.py::write_coverage` serializes `Coverage.to_dict()` and appends only `NotTestedControls`.
- Impact: baseline-exclusion validation fails and downstream automation cannot rely on the documented selection metric.
- Recommendation: choose one stable field name/schema, update writer/tests/docs together, and add compatibility handling if existing consumers use another spelling.
- Acceptance: baseline exclusion test passes; coverage schema documents selected/executed/not-tested/error fields and migration behavior.

### REV-SUP-001 — Unrestricted installed-plugin discovery lacks provenance policy

- Category: supply chain; Severity: Medium; Release blocking: No
- Evidence status: Confirmed — Static — `csaf/plugins.py::discover_plugin_modules`, `pyproject.toml` entry-point groups, `tests/test_plugins.py`.
- Impact: an installed distribution can add operator-executed checks; the code handles collisions/load failures but does not verify signer, provenance, version compatibility, or allowlist.
- Recommendation: add plugin metadata contract, compatibility checks, optional allowlist/lockfile, provenance logging, and explicit operator confirmation for third-party modules.
- Acceptance: plugin inventory appears in manifest/logs; incompatible/unapproved plugins fail closed or require explicit opt-in; tests cover malicious/broken metadata.

### REV-SAFE-001 — Manifest integrity is not manifest authenticity or evidence confidentiality

- Category: evidence/operator safety; Severity: Medium; Release blocking: No
- Evidence status: Confirmed — Static — `csaf/evidence.py`, `tests/test_evidence.py`, README evidence-safety section.
- Impact: an actor able to rewrite output can rewrite both artifacts and manifest; reports may contain sensitive IAM/configuration data.
- Recommendation: support optional signed manifests, key separation, encrypted output guidance/hooks, and explicit redaction policies.
- Acceptance: signed manifest verification detects altered manifest/artifact; secret-like fields are redacted under a documented mode; default behavior remains backward compatible.

### REV-DOC-001 — Historical execution reports are not clearly gated as stale release evidence

- Category: documentation; Severity: Medium; Release blocking: No
- Evidence status: Confirmed — Static — `docs/test-execution/README.md`, `docs/test-execution/aws.md`, `docs/migration-unreleased.md`.
- Impact: maintainers may infer current runtime/release readiness from 2026-07-29 snapshots that do not match the current host result.
- Recommendation: add commit/lockfile identifiers, a “snapshot only” banner, and CI-generated replacement artifacts on every release candidate.
- Acceptance: every execution report states exact commit, dependency environment, and validity window; stale reports cannot be mistaken for current release evidence.

## 18. Detailed Gap Analysis

Primary gaps are reproducible environment setup, canonical resource packaging, output schema stability, release/version truth, plugin trust, signed evidence, live provider integration fixtures, and operator campaign orchestration. No evidence supports calling the project exploitable or unsafe for its intended read-only posture; the gaps chiefly reduce confidence, interoperability, and release safety.

## 19. Architecture, Extensibility, and Compatibility Recommendations

Introduce a versioned internal run/campaign model around existing `RunConfig`, `Engagement`, `EvidenceStore`, and `Manifest`; preserve current CLI defaults; expose provider-neutral control/result interfaces; make plugin contracts explicit and logged; and generate schemas/help from the same source used by the parser/catalog. Keep active validation opt-in and read-only by default.

## 20. Dependency, Container, GitHub, CI/CD, Release, and Supply-Chain Findings

Hash-locked requirements and Dependabot are strengths. Missing local tooling prevented `pip-audit`, SBOM, build, and twine verification. Release workflow has broad write/id-token/attestation permissions appropriate to publishing but should be validated against protected environments and tag controls. Add a pinned review container or reusable CI image, verify lockfile freshness, enforce dependency provenance for plugins, and make release jobs depend on the same full gates as CI.

## 21. Testing, Quality, Adversarial-Fixture, and Validation Recommendations

Fix environment bootstrap first; add a preflight test that reports all missing dependencies before running tests; add Windows/Linux resource parity tests; add golden CLI/help/output schema tests; add plugin trust/compatibility fixtures; add signed-manifest tests; and retain current fake-provider tests while adding disposable local HTTP/API fixtures for pagination, throttling, malformed responses, and cancellation.

## 22. Reliability, Performance, Portability, Evidence-Lifecycle, and Operator/User-Experience Findings

AWS supports configurable concurrency but other providers are sequential. HTTP calls have 60-second timeouts but no visible retry/backoff/cancellation contract. Output is rich and multi-format but has no machine-readable command schema or stable selection-field contract. Evidence lifecycle lacks authenticated manifest, retention, redaction, and cleanup automation. These are material for large assessments and repeated purple-team campaigns.

## Top Ten Offensive Security Tooling Feature Enhancements

| Rank | ID | Enhancement | Why it fits |
|---:|---|---|---|
| 1 | OFF-FEAT-001 | Signed, replayable ATT&CK validation campaigns | Reuses `AdversarySimulation`, MITRE mappings, engagements, evidence, manifests |
| 2 | OFF-FEAT-002 | Cross-cloud attack-path correlation | Reuses normalized `ControlResult`, mappings, and multi-provider catalogs |
| 3 | OFF-FEAT-003 | Scope-aware validation plan/preview | Reuses engagement scope and profile selection; reduces operator error |
| 4 | OFF-FEAT-004 | Detection-coverage gap-to-test planner | Reuses `detection_coverage.py` and ATT&CK mappings |
| 5 | OFF-FEAT-005 | Evidence-backed finding replay/delta campaigns | Reuses `delta.py`, manifests, and prior findings |
| 6 | OFF-FEAT-006 | Provider-neutral check/plugin SDK with signed inventory | Reuses entry points and module dispatch with trust controls |
| 7 | OFF-FEAT-007 | Read-only permission adequacy simulator | Reuses provider guards, attestation results, and Validation profile |
| 8 | OFF-FEAT-008 | Multi-region/cloud concurrency controller | Extends existing AWS `max_workers` to bounded provider-neutral execution |
| 9 | OFF-FEAT-009 | Campaign evidence bundle export/import | Reuses report writers, schemas, manifests, and source revision |
| 10 | OFF-FEAT-010 | Safe negative-control fixture pack | Reuses fake sessions/modules to validate detections without real targets |

All ten are **Proposed**, not current capabilities. Scores use 1–5 per factor: raw priority = operator impact + strategic fit + architecture reuse + feasibility + testability + defensive value − maintenance burden − misuse risk − operational complexity; adjusted priority multiplies by evidence confidence (0.9 for high, 0.75 medium) and sequencing adjustment. The ranked order reflects safety prerequisites and reuse, not ties or filler.

1. **OFF-FEAT-001** — CLI `csaf campaign plan/run/replay`, signed campaign manifest, ATT&CK technique/control selection, explicit target scope, dry-run, bounded concurrency, cancellation, defender telemetry, artifact hashes, cleanup/rollback (no remote mutation), fake-provider and golden-report tests. Prerequisites: REV-REL-001/002, REV-SAFE-001, roadmap 1/2/3/4/5. Score 5+5+5+3+4+5−3−4−3 = 17; adjusted 15.3. Acceptance: deterministic signed plan and replay produce identical normalized results from fixtures; out-of-scope and tampered plans fail closed.
2. **OFF-FEAT-002** — Correlate IAM/network/storage/K8s findings into evidence-linked paths. Scope is analytical only; no exploit or mutation. Prerequisites: normalized result schema, provenance, cross-cloud identifiers. Score 5+5+4+3+3+5−4−3−3 = 15; adjusted 13.5.
3. **OFF-FEAT-003** — `--plan` emits selected controls, target/account/context, permissions, estimated calls, and exclusions before execution. Score 5+5+5+5+5+4−2−2−2 = 18; adjusted 16.2, but sequenced after resource/schema fixes.
4. **OFF-FEAT-004** — Turn ATT&CK gaps into a safe validation queue with explicit operator approval and fixture/defender telemetry requirements. Score 4+5+5+4+4+5−2−3−2 = 20; adjusted 18.0.
5. **OFF-FEAT-005** — Signed prior-run comparison with stable campaign IDs, new/persisted/resolved evidence, and retention controls. Score 4+4+5+4+5+4−2−2−2 = 20; adjusted 18.0.
6. **OFF-FEAT-006** — Versioned plugin contract, signed inventory, allowlist, capability declaration, and isolation boundary. Score 4+5+4+3+3+4−4−4−3 = 8; adjusted 7.2.
7. **OFF-FEAT-007** — Compare required read-only permissions with observed API calls using fake/recorded sessions; no credential discovery. Score 4+4+4+3+4+5−3−2−2 = 17; adjusted 15.3.
8. **OFF-FEAT-008** — Provider-neutral bounded workers with per-provider rate limits, timeouts, retries, cancellation, and deterministic ordering. Score 4+4+4+3+4+3−4−2−4 = 8; adjusted 7.2.
9. **OFF-FEAT-009** — Portable signed bundle with schema version, source revision, lock hash, manifest, reports, and redaction profile. Score 4+4+5+4+5+4−2−2−2 = 20; adjusted 18.0.
10. **OFF-FEAT-010** — Disposable fixture pack for public exposure, privilege, logging, K8s RBAC/pod/network, and error cases. Score 4+4+5+5+5+5−2−1−1 = 24; adjusted 21.6, sequenced after the foundational release fixes despite high raw value.

## Top Fifteen Overall Prioritized Enhancements

1. Reproducible isolated dependency/bootstrap environment (REV-REL-001), P1, acceptance: clean install and full gates pass.
2. Canonicalize or generate packaged JSON resources (REV-REL-002), P1, acceptance: parity test passes on Windows/Linux.
3. Stabilize coverage/report schemas and compatibility aliases (REV-COR-001), P1, acceptance: runner-path and schema tests pass.
4. Refresh execution docs from CI and bind them to commit/lock hash (REV-DOC-001), P1.
5. Add signed-manifest/authenticated evidence mode (REV-SAFE-001), P1.
6. Add `--plan`/preflight command and machine-readable plan schema, enabling OFF-FEAT-003.
7. Add campaign model and ATT&CK validation queue, enabling OFF-FEAT-001/004.
8. Add plugin contract, provenance, compatibility, allowlist, and inventory, enabling OFF-FEAT-006.
9. Add provider-neutral normalized resource identifiers and correlation graph, enabling OFF-FEAT-002.
10. Add deterministic bounded concurrency/retry/cancellation, enabling OFF-FEAT-008.
11. Add signed replay/delta campaign IDs and retention/cleanup, enabling OFF-FEAT-005/009.
12. Add disposable negative-control fixture pack, enabling OFF-FEAT-010.
13. Add local HTTP/API integration fixtures for pagination, throttling, and malformed responses.
14. Add release governance checks: tag protection, CODEOWNERS, required gates, artifact verification, and release checklist.
15. Add output redaction, encryption-at-rest guidance/hooks, and evidence lifecycle policy.

## Top User-Experience Enhancements

| Rank | ID | Enhancement | Friction evidence |
|---:|---|---|---|
| 1 | UX-ENH-001 | Dependency-aware guided preflight | Missing `jsonschema` currently becomes fatal runtime failure |
| 2 | UX-ENH-002 | `--plan` preview with scope and selected controls | Profile/scope selection is implicit until execution |
| 3 | UX-ENH-003 | Stable machine-readable output schema and migration aliases | `SelectedControls` expectation conflicts with emitted coverage keys |
| 4 | UX-ENH-004 | Generated CLI/help and provider option reference | Parser and README can drift; no generated snapshot |
| 5 | UX-ENH-005 | Clear recovery-oriented error catalog | Dependency/schema/auth errors are distributed across code paths |
| 6 | UX-ENH-006 | Accessible terminal/HTML output modes | Rich HTML/CSV/JSON exists, but no explicit color/TTY/accessibility contract |
| 7 | UX-ENH-007 | First-run fixture tutorial and cleanup command | Self-check is documented but unavailable without dependencies; output path is nested |

1. **UX-ENH-001** — `csaf-assess --preflight` checks Python, declared dependencies, optional provider extras, write access, schema resources, and output directory; before: traceback/fatal missing module; after: grouped install commands and safe next step. Tests: missing/partial dependency fixtures and golden text. Acceptance: no import traceback for missing dependency; exit code and remediation are stable.
2. **UX-ENH-002** — `--plan` prints cloud/profile/scope/control count/exclusions/output path without API calls. Tests: golden plan and out-of-scope cases. Acceptance: plan is deterministic and explicitly says no network calls.
3. **UX-ENH-003** — Versioned coverage schema with `selected`, `executed`, `not_tested`, `error`, plus compatibility aliases. Tests: JSON schema/golden fixtures. Acceptance: existing consumers continue to parse or receive documented migration error.
4. **UX-ENH-004** — Generate README option table from parser metadata and test `--help` snapshot. Acceptance: every parser option appears once with default and provider applicability.
5. **UX-ENH-005** — Error codes and recovery guidance for missing files, schema violations, unauthorized profile/scope, dependency preflight, and incomplete coverage. Acceptance: each fatal path has stable code, actionable message, and negative test.
6. **UX-ENH-006** — no-color/plain-text mode, semantic HTML headings, table captions, keyboard-friendly details, and CSV/JSON alternatives. Acceptance: HTML is navigable without color and reports pass accessibility smoke checks.
7. **UX-ENH-007** — fixture tutorial that runs self-check, locates the unique run directory, verifies manifest, and offers safe cleanup. Acceptance: tutorial works from unrelated CWD in the locked environment.

## Offensive Feature-, Roadmap-, and UX-Enhancement Crosswalk

| Offensive | Enabling roadmap | UX support |
|---|---|---|
| OFF-001 | 1,2,3,5,6,7,11 | UX-001,002,005 |
| OFF-002 | 3,7,9,13 | UX-003,006 |
| OFF-003 | 1,3,6 | UX-001,002,004 |
| OFF-004 | 7,9,12 | UX-002,005 |
| OFF-005 | 3,5,11 | UX-003,007 |
| OFF-006 | 8,14 | UX-001,004 |
| OFF-007 | 1,7,13 | UX-002,005 |
| OFF-008 | 1,10,13 | UX-001,005 |
| OFF-009 | 2,5,11,15 | UX-003,006,007 |
| OFF-010 | 1,12,13 | UX-001,007 |

## Phased Delivery Roadmap

Phase 0: install locked dependencies in an isolated environment and capture baseline. Phase 1: fix resource parity, coverage schema, release/version docs, and current execution reports. Phase 2: add preflight/plan UX, error catalog, and golden output tests. Phase 3: add signed evidence and plugin trust controls. Phase 4: deliver fixture pack, ATT&CK campaign model, detection planner, and replay/delta. Phase 5: add cross-cloud correlation and bounded concurrency only after deterministic evidence and release gates are stable.

## Quick Wins

1. Add `jsonschema`/tool availability diagnostics to `test_dependencies.py` and CI logs.
2. Normalize duplicate JSON resources in one build step and add newline-independent semantic parity test.
3. Reconcile `SelectedControls` with `Coverage.to_dict()` and schema/docs.
4. Add current commit and lock hash to `docs/test-execution/README.md`.
5. Add a `--no-color`/plain output switch and stable error codes.
6. Add CODEOWNERS and a release checklist documenting required checks and attestations.

## Major Risks and Tradeoffs

Campaign breadth increases maintenance and misuse risk; native provider checks preserve control but duplicate cloud semantics; plugins improve extensibility but expand supply-chain trust; richer evidence improves reproducibility but increases sensitivity; concurrency improves throughput but complicates rate limits and deterministic ordering; local-first operation improves privacy but limits centralized campaign observability; output redesign improves readability but requires compatibility aliases. Every future active/validation capability must remain explicit, scoped, bounded, auditable, and non-mutating.

## Recommended Next Implementation Blueprint and Follow-On Offensive Feature MVP

Implement the reproducible preflight + `--plan` foundation first. Add a `PreflightResult` and `AssessmentPlan` schema, parser subcommands, dependency/resource checks, selected-control resolution, engagement scope validation, estimated provider operations, deterministic serialization, and golden tests. Then build OFF-FEAT-001 as a fixture-only signed campaign: campaign manifest references an engagement, ATT&CK technique IDs, selected controls, provider fixture, source revision, and expected evidence schema; execution is offline, replayable, and emits a signed/hash-verified bundle. No target interaction or exploit execution belongs in the MVP.

## Release Readiness and Quality Gates

Not ready for a verifiable release from this environment. Required gates: isolated lockfile install; dependency preflight; all 429+ tests pass; coverage ≥90%; resource parity; lint/format; all four offline self-checks; wheel/sdist build and twine check; installed-wheel smoke from unrelated CWD; SBOM, checksum, provenance and SBOM attestations; current docs generated; protected tag/release governance confirmed; and review-only status/diff checks remain clean.

## Blocked or Unverified Items

Live AWS/Azure/GCP/K8s execution; cloud permission adequacy; package build/twine; coverage; lint/format; clean-room install; release artifact signatures/attestations; latest public release; GitHub settings/issues/PRs/discussions; upgrade/uninstall/rollback; and current runtime evidence from the documented snapshots.

## Evidence Ledger

Static: `pyproject.toml`, `setup.py`, `csaf/__init__.py`, `invoke_assessment.py`, `csaf/runner.py`, `csaf/engagement.py`, `csaf/engagement_signing.py`, `csaf/plugins.py`, provider sessions, catalogs, baselines, schemas, README, docs, workflows, SECURITY.md, CHANGELOG.md, tests. Runtime: bundled Python 3.12.13; `python -m unittest discover -s tests -v` → 429 discovered, 17 failures, 20 errors, 8 skipped; `python test_dependencies.py` → dependency failures; self-check → blocked by `jsonschema`; build → blocked by missing `build`; git status/diff/check → clean. No external authority was used.

## File Coverage Appendix

All first-party paths returned by `rg --files` were included by category: package modules under `csaf/`, provider modules under `csaf/clouds/`, schemas/resources, catalogs/baselines, tests, docs/reference, packaging files, and GitHub workflows. Generated caches, `dist/`, `*.egg-info`, `.coverage`, and `__pycache__` were treated as generated/untracked and excluded from source-coverage claims. Exact per-file manifest is represented by the repository inventory command recorded below; no files were copied into review artifacts.

## Command Execution Ledger

| Command | Result |
|---|---|
| `git status --short; git diff --stat; git diff --check` | clean / empty / pass |
| `rg --files` | 139 repository paths; 124 Python files in `csaf`+`tests` |
| `python --version` | system `python` unavailable; bundled Python 3.12.13 used |
| `python test_dependencies.py` | blocked/fails due missing declared packages |
| `python invoke_assessment.py --version/--help` | parser/version evidence available with bundled runtime |
| `python -m unittest discover -s tests -v` | 429 discovered; 17 failures; 20 errors; 8 skipped |
| four `--self-check` commands | blocked by missing `jsonschema` |
| `python -m build --no-isolation` | blocked: module unavailable |
| `ruff check/format --check` | blocked: executable unavailable in PATH |

## Review Manifest and Artifact Hashes

Review artifact: `review-output/REVIEW.md`. Machine-readable companions: `review-output/findings.json`, `review-output/offensive-features.json`, and `review-output/ux-enhancements.json`. SHA-256 at handoff: `findings.json` = `f8241cd0ad169476843d4c65d725e84a6e7001f1fe7eec4c223feefb4777327b`; `offensive-features.json` = `ee3bab90b1383a1fe2bcf7d4709a0d097f39125cea35c88758aa81f9714eca60`; `ux-enhancements.json` = `8ffefc890c2a2f9bbcfe251ffa8e949d0bd4335a87ca9ece68383429561c2d17`. This review does not authenticate its own manifest.

## Final Completeness Self-Audit

The review identifies repository/ref/release limitation, scope and safety boundaries, evidence statuses, architecture, capabilities, command/configuration surfaces, findings, testing/runtime limitations, exactly ten offensive feature enhancements, fifteen overall enhancements, seven UX enhancements, crosswalk, roadmap, quick wins, risks, blueprint, release gates, blocked items, ledger, and coverage appendix. Claims of current runtime success are not made where dependencies were unavailable. Review-only source status remained clean; `review-output/` contains only the requested review artifacts.
