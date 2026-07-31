# Documentation accuracy review — 2026-07-31

## Scope and method

Reviewed all Markdown documentation, the root CLI and signing scripts, the
packaging/dependency manifests, schemas and examples, cloud providers and
sessions, reporting/output code, tests, and CI workflows. The implementation
is the source of truth.

| Check | Result |
|---|---|
| `invoke_assessment.py --help` | Passed; option list matches the parser |
| `invoke_assessment.py --version` | Passed; printed `CSAF v1.0.0` |
| `sign_engagement.py --help` | Passed; options and usage rendered |
| `invoke_assessment.py --self-check --output-dir out` | Blocked: available runtime lacks `jsonschema` |
| `python -m unittest discover -s tests` | Blocked by the same missing required dependency |

No cloud credentials, network calls, or mutating operations were used.

## Functionality inventory

| Capability | Implementation evidence | Interface | Status |
|---|---|---|---|
| Offline synthetic assessment | `invoke_assessment.py`, `csaf/selfcheck.py` | `--self-check` | Implemented; local run blocked by missing `jsonschema` |
| AWS assessment | `csaf/clouds/aws/session.py`, `provider.py`, modules | `--cloud aws` | Implemented; live execution not attempted |
| Azure assessment | `csaf/clouds/azure/session.py`, `provider.py`, modules | `--cloud azure` | Implemented; optional SDK required |
| GCP assessment | `csaf/clouds/gcp/session.py`, `provider.py`, modules | `--cloud gcp` | Implemented; optional SDK required |
| Kubernetes assessment | `csaf/clouds/k8s/session.py`, `provider.py`, modules | `--cloud k8s` | Implemented; optional SDK required |
| Engagement signing/verification | `sign_engagement.py`, `csaf/engagement_signing.py` | `csaf-sign-engagement` or script | Implemented; HMAC shared secret, not encryption |
| Reports and evidence manifest | `csaf/reporting.py`, `csaf/evidence.py`, `csaf/runner.py` | Assessment output directory | Implemented |

## Traceability matrix

| ID | Documentation | Claim | Evidence / verification | Status | Action |
|---|---|---|---|---|---|
| DOC-001 | `README.md` Quick start/CLI reference | Four clouds and documented flags are supported | `build_parser()` choices/options; `--help` executed | VERIFIED | Automated contract test added |
| DOC-002 | `README.md` Installation | Python `>=3.10`; core dependencies are installed from `requirements.txt` or package metadata | `pyproject.toml`, `requirements.txt`, `test_dependencies.py` | VERIFIED | Added virtualenv and Windows note |
| DOC-003 | `README.md` Output artifacts | A run has a unique subdirectory and named reports/logs | `csaf/runner.py` and `csaf/reporting.py` | VERIFIED | Clarified current 17-file set |
| DOC-004 | `docs/test-execution/*.md` | Self-check produces an “exact same 14-artifact output” | Current runner writes 17 possible top-level files plus `evidence/` | INACCURATE | Reworded all four reports |
| DOC-005 | `README.md` Testing | More than 400 unit tests exist | Static count found 435 `test_*` methods | VERIFIED | None |
| DOC-006 | `README.md` Testing | Line coverage is 94% | CI enforces `>=90%`; local coverage could not be measured | UNTESTED | CI is authoritative for current coverage |
| DOC-007 | `README.md` Safety | Providers enforce read-only access | Read-only wrappers in all four sessions and dedicated tests | PARTIALLY VERIFIED | Static review supports claim; live calls not run |
| DOC-008 | `README.md` Authorization | Active profiles require signed, approved, scoped, in-window engagement | `csaf/engagement.py`, runner checks, signing script | VERIFIED | None |
| DOC-009 | `README.md` Catalog section | Catalog counts are AWS 31, Azure 16, GCP 19, K8s 5 | JSON catalog files and static count | VERIFIED | Automated presence guard added |
| DOC-010 | `README.md`, `docs/migration-unreleased.md` | `--output-dir` is a parent containing timestamp/random run directory | `run_assessment()` creates `output_base / run_id` | VERIFIED | None |

## Remaining unresolved items

The local bundled Python runtime does not include required `jsonschema`, so the
full test suite and offline pipeline remain untested here. CI installs the
hash-locked dependencies and is the appropriate place to confirm those checks.
Live cloud execution was not attempted because it requires credentials and
external systems.

The new `tests/test_documentation_contract.py` test runs through normal CI test
discovery and fails if CLI options disappear from the README, documented
cloud/profile choices stop matching the parser, catalog-count claims vanish,
or key output artifacts are no longer documented.
