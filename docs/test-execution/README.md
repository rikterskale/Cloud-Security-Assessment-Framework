# Test Execution Reports

> These are **point-in-time snapshots**, not current runtime evidence. The AWS/Azure/GCP reports were captured 2026-07-29; the Kubernetes report was re-captured 2026-08-05 after the Kubernetes catalog grew to 8 controls. Re-generate on each release.

Detailed, evidence-based records of running CSAF's unit test suite and offline `--self-check` pipeline for each supported cloud. Each report includes:

- The exact commands run
- Full verbose unit test output
- Full self-check console and structured log output
- Complete contents of every generated artifact (`control-results`, `findings`, `coverage-report`, `detection-coverage`, `remediation-roadmap`, `manifest`)
- Independent SHA-256 hash verification of the manifest's tamper-evidence claim
- Confirmation that each cloud's optional SDK (`boto3`, `azure-identity`, `google-auth`, `kubernetes`) was genuinely absent from the environment during the run

Generated 2026-07-29 against `main`. These reports are historical snapshots;
they do not establish that the same results hold for the current checkout.

| Report | Cloud | Unit tests | Self-check result |
|---|---|---|---|
| [aws.md](aws.md) | AWS | 102 / 102 passed | 5 findings, risk 70.0 (CRITICAL), coverage 29/30 |
| [azure.md](azure.md) | Azure | 58 / 58 passed | 5 findings, risk 45.0 (HIGH), coverage 15/16 |
| [gcp.md](gcp.md) | GCP | 76 / 76 passed | 5 findings, risk 45.0 (HIGH), coverage 18/19 |
| [k8s.md](k8s.md) | Kubernetes | 26 / 26 passed | 4 findings, risk 55.0 (HIGH), coverage 7/8 |

## Platform validation status

| Platform | Status | Evidence |
|---|---|---|
| AWS | Verified | Offline self-check and AWS unit-test subset recorded in [aws.md](aws.md) |
| Azure | Partially verified | Offline self-check and provider tests in [azure.md](azure.md); live credentials are environment-specific |
| GCP | Partially verified | Offline self-check and provider tests in [gcp.md](gcp.md); live credentials are environment-specific |
| Kubernetes | Static-only | Catalog/schema and offline self-check coverage in [k8s.md](k8s.md); cluster behavior requires a target cluster |

“Verified” refers to the recorded scope and date above, not a guarantee of current live-cloud access. Re-run the documented commands before relying on a release.

> **Current figures (re-verified 2026-08-05 against the tip of `main`):** the per-cloud unit-test subsets shown in each report now run **AWS 104, Azure 60, GCP 76, Kubernetes 26** tests; the self-check results above still reproduce exactly (AWS 29/30, Azure 15/16, GCP 18/19, Kubernetes 7/8). The AWS/Azure/GCP report bodies remain their 2026-07-29 capture; only the counts here are refreshed.

These are point-in-time snapshots, not a substitute for re-running the suite (`python3 -m unittest discover -s tests`) or the self-check (`python3 invoke_assessment.py --self-check --cloud <cloud>`) yourself against the current codebase. The runner currently writes 18 possible top-level files plus the `evidence/` directory; older report text that calls this a “14-artifact” output is historical wording.
