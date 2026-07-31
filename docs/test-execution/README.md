# Test Execution Reports

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
| [k8s.md](k8s.md) | Kubernetes | 26 / 26 passed | 4 findings, risk 55.0 (HIGH), coverage 4/5 |

These are point-in-time snapshots, not a substitute for re-running the suite (`python3 -m unittest discover -s tests`) or the self-check (`python3 invoke_assessment.py --self-check --cloud <cloud>`) yourself against the current codebase. The runner currently writes 17 possible top-level files plus the `evidence/` directory; older report text that calls this a “14-artifact” output is historical wording.
