# Cloud Security Assessment Framework (CSAF)

CSAF is a **read-only** cloud security posture assessment framework. It
enumerates configuration, evaluates a declarative control catalog, records
exactly one status per selected control, and produces coverage, findings, and
executive/technical/remediation reports with a tamper-evident evidence manifest.

It does **not** create, modify, or delete cloud resources, and it does **not**
execute exploitation. A read-only guardrail blocks any mutating AWS API call at
runtime. Optional non-destructive validation (for example
`iam:SimulatePrincipalPolicy`-style policy analysis) is gated behind the
`Validation` authorization profile and an approving engagement file.

This first release implements **AWS** end-to-end. The framework core
(engagement, catalog, coverage, findings, reporting) is cloud-agnostic so Azure
and GCP providers can be added under `csaf/clouds/`.

> The offensive red-team methodology documents that seeded this project now live
> under [`reference/`](reference/) and are **reference-only**. CSAF itself is a
> defensive, read-only assessment tool.

## Design invariants

These mirror the sibling Active Directory assessment framework:

- **One status per selected control** — `Pass`, `Fail`, `Review`,
  `NotApplicable`, `NotTested`, or `Error`.
- **Execution errors are not security passes.** `NotTested` and `Error` never
  produce a finding and never count as coverage.
- **Findings are a strict subset of control results**, derived only from `Fail`
  and `Review` states, with stable object-aware finding IDs.
- **Coverage is tracked separately from findings.** An empty findings list does
  not prove a clean, fully-executed assessment.

## Quick start

### 1. Install

```bash
python3 -m pip install -r requirements.txt
```

### 2. Preflight

```bash
python3 test_dependencies.py
```

### 3. Offline demo (no AWS needed)

```bash
python3 invoke_assessment.py --self-check --output-dir out
```

This runs the full evaluation and reporting pipeline against a synthetic posture
so you can see every output artifact without cloud credentials.

### 4. Assess a real account (read-only credentials)

Use credentials with a read-only policy such as the AWS managed
`SecurityAudit` or `ReadOnlyAccess` policy.

```bash
python3 invoke_assessment.py \
  --profile Assessment \
  --regions us-east-1 us-west-2 \
  --aws-profile audit \
  --baseline baselines/aws-cis-1.5.json \
  --output-dir out
```

### 5. Validation profile (requires an approving engagement)

```bash
python3 invoke_assessment.py \
  --profile Validation \
  --engagement engagement.json \
  --regions us-east-1 \
  --output-dir out
```

The run refuses to start unless the engagement sets
`activeValidationApproved: true` and the current time is inside its window. See
[`schemas/engagement.example.json`](schemas/engagement.example.json).

## Authorization profiles

| Profile | Read-only | Extra behaviour | Authorization |
|---|---|---|---|
| `Inventory` | yes | Collects config; issues few conclusions | None |
| `Assessment` | yes | Default posture assessment | None |
| `Validation` | yes | Adds non-destructive policy validation controls | Requires approved, in-window engagement |
| `AdversarySimulation` | yes | Requires explicit approval; framework stays read-only | Requires approved, in-window engagement |

## Exit codes

- `0` — all selected controls executed, no execution errors.
- `2` — completed, but one or more selected controls were `NotTested` or errored
  (`CompletedWithErrors`). Inspect `coverage-report.csv`.
- `1` — fatal runner or prerequisite failure (e.g. unauthorized profile, account
  outside the engagement scope).

## Output

```text
out/
├── assessment-<ts>.log          # human-readable log
├── assessment-<ts>.jsonl        # structured JSON Lines log
├── control-results.jsonl        # every control result (schema 3.0)
├── control-results.csv
├── findings.csv                 # prioritized findings only
├── findings.json
├── coverage-report.json         # executed/pass/fail/not-tested/error + not-tested IDs
├── coverage-report.csv
├── remediation-roadmap.csv      # prioritized, horizon-bucketed remediation
├── technical-report.json        # full structured results + findings + compliance
├── executive-summary.html       # severity + coverage + compliance rollup
├── manifest.json                # SHA-256 of every artifact
└── evidence/                    # raw collector evidence (e.g. credential report)
```

Start with `coverage-report.csv` to confirm every selected control ran, then
`findings.csv` for prioritized weaknesses. `NotTested` and `Error` are never
security passes.

## Control coverage (AWS)

29 controls across Identity/IAM, privileged access, S3 data protection,
EC2/compute, networking, logging & detection (CloudTrail, Config, GuardDuty),
KMS, and RDS. Each control maps to CIS AWS Foundations, NIST SP 800-53, and/or
MITRE ATT&CK references in [`controls/control-catalog.json`](controls/control-catalog.json).

| Category | Example controls |
|---|---|
| Identity / IAM | Root MFA, root keys, password policy, user MFA, key rotation, unused credentials, `*` admin policies, Access Analyzer |
| Privileged access | Privilege-escalation-enabling permissions (Validation-only) |
| S3 | Account block-public-access, public buckets, default encryption, TLS-only policy |
| Compute (EC2) | IMDSv2 required, EBS default encryption, public-instance exposure |
| Network | Admin-port ingress from `0.0.0.0/0`, default SG restricted, VPC flow logs |
| Logging / detection | Multi-region CloudTrail, log validation, KMS encryption, Config, GuardDuty |
| KMS | Customer-managed key rotation |
| RDS | Encryption at rest, public accessibility |
| Operations | Break-glass procedure (operator attestation) |

## Baselines

Thresholds (password length, key age, sensitive ports, required services) live in
[`baselines/aws-cis-1.5.json`](baselines/aws-cis-1.5.json). Supply a customer
baseline with `--baseline` to override thresholds, override per-control severity,
or mark controls not-applicable.

## Safety

- **Read-only guardrail.** `csaf/clouds/aws/session.py` wraps every boto3 client
  so only non-mutating operations (`describe_*`, `list_*`, `get_*`, `head_*`, and
  read-only `simulate_*`) can be called; anything else raises `ReadOnlyViolation`.
- **Scope enforcement.** The runner refuses to assess an account that is not in
  the engagement's `authorizedAccounts`.
- **Evidence protection.** The manifest proves artifact integrity via SHA-256; it
  does not encrypt evidence. Store outputs on an access-controlled, encrypted
  volume. Evidence can contain sensitive IAM and configuration data.

## Repository layout

```text
.
├── invoke_assessment.py         # main runner (CLI)
├── test_dependencies.py         # preflight
├── csaf/                        # framework package
│   ├── model.py                 # statuses, control results, findings, IDs
│   ├── catalog.py               # control catalog + profile filtering
│   ├── baseline.py              # thresholds
│   ├── engagement.py            # authorization profiles, scope, window
│   ├── coverage.py              # coverage accounting + risk scoring
│   ├── compliance.py            # framework rollup from mappings
│   ├── reporting.py             # JSON/JSONL/CSV/HTML outputs
│   ├── evidence.py              # evidence store + SHA-256 manifest
│   ├── logging_.py              # console + JSONL logging
│   ├── remediation.py           # remediation guidance by control
│   ├── runner.py                # orchestration + exit-code policy
│   ├── selfcheck.py             # offline synthetic provider
│   └── clouds/aws/              # AWS provider, read-only session, modules
├── controls/control-catalog.json
├── baselines/aws-cis-1.5.json
├── schemas/                     # finding / control-result / engagement / manifest
├── tests/                       # unit + end-to-end tests
├── reference/                   # original red-team docs (reference-only)
└── .github/workflows/ci.yml
```

## Continuous integration

`.github/workflows/ci.yml` runs on push, PR, and manual dispatch with read-only
permissions and these gates:

- Ruff lint and format checks
- `pip-audit` dependency vulnerability audit
- Python 3.10 / 3.12 / 3.14 unit-test matrix
- Dependency preflight and offline self-check report generation

Run locally:

```bash
pip install -r requirements.txt -r requirements-ci.txt
ruff check csaf tests invoke_assessment.py test_dependencies.py
ruff format --check csaf tests invoke_assessment.py test_dependencies.py
python3 -m unittest discover -s tests -v
python3 invoke_assessment.py --self-check --output-dir out
```

## Extending to other clouds

Add a provider package under `csaf/clouds/<cloud>/` that exposes an
`evaluate(controls, regions)` method returning `ControlResult` objects, add a
matching control catalog, and register it in the runner. The core (engagement,
coverage, findings, reporting, manifest) is cloud-agnostic and reused as-is.

## Authorized use

CSAF is for authorized security assessments only. Run it against accounts you
own or are explicitly authorized to assess, using least-privilege read-only
credentials, and protect the output directory.
