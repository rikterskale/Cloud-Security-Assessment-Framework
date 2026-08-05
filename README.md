# Cloud Security Assessment Framework (CSAF)

CSAF is a **read-only** cloud security posture assessment framework. It
enumerates configuration, evaluates a declarative control catalog, records
exactly one status per selected control, and produces coverage, findings, and
executive/technical/remediation reports with a SHA-256 evidence inventory.

It does **not** create, modify, or delete cloud resources, and it does **not**
execute exploitation. A read-only guardrail blocks any mutating cloud API call
at runtime. Optional non-destructive validation (for example
`iam:SimulatePrincipalPolicy`-style policy analysis) is gated behind the
`Validation` authorization profile and an approving engagement file.

CSAF supports **AWS, Azure, GCP, and Kubernetes** end-to-end. The framework
core (engagement, catalog, coverage, findings, reporting) is cloud-agnostic;
each cloud plugs in as a provider under `csaf/clouds/` with its own control
catalog and CIS-aligned baseline.

> The offensive red-team methodology documents that seeded this project live
> under [`reference/`](reference/) and are **reference-only**. The directory
> also contains a standalone experimental aggregator; it is not packaged,
> imported, or executed by CSAF. CSAF itself is a defensive, read-only
> assessment tool.

## Table of contents

- [Novice Usability Guide](docs/NOVICE_USABILITY_GUIDE.md) — start here if you are new
- [Design invariants](#design-invariants)
- [Quick start](#quick-start)
- [Container deployment](#container-deployment)
- [Authorization profiles](#authorization-profiles)
- [Exit codes](#exit-codes)
- [Architecture and data flow](#architecture-and-data-flow)
- [Coverage semantics](#coverage-semantics)
- [Control catalog](#control-catalog)
- [Baselines](#baselines)
- [Engagement authorization](#engagement-authorization)
- [Output artifacts](#output-artifacts)
- [Safety](#safety)
- [Testing](#testing)
- [Continuous integration](#continuous-integration)
- [Repository layout](#repository-layout)
- [Extending to other clouds](#extending-to-other-clouds)
- [Authorized use](#authorized-use)

## Design invariants

These mirror the sibling Active Directory assessment framework, and each one is
pinned by unit tests (see [Testing](#testing)):

- **One status per selected control** — `Pass`, `Fail`, `Review`,
  `NotApplicable`, `NotTested`, or `Error`.
- **Execution errors are not security passes.** `NotTested` and `Error` never
  produce a finding, never count as coverage, and never contribute to the risk
  score. A check that raises an exception is converted into a single `Error`
  result by the module dispatcher (`csaf/clouds/base.py`) — it can never
  silently vanish or be recorded as a pass.
- **Findings are a strict subset of control results**, derived only from `Fail`
  and `Review` states, with stable object-aware finding IDs
  (`F-<16 hex chars>` over cloud|account|region|control|resource).
- **Coverage is tracked separately from findings.** An empty findings list does
  not prove a clean, fully-executed assessment. The executive summary renders a
  warning banner whenever coverage is incomplete.

## Quick start

> **New to the terminal, Git, or Python? Start here → [Novice Usability Guide](docs/NOVICE_USABILITY_GUIDE.md).**
> It walks you from an unprepared computer to a verified first result, with troubleshooting, cleanup, and uninstall steps. For OS-specific terminal detail, see the platform guides: [Windows](docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md) · [Linux](docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md). All assume no prior experience and start with the safe offline demo.

**Your first successful run takes one command and needs no cloud account, credentials, or internet** — it uses synthetic data to prove the tool works end to end and writes a full set of reports:

```bash
python3 invoke_assessment.py --self-check --output-dir out
```

Expect `[INCOMPLETE] Completed. ... Coverage 29/30 executed.` and exit code `2` — that is success for the demo (one control is intentionally left untested). Once that works, continue below to install properly and assess a real environment.

### 1. Install

Install from a source checkout or a built wheel. Default catalogs, baselines,
and runtime schemas are package resources, so the `csaf-assess` console script
works from any current directory.

Using a virtual environment is recommended. On Windows, replace `python3`
below with `py` if that is the command provided by your Python installation.

```bash
python3 -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python3 -m pip install -r requirements.txt
python3 -m pip install .
```

For live Azure, GCP, or Kubernetes assessments, add the optional provider
dependencies:

```bash
python3 -m pip install -r requirements-azure.txt
```

```bash
python3 -m pip install -r requirements-gcp.txt
```

```bash
python3 -m pip install -r requirements-k8s.txt
```

### Container deployment

Production-ready Linux and Windows container definitions install every
supported provider SDK (AWS, Azure, GCP, and Kubernetes) from the hash-locked
dependency set. Use the Linux image on Linux container hosts and the Windows
image on Windows Server 2022-compatible container hosts; a single container
cannot provide both operating-system kernels. See
[Container support and certification](docs/CONTAINER_SUPPORT.md) for hardened
run commands, platform support, and the CI certification gates.

### 2. Preflight

```bash
python3 test_dependencies.py
```

For actionable prerequisite, packaged-resource, and output-directory checks:

```bash
python3 invoke_assessment.py --preflight
```

To preview the selected controls without credentials or network calls:

```bash
python3 invoke_assessment.py --plan --cloud aws --profile Assessment
```

See the generated [CLI reference](docs/CLI_REFERENCE.md) for the complete
option surface. For a guided offline fixture run that verifies its manifest:

```bash
python3 invoke_assessment.py --tutorial --output-dir tutorial-output
```

Remove only that tutorial output with
`--cleanup-tutorial --output-dir tutorial-output`.

### 3. Offline demo (no cloud needed)

```bash
python3 invoke_assessment.py --self-check --output-dir out
```

Add `--cloud azure`, `--cloud gcp`, or `--cloud k8s` to demo those catalogs. This runs the full
evaluation and reporting pipeline against a synthetic posture (`csaf/selfcheck.py`)
so you can see every output artifact without cloud credentials. The AWS demo
posture deliberately leaves one operator-attestation control untested, so the
run exits `2` (`CompletedWithErrors`) — demonstrating that incomplete coverage
is always surfaced.

### 4. Assess a real environment (read-only credentials)

**AWS** — use credentials with a read-only policy such as the AWS managed
`SecurityAudit` or `ReadOnlyAccess` policy:

```bash
python3 invoke_assessment.py \
  --profile Assessment \
  --regions us-east-1 us-west-2 \
  --aws-profile audit \
  --baseline baselines/aws-cis-1.5.json \
  --output-dir out
```

**Azure** — authenticates via `DefaultAzureCredential` (Azure CLI login,
environment variables, or managed identity) with a read-only role such as
`Reader` plus `Security Reader`:

```bash
python3 invoke_assessment.py --cloud azure \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --output-dir out
```

If the credentials see exactly one enabled subscription, `--subscription` can
be omitted.

**GCP** — authenticates via Application Default Credentials
(`gcloud auth application-default login` or a service-account key) with a
read-only role such as `roles/viewer`:

```bash
python3 invoke_assessment.py --cloud gcp --project my-project --output-dir out
```

**Kubernetes** — authenticates via the current (or named) kubeconfig context
with a read-only ClusterRole such as one aggregated from the built-in `view`
role:

```bash
python3 invoke_assessment.py --cloud k8s --kube-context my-cluster --output-dir out
```

If `--kube-context` is omitted, the kubeconfig's `current-context` is used.

### 5. Validation profile (requires a signed, scoped engagement)

```bash
python3 sign_engagement.py --engagement engagement.json --key-file engagement.key
python3 invoke_assessment.py \
  --profile Validation \
  --engagement engagement.json \
  --engagement-key-file engagement.key \
  --regions us-east-1 \
  --output-dir out
```

The run refuses to start unless the engagement sets
`activeValidationApproved: true`, contains explicit account and applicable
region scope, has a valid HMAC signature, and the current time is inside its
complete start/end window. See
[`schemas/engagement.example.json`](schemas/engagement.example.json) and the
matching [`schemas/engagement.schema.json`](schemas/engagement.schema.json).

### CLI reference

| Flag | Default | Purpose |
|---|---|---|
| `--cloud` | `aws` | Cloud provider to assess (`aws`, `azure`, `gcp`, `k8s`) |
| `--profile` | `Assessment` | Authorization profile (`Inventory`, `Assessment`, `Validation`, `AdversarySimulation`) |
| `--regions` | `us-east-1` | Regions evaluated by per-region AWS controls (space-separated); Azure/GCP/K8s controls are subscription/project/cluster scoped |
| `--catalog` | the selected cloud's catalog | Control catalog path |
| `--baseline` | the selected cloud's CIS baseline | Threshold/override baseline path |
| `--engagement` | none | Signed engagement authorization file (required for active profiles) |
| `--engagement-key-file` | none | Shared-secret verification key (required for active profiles; see [`sign_engagement.py`](sign_engagement.py)) |
| `--previous-findings` | none | Prior run's `findings.json` to diff against (adds `DeltaStatus` + `findings-resolved.json`) |
| `--aws-profile` | none | Named AWS credentials profile (read-only) |
| `--subscription` | discovered if unambiguous | Azure subscription ID |
| `--project` | ADC default project | GCP project ID |
| `--kube-context` | kubeconfig's `current-context` | Kubernetes context to assess |
| `--kubeconfig` | standard kubeconfig locations / `KUBECONFIG` | Path to a kubeconfig file |
| `--max-workers` | `1` | AWS only: evaluate this many regions concurrently (sequential by default) |
| `--output-dir` | `csaf-output` | Parent directory; each assessment gets a unique run subdirectory |
| `--export` | none | Additionally write findings in interoperability formats (`sarif`, `oscal`); space-separated. Additive — never replaces `findings.json`/`findings.csv` |
| `--attest-key-file` | none | Shared-secret key; writes `attestation.json` signing the run manifest (verify later with `csaf-attest verify <run-dir> --key-file ...`) |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| `--check-only` | off | Preflight — validate profile, engagement, scope, and catalog selection, then exit without contacting the cloud or writing reports |
| `--self-check` | off | Offline run with synthetic data, no cloud calls |
| `--preflight` | off | Dependency-aware local prerequisite check; no cloud calls or reports |
| `--plan` | off | Deterministic no-network control and scope preview |
| `--tutorial` | off | Run the safe offline fixture tutorial and verify `manifest.json` |
| `--cleanup-tutorial` | off | Remove only a tutorial output directory explicitly named by `--output-dir` |
| `--no-color` | off | Plain terminal output without color or decorative styling |
| `--output-format` | `text` | Format preflight/plan output as `text` or `json` |
| `--explain` | none | Print a control's intent, expected state, mappings, and remediation (offline), then exit |
| `--help` | off | Show the CLI help and exit |

### Companion commands

Besides `csaf-assess` and `csaf-sign-engagement`, the package installs focused,
read-only helper commands (all offline, none perform cloud calls):

| Command | Purpose |
|---|---|
| `csaf-campaign` | Create/sign/verify/run a signed, replayable assessment **campaign** (reproducible runs) |
| `csaf-attest` | Sign (`sign`) and verify (`verify`) an **attested evidence bundle** over a run's manifest |
| `csaf-drift` | Compare two runs' `findings.json` and alert on **new/resolved** findings (exit non-zero to gate cron/CI) |
| `csaf-aggregate` | Roll several run directories into one **org-wide** report with cross-scope control failures |
| `csaf-detection-pack` | Build a **purple-team** detection-coverage pack (benign, defender-focused validation markers) |
| `csaf-attack-path` | Read-only IAM **privilege-escalation path** analysis over a provided IAM snapshot |
| `csaf-lint-catalog` | Validate a control catalog (schema + module/check resolution) |
| `csaf-new-module` | Print a new assessment-module scaffold + catalog stub |

Active (non-destructive) validation checks additionally inherit engagement
gating from `AssessmentModule.active_validation` — a `Validation`/
`AdversarySimulation` check that a signed engagement did not approve returns
`NotTested` (fail-closed) rather than running.

### Concurrency model

`--max-workers` parallelizes evaluation across **AWS regions**, which are
independent partitions each given its own isolated cache. It is AWS-only by
design. Azure, GCP, and Kubernetes assess a single subscription / project /
cluster whose collection APIs already return resources across all locations in
one pass, so there is no equivalent partition to parallelize; the only parallel
unit would be modules, which share one memoization cache and one provider
session whose SDK client is not guaranteed thread-safe. Those providers are
therefore evaluated sequentially (a safe default) and ignore `--max-workers`.

## Authorization profiles

| Profile | Read-only | Extra behaviour | Authorization |
|---|---|---|---|
| `Inventory` | yes | Reserved; current catalogs select no Inventory controls, so the runner exits `1` | None |
| `Assessment` | yes | Default posture assessment | None |
| `Validation` | yes | Adds non-destructive policy validation controls | Requires signed, approved, in-window, explicitly scoped engagement |
| `AdversarySimulation` | yes | Validation's control set, narrowed to only MITRE ATT&CK-mapped controls | Requires signed, approved, in-window, explicitly scoped engagement |

Validation-only controls (marked `validationOnly` in the catalog) are excluded
from `Inventory` and `Assessment` selections. `AdversarySimulation` is not an
alias of `Validation`: `Catalog.for_profile()` further filters its selection
to controls carrying at least one `MITRE:` mapping, so a run prioritizes
exactly the controls relevant to attacker tradecraft rather than duplicating
`Validation`'s full set under a different name. The framework itself stays
identically read-only under both profiles — only the *selected controls*
differ.

The runner treats a profile that selects zero controls as a fatal
configuration error rather than reporting a misleading successful `0/0`
assessment.

## Exit codes

- `0` — all selected controls executed, no execution errors.
- `2` — completed, but one or more selected controls were `NotTested` or errored
  (`CompletedWithErrors`). Inspect `coverage-report.csv`.
- `1` — fatal runner or prerequisite failure (e.g. unauthorized profile, account
  outside the engagement scope, unreadable catalog or baseline). Fatal failures
  are returned as an exit code with a logged reason — never an unhandled
  traceback.

## Architecture and data flow

```text
invoke_assessment.py (CLI)
        │  argparse -> RunConfig
        ▼
csaf/runner.py (orchestration + exit-code policy)
        │
        ├─ catalog.py      loads controls/control-catalog.json, filters by profile
        ├─ baseline.py     merges customer thresholds over defaults,
        │                  applies severity overrides + not-applicable exclusions
        ├─ engagement.py   authorizes the profile, scope, and time window
        │
        ├─ selfcheck.py    (offline) deterministic synthetic results
        │     — or —
        ├─ clouds/aws/provider.py
        │       │  groups controls by module; global modules (identity, s3)
        │       │  run once, regional modules (compute, network, logging,
        │       │  kms, rds) run per authorized region; attestation controls
        │       │  are answered from the engagement file
        │       ▼
        │  clouds/base.py AssessmentModule.evaluate()
        │       │  dispatches control.check to the module method;
        │       │  any exception -> one Error result (never a pass)
        │       ▼
        │  clouds/aws/modules/*.py  check functions
        │       │  every AWS call goes through clouds/aws/session.py
        │       │  ReadOnlyClient (mutating verbs raise ReadOnlyViolation)
        │       ▼
        │  ControlResult objects (model.py, schema 3.0)
        │
        ├─ model.py        findings derived from Fail/Review results only
        ├─ coverage.py     per-control rollup + weighted risk score
        ├─ compliance.py   CIS / NIST / MITRE rollup from control mappings
        ├─ reporting.py    JSONL/CSV/JSON/HTML artifacts
        └─ evidence.py     raw evidence store + SHA-256 manifest
```

Key components:

- **`csaf/model.py`** — controlled vocabularies (statuses, severities,
  confidences), `ControlResult`, `Finding`, deterministic finding IDs, and the
  `finding_from_result` normalisation (`Review` findings are floored at
  `MEDIUM` because an unconfirmed weakness is not dismissible).
- **`csaf/clouds/base.py`** — the module dispatcher. A check may return one
  result, a list of per-resource results, or `None`; anything it raises becomes
  a single `Error` result. `Pass`/`NotApplicable`/`NotTested` results are
  forced to `INFO` severity so passing controls never inflate risk.
- **`csaf/clouds/aws/session.py`** — `ReadOnlyClient` proxy allowing only
  non-mutating operations (`describe_*`, `list_*`, `get_*`, `head_*`,
  `lookup_*`, `batch_get_*`, credential-report generation, and read-only
  `simulate_*`); everything else raises `ReadOnlyViolation`. Paginators are
  guarded the same way.
- **`csaf/clouds/aws/provider.py`** — orchestrates modules across regions with
  a shared per-scope cache (the credential report, bucket list, instance and
  trail inventories are each collected once per scope, then reused by every
  check in that scope). Regional-module evaluation is sequential by default;
  `--max-workers N` evaluates up to `N` regions concurrently via a thread
  pool. Each region gets its own cache (never shared across threads), and
  module instances are stateless, so no locking is needed there; the logger
  itself is lock-protected so concurrent region logs never interleave into
  corrupted lines.

## Coverage semantics

A control may produce many results (one per resource, one per region). Coverage
rolls them up to a single status per control using a dominance ranking:

```text
Error > Fail > Review > Pass > NotApplicable > NotTested
```

- **`Error` dominates everything**, including `Pass` and `Fail`: a control that
  errored in any region did not fully execute, so it counts as `Error` in
  coverage and forces exit code `2`. The `Fail` results it did produce still
  become findings — findings derive from the raw per-result statuses, not the
  rollup — so an execution error can hide neither a weakness nor itself.
- **`Fail`/`Review` dominate `Pass`**: a weakness on any resource is never
  averaged away by other resources passing.
- Any selected control with no result at all is counted `NotTested` (this is
  how an unimplemented or unregistered module surfaces).

The weighted risk score counts `Fail`/`Review` results by severity
(`CRITICAL=40, HIGH=20, MEDIUM=10, LOW=3`), halves the sum, and saturates at
100. Ratings: `>=70 CRITICAL`, `>=45 HIGH`, `>=20 MEDIUM`, `>0 LOW`, else
`MINIMAL`.

## Control catalog

Each control maps to the relevant CIS Foundations benchmark, NIST SP 800-53,
and/or MITRE ATT&CK references in its catalog under [`controls/`](controls/).

### AWS — 31 controls ([`control-catalog.json`](controls/control-catalog.json))

| Category | Example controls |
|---|---|
| Identity / IAM | Root MFA, root keys, password policy, user MFA, key rotation, unused credentials, `*` admin policies, Access Analyzer |
| Privileged access | Privilege-escalation-enabling permissions (Validation-only) |
| S3 | Account block-public-access, public buckets, default encryption, TLS-only policy |
| Compute (EC2) | IMDSv2 required, EBS default encryption, public-instance exposure |
| Network | Admin-port ingress from `0.0.0.0/0`, default SG restricted, VPC flow logs |
| Logging / detection | Multi-region CloudTrail, log validation, KMS encryption, Config, GuardDuty |
| KMS / RDS | Customer-managed key rotation; RDS encryption at rest, public accessibility |
| Secrets | Secrets Manager rotation enabled, customer-managed KMS encryption |
| Operations | Break-glass procedure (operator attestation) |

### Azure — 16 controls ([`control-catalog-azure.json`](controls/control-catalog-azure.json))

| Category | Example controls |
|---|---|
| Privileged access | No custom subscription-admin roles, limited subscription Owners |
| Defender for Cloud | Standard-tier plans for core workloads, security contact configured |
| Storage | Secure transfer required, blob public access disallowed, TLS 1.2 minimum, default-deny network ACLs |
| Network | NSG admin-port ingress from Internet, Network Watcher enabled |
| Compute | VMs use managed disks |
| Logging | Subscription activity-log export, Azure SQL auditing |
| SQL / Key Vault | SQL public network access disabled; vault soft delete + purge protection |
| Operations | Break-glass procedure (operator attestation) |

### GCP — 19 controls ([`control-catalog-gcp.json`](controls/control-catalog-gcp.json))

| Category | Example controls |
|---|---|
| Identity / IAM | Service accounts without admin roles, no user-managed SA keys, SA key rotation, basic roles on users |
| Storage | No public bucket IAM grants, uniform bucket-level access |
| Network | No default network, no `0.0.0.0/0` ingress to admin ports, subnet flow logs |
| Compute | Default compute SA not used, no external IPs, OS Login, serial ports disabled |
| Logging | allServices audit config, catch-all log sink |
| KMS / Cloud SQL | CMEK rotation; Cloud SQL not open to world, TLS required |
| Operations | Break-glass procedure (operator attestation) |

### Kubernetes — 8 controls ([`control-catalog-k8s.json`](controls/control-catalog-k8s.json))

| Category | Example controls |
|---|---|
| RBAC | No non-system subject bound to `cluster-admin` |
| Pod Security | No privileged containers, no `hostNetwork` pods (outside kube-system/kube-public/kube-node-lease) |
| Network | Every workload namespace has at least one NetworkPolicy |
| Operations | Break-glass procedure, API-server audit logging, secrets encrypted at rest, and Pod Security Admission enforcement (operator attestations) |

Each catalog entry declares its `module` (implementation class), `check`
(method name), `defaultSeverity`, `expectedState`, `profiles`, and framework
`mappings`. A catalog-integrity test verifies every entry resolves to a real,
callable check and has a remediation entry, so the catalog cannot drift from
the code.

Notable check behaviours:

- The privilege-escalation check flags grants of known privesc-enabling
  actions (Rhino Security Labs matrix) including **wildcard grants** such as
  `iam:Pass*` or `iam:Attach*` (matched case-insensitively, IAM-style). Full
  `Action:*` admin policies are excluded there — they are flagged separately by
  the `*`-admin control.
- The S3 encryption check treats `AccessDenied` on a bucket as an offender
  (an unverifiable bucket is not assumed encrypted); any *unexpected* error
  aborts the check into an `Error` result rather than skipping the bucket.
- Attestation controls (e.g. break-glass procedure) are answered from the
  engagement file's `attestations` map; a missing attestation is `NotTested`,
  an unrecognized attested status is coerced to `Review`, and attestation
  confidence is always `LOW`.

## Baselines

Thresholds (password length, key age, sensitive ports, required services) live
per cloud in [`baselines/`](baselines/): `aws-cis-1.5.json`, `azure-cis-2.0.json`,
`gcp-cis-1.3.json`, and `k8s-cis-1.8.json`. Supply a customer baseline with `--baseline` to:

- **override thresholds** — customer values merge over the defaults in
  `csaf/baseline.py`, untouched keys keep their defaults;
- **override per-control severity** — `severityOverrides` maps control IDs to a
  severity applied to that control's findings;
- **exclude controls** — IDs in `notApplicableControls` are removed from the
  selection before evaluation (they do not appear in results or coverage
  denominators).

## Engagement authorization

The engagement file ([schema](schemas/engagement.schema.json),
[example](schemas/engagement.example.json)) binds a run to an authorized scope:

- `authorizedAccounts` — the runner refuses (exit `1`) to assess an account,
  subscription, project, or cluster context not listed. Active profiles require
  at least one explicit entry.
- `authorizedRegions` — every requested AWS region must be listed. Active AWS
  profiles require at least one explicit region.
- `authorizedSourceAddresses` — the local CLI cannot prove its public source
  address, so an active run containing this restriction fails closed. Enforce
  the restriction outside CSAF or omit the field.
- `windowStartUtc` / `windowEndUtc` — `Validation` and `AdversarySimulation`
  refuse to run outside the window.
- `activeValidationApproved` — must be `true` for `Validation` /
  `AdversarySimulation`; `Inventory` and `Assessment` never require it.
- `attestations` — operator-supplied answers for manual controls.
- `stopConditions` / `prohibitedActions` / `operatorContacts` — parsed and
  covered by an optional signature, but not automatically enforced.

### Engagement signing (required for active profiles)

The engagement file grants active-validation authorization by itself — a JSON
flag anyone with filesystem access could edit unnoticed. Signing binds an
approver's review to a shared secret so a later silent edit is detectable:

```bash
python3 -c "import secrets; open('engagement.key','wb').write(secrets.token_bytes(32))"
python3 sign_engagement.py --engagement engagement.json --key-file engagement.key
```

Then pass `--engagement-key-file engagement.key` to `invoke_assessment.py`.
`Validation`/`AdversarySimulation` is refused without a key or if the signature
doesn't verify — including after any edit made post-signing, since the
signature covers the full file content (minus the signature field itself).
This is HMAC (shared-secret) signing, not PKI — appropriate for an approver and
operator who already share a key out of band, not for third-party verification.
See [`csaf/engagement_signing.py`](csaf/engagement_signing.py).

## Output artifacts

```text
out/
└── <UTC timestamp>-<random>/
    ├── assessment-<ts>.log          # human-readable log
    ├── assessment-<ts>.jsonl        # structured JSON Lines log
    ├── control-results.jsonl        # every control result, one JSON object per line
    ├── control-results.csv
    ├── findings.csv                 # prioritized findings only (CRITICAL first)
    ├── findings.json
    ├── findings-resolved.json       # only written with --previous-findings
    ├── detection-coverage.json
    ├── detection-coverage.csv
    ├── coverage-report.json
    ├── coverage-report.csv
    ├── remediation-roadmap.csv
    ├── technical-report.json
    ├── executive-summary.html
    ├── manifest.json                # source revision + artifact SHA-256 inventory
    └── evidence/                    # raw collector evidence, namespaced
```

The current release writes 17 possible top-level files in the run directory;
the `evidence/` directory may contain additional raw evidence files.

Start with `coverage-report.csv` to confirm every selected control ran, then
`findings.csv` for prioritized weaknesses. `NotTested` and `Error` are never
security passes. A unique run directory prevents concurrent or repeated runs
from overwriting one another. Reports, evidence, signatures, and manifests use
same-directory temporary files followed by atomic replacement, so interrupted
writes do not replace a previously complete destination.

Every emitted AWS, Azure, GCP, and Kubernetes control result and finding
conforms to the JSON Schemas in [`schemas/`](schemas/)
(`control-result.schema.json`, `finding.schema.json`) — this is enforced by
tests against a full pipeline run, not just hand-picked examples. Catalog,
baseline, and engagement input JSON is also validated against strict packaged
schemas before it is used; unknown fields, incompatible schema versions, and
invalid known threshold types fail with an actionable fatal error. The
technical report and manifest record the source revision when
discoverable (or when `CSAF_SOURCE_REVISION` is supplied). The manifest records
`RelativePath` with forward slashes on every platform, hashes every artifact
except itself, and can be re-verified by recomputing SHA-256 over the files it
lists. Because the manifest is stored beside the artifacts and is not
independently signed, it is an integrity inventory rather than proof against
an actor who can rewrite both.

## Safety

- **Read-only guardrails.** Every provider enforces read-only access at runtime,
  independent of the IAM/RBAC role in use; violations raise `ReadOnlyViolation`
  (a `RuntimeError` subclass, so even broad `except RuntimeError` handlers stop
  the call). The guard is enforced at the proxy/transport layer *in addition
  to* the read-only role the operator is expected to use — defence in depth.
  - AWS: `csaf/clouds/aws/session.py`'s `ReadOnlyClient` wraps every boto3
    client so only non-mutating operations (`describe_*`, `list_*`, `get_*`,
    `head_*`, `lookup_*`, `batch_get_*`, credential-report generation, and
    read-only `simulate_*`) can be called. Paginators are guarded the same way.
  - Azure: `csaf/clouds/azure/session.py`'s `ArmSession` funnels every ARM REST
    call through a single choke point that only permits the `GET` verb (this
    also excludes secret-exposing POST "list" operations such as `listKeys`).
  - GCP: `csaf/clouds/gcp/session.py`'s `GcpSession` permits `GET` plus a
    narrow, exact-suffix allow-list of three read-only POST endpoints
    (`:getIamPolicy`, `:testIamPermissions`, `:searchAll`); a same-shaped
    mutating endpoint (`:setIamPolicy`) is explicitly tested as still blocked.
  - Kubernetes: `csaf/clouds/k8s/session.py`'s `ReadOnlyApiClient` wraps every
    generated API object so only `list_*`/`read_*` operations can be called;
    this specifically blocks `connect_*` (the verb prefix the client uses for
    exec/attach/port-forward), not just `create_*`/`patch_*`/`delete_*`.
- **Scope enforcement.** A configured engagement pins the cloud and any listed
  account/subscription/project/context. AWS regions must be a subset of
  `authorizedRegions`. Active profiles require nonempty explicit account scope,
  and active AWS profiles also require nonempty region scope. Read-only runs
  without an engagement remain intentionally unscoped.
- **Evidence protection.** The manifest inventories artifact hashes via
  SHA-256; it does not independently authenticate or encrypt evidence. Store
  outputs on an access-controlled, encrypted volume. Evidence can contain
  sensitive IAM and configuration data.
- **Report safety.** All untrusted values (finding titles, resource IDs,
  remediation text) are HTML-escaped before rendering into the executive
  summary.

## Testing

The suite (more than 400 tests, standard-library `unittest`, no cloud credentials and no
provider SDKs required) is designed around the framework's safety invariants:
every "never" in this README has a test asserting it. Line coverage is 94%
overall (CI gates at >= 90%; see [Continuous integration](#continuous-integration)).

```bash
python3 -m unittest discover -s tests -v
```

With line coverage (CI enforces >= 90% over `csaf/` + the CLI):

```bash
python3 -m coverage run --source=csaf,invoke_assessment -m unittest discover -s tests
python3 -m coverage report --show-missing
```

### Test layout

| File | Covers |
|---|---|
| `tests/fakes.py` | Shared test doubles: `FakeClient`/`FakeSession` (canned per-operation responses, paginators, call recording) and `make_ctx` for building real `CheckContext` objects |
| `test_model.py` | Status/severity vocabularies, finding derivation, deterministic object-aware finding IDs |
| `test_coverage.py` | Rollup dominance (`Error` > `Fail` > `Review` > `Pass`), missing-result -> `NotTested`, risk-score rating boundaries, `Error`/`NotTested` never contribute risk |
| `test_catalog.py` / `test_catalog_integrity.py` | Catalog loading, unique IDs, profile filtering, every control resolves to a real check and remediation |
| `test_engagement.py` | Profile authorization, approval + window requirements, account scoping |
| `test_baseline.py` | Threshold merging, severity overrides, not-applicable parsing, the shipped CIS baseline |
| `test_readonly.py` | Guardrail verb sweep (27 mutating operations blocked, 10 read verbs allowed), paginator guard, attribute passthrough |
| `test_base_module.py` | Dispatcher: exceptions -> single `Error` result, missing checks -> `Error`, severity normalisation, baseline overrides, metadata propagation |
| `test_provider.py` | Global vs per-region dispatch, unknown modules -> `NotTested`, one region erroring doesn't stop others, attestation handling |
| `test_module_identity.py` | Credential-report checks (root MFA/keys/activity, user MFA, key rotation boundaries, unused credentials), password policy, `*`-admin and privesc policy analysis, IAM wildcard matching |
| `test_module_s3.py` | Public-access block, policy- and ACL-public buckets, fail-closed inspection errors, encryption (`AccessDenied` counts as an offender; unexpected errors raise), TLS-only policies, bucket-list caching |
| `test_module_compute.py` | `_covered_ports`/`_has_public_cidr` tables, IMDSv2, EBS default encryption, public-instance exposure, inventory caching |
| `test_module_network.py` | Admin-port ingress (incl. custom baseline ports), default-SG rules, VPC flow logs |
| `test_module_kms_rds.py` | KMS rotation (only enabled customer symmetric keys evaluated), RDS encryption and public access |
| `test_module_logging.py` | CloudTrail multi-region/validation/KMS, Config recorder, GuardDuty detectors, trail caching |
| `test_compliance.py` | Framework rollup: evaluated/passed/failed counting, `Error`/`NotTested` excluded, unknown prefixes ignored |
| `test_evidence.py` | SHA-256 known vector, namespaced evidence store, manifest completeness, source revision, file-metadata timestamps, forward-slash paths, tamper detection |
| `test_reporting.py` | CSV/JSONL row integrity, severity ordering, remediation horizons, HTML escaping of hostile values, incomplete-coverage banner |
| `test_runner_selfcheck.py` | End-to-end offline pipeline: all artifacts produced, findings are a strict subset of Fail/Review controls |
| `test_runner_paths.py` | Unauthorized/out-of-window profiles -> exit `1`, missing catalog / malformed baseline -> fatal result (no traceback), baseline exclusions change selection, fully-executed run -> exit `0`, structured log content |
| `test_cli.py` | Argument defaults and validation, `--version`, exit-code propagation through `main()` |
| `test_logging.py` | Level filtering, JSONL structure and extra fields, console-only operation |
| `test_schema.py` | Every record from all four cloud self-check runs validates against the JSON Schemas; manifest hashes re-verify against the artifacts on disk |
| `test_ci_config.py` | CI workflow keeps its gates (lint, tests, coverage >= 90%, pip-audit, read-all permissions) |
| `test_readonly_azure_gcp.py` | Azure `ArmSession` (GET-only and ARM-host-pinned) and GCP `GcpSession` (GET + narrow read-only-POST allow-list) guardrails |
| `test_readonly_k8s.py` | Kubernetes `ReadOnlyApiClient` guardrail: `list_*`/`read_*` allowed, `create_*`/`delete_*`/`patch_*`/`replace_*` blocked, and `connect_*` (exec/attach/port-forward) specifically blocked |
| `test_provider_azure_gcp.py` | Azure/GCP provider dispatch: subscription/project-scoped module routing, attestation handling, unknown modules, module-instance reuse |
| `test_provider_k8s.py` | Kubernetes provider dispatch: cluster-scoped module routing, attestation handling, unknown modules, module-instance reuse |
| `test_module_azure_*.py` | All eight Azure check modules (identity, defender, storage, network, compute, monitor, sql, keyvault) against faked ARM responses |
| `test_module_gcp_*.py` | All seven GCP check modules (identity, storage, network, compute, logging, kms, sql) against faked GCP REST responses |
| `test_module_k8s_*.py` | All three Kubernetes check modules (rbac, pods, network) against faked API responses |

### Testing approach

- **No mocking framework, no network.** Check modules receive a `CheckContext`
  whose `session` is a `tests/fakes.py` fake (`FakeSession` for AWS,
  `FakeArmSession`/`FakeGcpSession`/`FakeK8sSession` for the others) serving
  canned API responses — checks are exercised byte-for-byte as in production,
  including evidence writes and baseline threshold lookups. Response values can
  be per-call callables (e.g. keyed on `Bucket`) or `Exception` instances to
  simulate API errors. Kubernetes fakes use `types.SimpleNamespace` to mirror
  the real client's attribute-style typed objects (`item.metadata.name`, etc.).
- **Invariant pinning.** The dangerous properties — mutating calls blocked,
  errors never passing, findings a strict subset, coverage never masking an
  error — each have dedicated tests, so a regression fails loudly.
- **Schema conformance as a gate.** `test_schema.py` runs the full pipeline and
  validates *every* emitted record, so the schemas, the dataclasses, and the
  writers cannot drift apart.
- **Config guarded by tests.** `test_ci_config.py` fails if a CI gate is
  removed; `test_catalog_integrity.py` fails if a catalog entry loses its
  implementation or remediation.

## Continuous integration

`.github/workflows/ci.yml` runs on push, PR, and manual dispatch with read-only
permissions and these gates:

- Ruff lint and format checks
- `pip-audit` dependency vulnerability audit
- CycloneDX SBOM generation (`pip-audit --format cyclonedx-json`), uploaded as
  a build artifact
- Python 3.10 / 3.12 / 3.14 unit-test matrix
- Line-coverage gate: `coverage report --fail-under=90` over `csaf/` and the CLI
- Dependency preflight and offline self-check report generation
- Hash-locked dependency installation
- Source/wheel build, metadata verification, and an installed-wheel smoke test
  executed outside the repository

`.github/workflows/release.yml` runs for `v*` tags. It builds the wheel and
source distribution with the commit revision embedded, verifies them, produces
a CycloneDX SBOM and SHA-256 checksums, smoke-tests the installed wheel, creates
GitHub artifact provenance and SBOM attestations, uploads the complete release
bundle, and publishes a GitHub Release. Verify a downloaded distribution with
`gh attestation verify <file> --repo <owner>/<repo>` and compare its digest to
`SHA256SUMS`.

Run locally:

```bash
pip install --require-hashes -r requirements-lock.txt
ruff check csaf tests invoke_assessment.py test_dependencies.py sign_engagement.py
ruff format --check csaf tests invoke_assessment.py test_dependencies.py sign_engagement.py
python3 -m coverage run --source=csaf,invoke_assessment -m unittest discover -s tests
python3 -m coverage report --fail-under=90
python3 invoke_assessment.py --self-check --output-dir out
```

## Repository layout

```text
.
├── invoke_assessment.py         # main runner (CLI)
├── test_dependencies.py         # preflight
├── sign_engagement.py           # HMAC-sign/verify an engagement file
├── pyproject.toml               # packaging + plugin entry-point group declarations
├── csaf/                        # framework package
│   ├── model.py                 # statuses, control results, findings, IDs
│   ├── catalog.py               # control catalog + profile filtering
│   ├── baseline.py              # thresholds, severity overrides, exclusions
│   ├── engagement.py            # authorization profiles, scope, window, signature check
│   ├── engagement_signing.py    # HMAC-SHA256 sign/verify primitives
│   ├── delta.py                 # findings delta vs a prior run (New/Persisted/Resolved)
│   ├── detection_coverage.py    # per-MITRE-technique Gap/Covered/Unknown rollup
│   ├── plugins.py               # third-party module discovery (entry points)
│   ├── coverage.py              # coverage accounting + risk scoring
│   ├── compliance.py            # framework rollup from mappings
│   ├── reporting.py             # JSON/JSONL/CSV/HTML outputs
│   ├── evidence.py              # evidence store + SHA-256 manifest
│   ├── logging_.py              # console + JSONL logging
│   ├── remediation.py           # remediation guidance by control
│   ├── runner.py                # orchestration + exit-code policy
│   ├── selfcheck.py             # offline synthetic provider (per cloud)
│   └── clouds/
│       ├── base.py              # module dispatcher (errors -> Error results)
│       ├── aws/                 # AWS provider, ReadOnlyClient guardrail, modules
│       │   ├── provider.py      # global/regional dispatch + attestations
│       │   ├── session.py       # ReadOnlyClient guardrail
│       │   └── modules/         # identity, s3, compute, network, logging, kms, rds
│       ├── azure/               # Azure provider, ArmSession (GET-only) guardrail, modules
│       ├── gcp/                 # GCP provider, GcpSession (GET + read-only-POST allow-list) guardrail, modules
│       └── k8s/                 # K8s provider, ReadOnlyApiClient (list_*/read_* only) guardrail, modules
├── controls/                    # control-catalog{,-azure,-gcp,-k8s}.json
├── baselines/                   # aws-cis-1.5, azure-cis-2.0, gcp-cis-1.3, k8s-cis-1.8
├── schemas/                     # finding / control-result / engagement / manifest
├── tests/                       # unit + integration + end-to-end tests (see Testing)
│   └── fakes.py                 # shared FakeClient/FakeSession/make_ctx doubles
├── reference/                   # original red-team docs (reference-only)
├── docs/test-execution/         # per-cloud test execution reports (unit tests + self-check evidence)
└── .github/workflows/ci.yml
```

## Extending to other clouds

Add a provider package under `csaf/clouds/<cloud>/` that exposes an
`evaluate(controls, regions)` method returning `ControlResult` objects, add a
matching control catalog and baseline, and register the cloud in
`csaf/runner.py`'s `CLOUDS` table. The Azure, GCP, and Kubernetes providers
are compact references for the pattern: a guarded read-only session, a module
registry, and a provider that dispatches catalog controls to check methods
(Azure/GCP/Kubernetes all evaluate once at a single "global" scope since none
has AWS's per-region structure). The core (engagement, coverage, findings,
reporting, manifest) is cloud-agnostic and reused as-is.

When adding checks:

1. Subclass `AssessmentModule`; each catalog `check` names a method taking
   `(control, ctx)` and returning a result, a list of per-resource results, or
   `None`. Raise freely — the dispatcher converts exceptions to `Error`.
2. Route every API call through a guarded read-only session.
3. Cache shared inventories in `ctx.cache` so multiple controls don't re-enumerate.
4. Add a remediation entry in `csaf/remediation.py` and mappings in the catalog
   (`test_catalog_integrity.py` enforces both).
5. Test the module with `tests/fakes.py` doubles — pass/fail/`NotApplicable`
   branches, error propagation, and threshold boundaries.

### Third-party modules (plugins)

Modules don't have to live in-tree. Any installed distribution can contribute
additional check modules via a Python entry point in the matching group
(`csaf.modules.aws`, `csaf.modules.azure`, `csaf.modules.gcp`, or `csaf.modules.k8s`):

```toml
[project.entry-points."csaf.modules.aws"]
my_service = "my_csaf_extra.aws:MyServiceModule"
```

`pip install`-ing that distribution makes `MyServiceModule` available under
the catalog `module` key `my_service` — no change to CSAF itself. Built-in
modules always win on a name collision (a plugin can't silently shadow a
core control's implementation), and a plugin that fails to load only drops
that one plugin, never the built-ins. See
[`csaf/plugins.py`](csaf/plugins.py) and [`pyproject.toml`](pyproject.toml).

**Trust model.** An installed plugin runs in-process with full trust, so
installing one is an explicit trust decision. For locked-down environments, set
`CSAF_PLUGIN_ALLOWLIST` to a comma-separated list of entry-point names that may
load; any other plugin is skipped (fail closed). Unset loads every installed
plugin (default); an empty value loads none.

### Authoring tools

Two console scripts help you write correct catalogs and modules:

- `csaf-lint-catalog path/to/control-catalog.json` — validates a catalog
  against the packaged JSON Schema and runs semantic checks the schema can't
  express, most importantly that every control's `module`/`check` pair resolves
  to a real check method in the (built-in or plugin) registry for its cloud.
  Exits non-zero on errors; add `--strict` to fail on warnings too.
- `csaf-new-module --cloud aws --module eventbridge` — prints a ready-to-edit
  `AssessmentModule` scaffold plus a matching catalog-entry stub and the one
  registry line needed to wire it in.

Both are offline and read-only. See [`csaf/authoring.py`](csaf/authoring.py).

## Authorized use

CSAF is for authorized security assessments only. Run it against accounts,
subscriptions, projects, or clusters you own or are explicitly authorized to
assess, using least-privilege read-only credentials, and protect the output
directory.
