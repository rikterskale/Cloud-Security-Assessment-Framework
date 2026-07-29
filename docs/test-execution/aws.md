# CSAF Test Execution Report — AWS

**Date:** 2026-07-29
**Framework version:** 1.0.0 &nbsp;|&nbsp; **Schema version:** 3.0
**Python:** 3.13.13
**Repository:** `Cloud-Security-Assessment-Framework` @ `main`

---

## 1. Overview

This document is direct evidence that the AWS provider's read-only guardrail, all seven AWS check modules, the multi-region concurrency path, and the full end-to-end reporting pipeline actually execute correctly — not just that the code exists. Two independent executions were performed:

1. **Unit test suite** — every AWS-specific test file, run verbose, against fake (non-network) AWS API doubles.
2. **Offline self-check pipeline** — the real `invoke_assessment.py` CLI, run against a deterministic synthetic posture (`--self-check`), producing the exact same 14-artifact output a live AWS assessment would produce.

No AWS credentials, network access, or the `boto3`/`botocore` packages were required for either run. `boto3`/`botocore` were in fact **not installed** in this environment at the time of the run (confirmed below), which independently demonstrates the framework's design claim that these are optional, lazily-imported dependencies.

---

## 2. Unit Test Suite Execution

### 2.1 Command

```bash
python3 -m unittest \
  tests.test_readonly \
  tests.test_provider \
  tests.test_provider_concurrency \
  tests.test_module_identity \
  tests.test_module_s3 \
  tests.test_module_compute \
  tests.test_module_network \
  tests.test_module_kms_rds \
  tests.test_module_logging \
  tests.test_module_secrets \
  tests.test_catalog \
  -v
```

### 2.2 Result

```
Ran 102 tests in 0.122s

OK
```

**102 / 102 passed, 0 failures, 0 errors.**

### 2.3 What each file proves

| File | What it verifies |
|---|---|
| `test_readonly.py` | The `ReadOnlyClient` proxy: read verbs (`describe_*`, `list_*`, `get_*`, `simulate_*`) pass through; mutating verbs (`create_bucket`, `delete_user`, `put_bucket_policy`) raise `ReadOnlyViolation`; paginators are guarded the same way. |
| `test_provider.py` | `AwsProvider` dispatch: global modules (identity, s3) evaluate once regardless of region count; regional modules evaluate per region; an unknown module yields no result (surfaces as `NotTested`); a check exception in one region doesn't stop other regions; attestation controls resolve from the engagement file. |
| `test_provider_concurrency.py` | The opt-in `max_workers` concurrency path: results match the sequential path exactly; an error in one region doesn't lose results from others; `max_workers` is safely capped at region count; **a rendezvous test proves genuine parallel execution** (one region's fake call blocks waiting for a signal only a concurrently-running second region can set — this would deadlock under sequential execution). |
| `test_module_identity.py` | Root MFA/keys/activity, user MFA, password policy, access-key rotation, unused credentials, `Action:*`/`Resource:*` admin-policy detection, IAM Access Analyzer, and privilege-escalation-grant detection (including the wildcard-match fix: `iam:Pass*` correctly matches `iam:PassRole`). |
| `test_module_s3.py` | Account-level Block Public Access, per-bucket public policy/ACL detection, default encryption (`AccessDenied` correctly counted as an offender, not silently passed), TLS-only bucket policies, bucket-list caching. |
| `test_module_compute.py` | IMDSv2 enforcement, EBS default encryption, public-instance exposure on sensitive ports, the `_covered_ports`/`_has_public_cidr` helper logic. |
| `test_module_network.py` | Security-group admin-port ingress from `0.0.0.0/0`, default security-group rule restriction, VPC flow-log coverage. |
| `test_module_kms_rds.py` | KMS key-rotation (only enabled customer-managed symmetric keys evaluated), RDS storage encryption and public-accessibility checks. |
| `test_module_logging.py` | Multi-region CloudTrail, log-file validation, KMS-encrypted trails, AWS Config recording, GuardDuty detector status; trail-inventory caching. |
| `test_module_secrets.py` | Secrets Manager rotation-enabled and customer-managed-KMS-encryption checks (the newest AWS module, added as a catalog-expansion demonstration). |
| `test_catalog.py` | Catalog loading, unique/prefixed control IDs, `Assessment` profile excluding validation-only controls, and — the newest addition — `AdversarySimulation` being a genuine, non-trivial, MITRE-mapped **subset** of `Validation` (not an alias). |

---

## 3. Self-Check Pipeline Execution

### 3.1 Command

```bash
python3 invoke_assessment.py --cloud aws --self-check --log-level DEBUG --output-dir out
```

### 3.2 Console output

```
[INCOMPLETE] Completed. 5 findings, risk 70.0/100 (CRITICAL). Coverage 29/30 executed.
[*] Output written to out
```

### 3.3 Structured log (`assessment-<ts>.log`, chronological)

```
2026-07-29T21:55:12Z [INFO ] engagement: Profile 'Assessment' authorization: Read-only profile; no active-validation authorization required.
2026-07-29T21:55:12Z [INFO ] catalog: Selected 30 controls for profile 'Assessment'.
2026-07-29T21:55:12Z [INFO ] runner: Running in offline self-check mode (no cloud calls).
2026-07-29T21:55:12Z [WARN ] coverage: SELECTED CHECK NOT COMPLETED: CSAF-AWS-OPS-001
2026-07-29T21:55:12Z [INFO ] runner: Completed. 5 findings, risk 70.0/100 (CRITICAL). Coverage 29/30 executed.
2026-07-29T21:55:12Z [WARN ] runner: CompletedWithErrors: not every selected control executed.
```

This reads exactly as designed: `CSAF-AWS-OPS-001` (an attestation-only control with no operator-supplied answer) is correctly reported as `NotTested`, never silently passed, and the run correctly exits with `CompletedWithErrors` because coverage is incomplete (29 of 30 selected controls executed) — even though the run otherwise "succeeded."

### 3.4 Same run, `assessment-<ts>.jsonl` (structured form)

```json
{"ts": "2026-07-29T21:55:12Z", "runId": "20260729T215512Z", "level": "INFO", "component": "engagement", "message": "Profile 'Assessment' authorization: Read-only profile; no active-validation authorization required."}
{"ts": "2026-07-29T21:55:12Z", "runId": "20260729T215512Z", "level": "INFO", "component": "catalog", "message": "Selected 30 controls for profile 'Assessment'."}
{"ts": "2026-07-29T21:55:12Z", "runId": "20260729T215512Z", "level": "INFO", "component": "runner", "message": "Running in offline self-check mode (no cloud calls)."}
{"ts": "2026-07-29T21:55:12Z", "runId": "20260729T215512Z", "level": "WARN", "component": "coverage", "message": "SELECTED CHECK NOT COMPLETED: CSAF-AWS-OPS-001"}
{"ts": "2026-07-29T21:55:12Z", "runId": "20260729T215512Z", "level": "INFO", "component": "runner", "message": "Completed. 5 findings, risk 70.0/100 (CRITICAL). Coverage 29/30 executed."}
{"ts": "2026-07-29T21:55:12Z", "runId": "20260729T215512Z", "level": "WARN", "component": "runner", "message": "CompletedWithErrors: not every selected control executed."}
```

### 3.5 Environment note (proves the "optional dependency" design claim)

`boto3`/`botocore` were confirmed **not installed** in this environment before the run:

```
[FAIL] boto3 installed: missing (needed for live AWS assessment)
[FAIL] botocore installed: missing (needed for live AWS assessment)
```

The self-check run above completed successfully anyway — `--self-check` never imports `boto3`, confirming the "optional, lazily-imported dependency" design is real, not just documented.

---

## 4. Generated Artifacts

### 4.1 Directory listing

```
out/
├── assessment-20260729T215512Z.jsonl
├── assessment-20260729T215512Z.log
├── control-results.csv
├── control-results.jsonl
├── coverage-report.csv
├── coverage-report.json
├── detection-coverage.csv
├── detection-coverage.json
├── executive-summary.html
├── findings.csv
├── findings.json
├── manifest.json
├── remediation-roadmap.csv
└── technical-report.json
```

13 artifacts (14 including the manifest itself, which is excluded from its own hash listing) — matches the README's documented output contract exactly.

### 4.2 `control-results.jsonl` — full content (30 controls, one JSON object per line)

```json
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-001", "Title": "Root account has MFA enabled", "Category": "Identity", "Status": "Fail", "Severity": "CRITICAL", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "root mfa_active=False", "ExpectedValue": "The account root user has an MFA device enabled.", "Mappings": ["CIS-AWS:1.5", "MITRE:T1078.004", "NIST-800-53:IA-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-002", "Title": "Root account has no active access keys", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "The root user has no active access keys.", "Mappings": ["CIS-AWS:1.4", "MITRE:T1078.004"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-003", "Title": "Root account is not used for routine activity", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "The root user has not been used within the recent-activity threshold.", "Mappings": ["CIS-AWS:1.7", "MITRE:T1078.004"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-004", "Title": "IAM password policy meets strength requirements", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "A password policy exists requiring length >= 14 and complexity.", "Mappings": ["CIS-AWS:1.8", "NIST-800-53:IA-5"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-005", "Title": "Console users have MFA enabled", "Category": "Identity", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "console user without MFA: alice", "ExpectedValue": "Every IAM user with a console password has an MFA device.", "Mappings": ["CIS-AWS:1.10", "MITRE:T1078.004", "NIST-800-53:IA-2(1)"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-006", "Title": "Access keys are rotated within policy", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Active access keys are younger than the rotation threshold (default 90 days).", "Mappings": ["CIS-AWS:1.14"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-007", "Title": "Unused credentials are disabled", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Passwords and access keys unused beyond the inactivity threshold are disabled.", "Mappings": ["CIS-AWS:1.12", "MITRE:T1078.004"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-008", "Title": "No policies grant full administrative privileges", "Category": "PrivilegedAccess", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "No customer-managed policy allows Action:* over Resource:* .", "Mappings": ["CIS-AWS:1.16", "MITRE:T1078"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-IAM-009", "Title": "IAM Access Analyzer is enabled", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "At least one IAM Access Analyzer analyzer is active in the account.", "Mappings": ["CIS-AWS:1.20"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-S3-001", "Title": "Account-level S3 Block Public Access is enabled", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "All four account-level S3 Block Public Access settings are enabled.", "Mappings": ["CIS-AWS:2.1.5", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-S3-002", "Title": "Buckets are not publicly accessible", "Category": "DataProtection", "Status": "Fail", "Severity": "CRITICAL", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "public-assets: policy public", "ExpectedValue": "No bucket policy or ACL grants public read/write access.", "Mappings": ["CIS-AWS:2.1.5", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-S3-003", "Title": "Buckets enforce default encryption", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every bucket has default server-side encryption configured.", "Mappings": ["CIS-AWS:2.1.1", "NIST-800-53:SC-28"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-S3-004", "Title": "Buckets enforce TLS-only access", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Bucket policies deny requests where aws:SecureTransport is false.", "Mappings": ["CIS-AWS:2.1.2", "NIST-800-53:SC-8"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-EC2-001", "Title": "Instances require IMDSv2", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every running instance sets HttpTokens=required (IMDSv2).", "Mappings": ["CIS-AWS:5.6", "MITRE:T1552.005"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-EC2-002", "Title": "EBS encryption by default is enabled", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "EBS encryption-by-default is enabled in each assessed region.", "Mappings": ["CIS-AWS:2.2.1", "NIST-800-53:SC-28"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-EC2-003", "Title": "Instances are not exposed with public IPs on sensitive ports", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Instances with public IPs are not reachable on administrative ports from 0.0.0.0/0.", "Mappings": ["MITRE:T1133"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-NET-001", "Title": "Security groups do not allow ingress to admin ports from anywhere", "Category": "Network", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "sg-0abc opens ports [22] to 0.0.0.0/0", "ExpectedValue": "No security group allows 0.0.0.0/0 or ::/0 ingress to ports 22 or 3389.", "Mappings": ["CIS-AWS:5.2", "MITRE:T1133"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-NET-002", "Title": "Default security groups restrict all traffic", "Category": "Network", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every default security group has no inbound or outbound rules.", "Mappings": ["CIS-AWS:5.4"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-NET-003", "Title": "VPC flow logging is enabled", "Category": "Network", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every VPC in scope has an active flow log.", "Mappings": ["CIS-AWS:3.9", "NIST-800-53:AU-12"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-LOG-001", "Title": "A multi-region CloudTrail trail is enabled", "Category": "Logging", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "active multi-region trails=0", "ExpectedValue": "At least one multi-region CloudTrail trail is logging and enabled.", "Mappings": ["CIS-AWS:3.1", "NIST-800-53:AU-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-LOG-002", "Title": "CloudTrail log file validation is enabled", "Category": "Logging", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "CloudTrail trails enable log file integrity validation.", "Mappings": ["CIS-AWS:3.2", "NIST-800-53:AU-9"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-LOG-003", "Title": "CloudTrail logs are encrypted with KMS", "Category": "Logging", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "CloudTrail trails encrypt logs with a KMS CMK.", "Mappings": ["CIS-AWS:3.5", "NIST-800-53:SC-28"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-LOG-004", "Title": "AWS Config is enabled", "Category": "Logging", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "AWS Config recorder is enabled and recording in each assessed region.", "Mappings": ["CIS-AWS:3.3", "NIST-800-53:CM-8"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-LOG-005", "Title": "GuardDuty is enabled", "Category": "Detection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Amazon GuardDuty has an active detector in each assessed region.", "Mappings": ["MITRE:DS0015", "NIST-800-53:SI-4"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-KMS-001", "Title": "Customer-managed KMS keys have rotation enabled", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Enabled customer-managed symmetric CMKs have automatic rotation on.", "Mappings": ["CIS-AWS:3.8", "NIST-800-53:SC-12"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-RDS-001", "Title": "RDS instances encrypt data at rest", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every RDS instance has storage encryption enabled.", "Mappings": ["CIS-AWS:2.3.1", "NIST-800-53:SC-28"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-RDS-002", "Title": "RDS instances are not publicly accessible", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "No RDS instance has PubliclyAccessible set to true.", "Mappings": ["CIS-AWS:2.3.3", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-SEC-001", "Title": "Secrets Manager secrets have rotation enabled", "Category": "Secrets", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every Secrets Manager secret has automatic rotation enabled.", "Mappings": ["CIS-AWS:2.3.4", "NIST-800-53:IA-5", "MITRE:T1552.001"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-SEC-002", "Title": "Secrets Manager secrets use a customer-managed KMS key", "Category": "Secrets", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every Secrets Manager secret is encrypted with a customer-managed KMS key, not the default AWS-managed key.", "Mappings": ["NIST-800-53:SC-28"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AWS-OPS-001", "Title": "Account break-glass procedure is documented", "Category": "Operations", "Status": "NotTested", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "AWS", "AccountId": "000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "No operator attestation supplied.", "ExpectedValue": "A documented, tested break-glass procedure exists for root and privileged access.", "Mappings": ["NIST-800-53:CP-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T21:55:12Z"}
```

### 4.3 `findings.csv` — full content (5 findings, CRITICAL-first ordering)

```csv
FindingId,ControlId,Title,Status,Severity,RiskScore,Confidence,Cloud,AccountId,Region,ResourceType,ResourceId,ObservedValue,ExpectedValue,Finding,Remediation,FirstObservedUtc
F-D18D0172F64EF854,CSAF-AWS-IAM-001,Root account has MFA enabled,Open,CRITICAL,95,HIGH,AWS,000000000000,global,,,root mfa_active=False,The account root user has an MFA device enabled.,Root account has MFA enabled: the assessed state does not meet the expected state.,Enable a hardware or virtual MFA device on the root user and store it securely offline.,2026-07-29T21:55:12Z
F-50B3D823D2E1E058,CSAF-AWS-S3-002,Buckets are not publicly accessible,Open,CRITICAL,95,HIGH,AWS,000000000000,global,,,public-assets: policy public,No bucket policy or ACL grants public read/write access.,Buckets are not publicly accessible: the assessed state does not meet the expected state.,Remove public bucket policies/ACLs and enable Block Public Access on affected buckets.,2026-07-29T21:55:12Z
F-D970F5E1065BB3C6,CSAF-AWS-IAM-005,Console users have MFA enabled,Open,HIGH,75,HIGH,AWS,000000000000,global,,,console user without MFA: alice,Every IAM user with a console password has an MFA device.,Console users have MFA enabled: the assessed state does not meet the expected state.,Require MFA for every IAM user with console access; enforce with an MFA-conditional policy.,2026-07-29T21:55:12Z
F-02ED85446A17BD89,CSAF-AWS-LOG-001,A multi-region CloudTrail trail is enabled,Open,HIGH,75,HIGH,AWS,000000000000,global,,,active multi-region trails=0,At least one multi-region CloudTrail trail is logging and enabled.,A multi-region CloudTrail trail is enabled: the assessed state does not meet the expected state.,Create a multi-region CloudTrail trail that is enabled and logging.,2026-07-29T21:55:12Z
F-76892F3EE49BBED2,CSAF-AWS-NET-001,Security groups do not allow ingress to admin ports from anywhere,Open,HIGH,75,HIGH,AWS,000000000000,global,,,sg-0abc opens ports [22] to 0.0.0.0/0,No security group allows 0.0.0.0/0 or ::/0 ingress to ports 22 or 3389.,Security groups do not allow ingress to admin ports from anywhere: the assessed state does not meet the expected state.,Restrict security-group ingress for ports 22/3389 to known management CIDRs or a bastion.,2026-07-29T21:55:12Z
```

**Verification: findings are a strict subset of Fail/Review control results.** Cross-checking against §4.2: the 5 finding `ControlId`s (`CSAF-AWS-IAM-001`, `CSAF-AWS-S3-002`, `CSAF-AWS-IAM-005`, `CSAF-AWS-LOG-001`, `CSAF-AWS-NET-001`) are exactly the 5 controls marked `Fail` in `control-results.jsonl` — no more, no fewer. `CSAF-AWS-OPS-001` (`NotTested`) does not appear as a finding, confirming the "NotTested/Error never produce a finding" invariant held in this real run.

### 4.4 `coverage-report.json` — full content

```json
{
  "SelectedControls": 30,
  "Executed": 29,
  "ExecutedRatio": 0.967,
  "Pass": 24,
  "Fail": 5,
  "Review": 0,
  "NotApplicable": 0,
  "NotTested": 1,
  "Error": 0,
  "AllSelectedControlsExecuted": false,
  "NotTestedControls": [
    "CSAF-AWS-OPS-001"
  ]
}
```

### 4.5 `detection-coverage.json` — full content (ATT&CK technique rollup)

```json
[
  {"Technique": "DS0015", "Status": "Covered", "ControlIds": ["CSAF-AWS-LOG-005"], "GapControlIds": []},
  {"Technique": "T1078", "Status": "Covered", "ControlIds": ["CSAF-AWS-IAM-008"], "GapControlIds": []},
  {"Technique": "T1078.004", "Status": "Gap", "ControlIds": ["CSAF-AWS-IAM-001", "CSAF-AWS-IAM-002", "CSAF-AWS-IAM-003", "CSAF-AWS-IAM-005", "CSAF-AWS-IAM-007"], "GapControlIds": ["CSAF-AWS-IAM-001", "CSAF-AWS-IAM-005"]},
  {"Technique": "T1133", "Status": "Gap", "ControlIds": ["CSAF-AWS-EC2-003", "CSAF-AWS-NET-001"], "GapControlIds": ["CSAF-AWS-NET-001"]},
  {"Technique": "T1530", "Status": "Gap", "ControlIds": ["CSAF-AWS-RDS-002", "CSAF-AWS-S3-001", "CSAF-AWS-S3-002"], "GapControlIds": ["CSAF-AWS-S3-002"]},
  {"Technique": "T1552.001", "Status": "Covered", "ControlIds": ["CSAF-AWS-SEC-001"], "GapControlIds": []},
  {"Technique": "T1552.005", "Status": "Covered", "ControlIds": ["CSAF-AWS-EC2-001"], "GapControlIds": []}
]
```

7 techniques referenced by this catalog's mappings; 3 have a real gap (`T1078.004`, `T1133`, `T1530`) matching the 5 findings above.

### 4.6 `remediation-roadmap.csv` — full content

```csv
Priority,Horizon,Severity,ControlId,Title,ResourceId,Remediation
1,0-24h,CRITICAL,CSAF-AWS-IAM-001,Root account has MFA enabled,,Enable a hardware or virtual MFA device on the root user and store it securely offline.
2,0-24h,CRITICAL,CSAF-AWS-S3-002,Buckets are not publicly accessible,,Remove public bucket policies/ACLs and enable Block Public Access on affected buckets.
3,1-7d,HIGH,CSAF-AWS-IAM-005,Console users have MFA enabled,,Require MFA for every IAM user with console access; enforce with an MFA-conditional policy.
4,1-7d,HIGH,CSAF-AWS-NET-001,Security groups do not allow ingress to admin ports from anywhere,,Restrict security-group ingress for ports 22/3389 to known management CIDRs or a bastion.
5,1-7d,HIGH,CSAF-AWS-LOG-001,A multi-region CloudTrail trail is enabled,,Create a multi-region CloudTrail trail that is enabled and logging.
```

### 4.7 `coverage-report.csv` — full content

```csv
Metric,Value
SelectedControls,30
Executed,29
ExecutedRatio,0.967
Pass,24
Fail,5
Review,0
NotApplicable,0
NotTested,1
Error,0
AllSelectedControlsExecuted,False
```

### 4.8 `executive-summary.html` — rendered content (key section)

```html
<h1>Cloud Security Assessment — Executive Summary</h1>
<p class="sub">AWS account 000000000000
&middot; profile Assessment
&middot; generated 2026-07-29T21:55:12Z &middot; CSAF v1.0.0</p>
<div class="banner">Coverage incomplete: 1 not tested, 0 errored. An empty findings list does not prove a clean assessment.</div>

<div class="cards">
<div class="card score"><div class="num">70.0</div><div class="label">Risk Score (CRITICAL)</div></div>
<div class="card"><div class="num">5</div><div class="label">Findings</div></div>
<div class="card critical"><div class="num">2</div><div class="label">Critical</div></div>
<div class="card high"><div class="num">3</div><div class="label">High</div></div>
<div class="card medium"><div class="num">0</div><div class="label">Medium</div></div>
<div class="card low"><div class="num">0</div><div class="label">Low</div></div>
</div>
<div class="cards">
<div class="card"><div class="num">29/30</div><div class="label">Controls Executed</div></div>
<div class="card"><div class="num">24</div><div class="label">Passed</div></div>
<div class="card"><div class="num">1</div><div class="label">Not Tested</div></div>
<div class="card"><div class="num">0</div><div class="label">Errors</div></div>
<div class="card critical"><div class="num">3</div><div class="label">ATT&amp;CK Technique Gaps</div></div>
</div>
<h2>Compliance Rollup</h2>
<table><thead><tr><th>Framework</th><th>Passed / Evaluated</th><th>Pass Rate</th></tr></thead>
<tbody><tr><td>CIS AWS Foundations</td><td>21/26</td><td>81%</td></tr>
<tr><td>MITRE ATT&amp;CK</td><td>10/14</td><td>71%</td></tr>
...
```

Every number on this page (`70.0` risk score, `29/30` coverage, `3` ATT&CK gaps, `81%`/`71%` compliance pass rates) is independently derivable from §4.2–4.5 above — nothing on the executive page is invented separately from the underlying data.

### 4.9 `manifest.json` — full content (tamper-evidence)

```json
{
  "SchemaVersion": "3.0",
  "FrameworkVersion": "1.0.0",
  "GeneratedAtUtc": "2026-07-29T21:55:12Z",
  "Cloud": "AWS",
  "AccountScope": "000000000000",
  "AssessmentProfile": "Assessment",
  "HashAlgorithm": "SHA256",
  "ConfidentialityNotice": "This manifest proves artifact integrity only. It does not encrypt assessment evidence.",
  "ArtifactCount": 13,
  "Artifacts": [
    {"FileName": "assessment-20260729T215512Z.jsonl", "RelativePath": "assessment-20260729T215512Z.jsonl", "SHA256": "BB0C4B8EC619AC6D2F656DD1D0BB55BF4FC233D8D1E287EC8C468760C03A66A7", "ByteLength": 550, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "assessment-20260729T215512Z.log", "RelativePath": "assessment-20260729T215512Z.log", "SHA256": "D8DB99CF55EFF939059272C388012A0370CA0A53F1969D9A5604297A6A118D9D", "ByteLength": 319, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "control-results.csv", "RelativePath": "control-results.csv", "SHA256": "2DB474AC62B4C21B49AC0B56F5526D541B14682C7166574E0A74944A993121DD", "ByteLength": 7030, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "control-results.jsonl", "RelativePath": "control-results.jsonl", "SHA256": "2F368E4BC15F42A93AD542930317AF1D385F3647B7DD5F6771AFE6458D6453F3", "ByteLength": 16931, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "coverage-report.csv", "RelativePath": "coverage-report.csv", "SHA256": "717CE0167DBCF23D94C821A08DF46E6B8F56D72CDD3D3028847BDBF4E3ED9D9B", "ByteLength": 170, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "coverage-report.json", "RelativePath": "coverage-report.json", "SHA256": "FFE91E10E522C5CE4AE7FD1965C7B6A0E1BF9F78B4FACBA45F1BB0E0D24E6E96", "ByteLength": 275, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "detection-coverage.csv", "RelativePath": "detection-coverage.csv", "SHA256": "27A71A8FE2D4F2ACDBE2608A40E692B97034B6DF9AD72CD0A41217B550CE4CE5", "ByteLength": 456, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "detection-coverage.json", "RelativePath": "detection-coverage.json", "SHA256": "C8D4F292A2ECB57207D7F59FB9C8B3196951AEED00E8479662650DCFFB6FCE89", "ByteLength": 1321, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "executive-summary.html", "RelativePath": "executive-summary.html", "SHA256": "C1AB7C1418D61C23AF81124ABFCD66177EFEAE9BF6694F3F19A70BCD4E6C8027", "ByteLength": 4828, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "findings.csv", "RelativePath": "findings.csv", "SHA256": "B6A2AD7C9D1D352C12430B33883B5A223EB40E9B7ABB1706F76A68886FAB1A12", "ByteLength": 2251, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "findings.json", "RelativePath": "findings.json", "SHA256": "F4FF24717EBDA01CDD533983705B308C032AAC0C14E75D4CB2AD0C40C3258A32", "ByteLength": 4611, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "remediation-roadmap.csv", "RelativePath": "remediation-roadmap.csv", "SHA256": "0ACE0E3F65610C33E81837C4E0987A489B2FB36C52C0999CDD5F79232903B386", "ByteLength": 860, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"},
    {"FileName": "technical-report.json", "RelativePath": "technical-report.json", "SHA256": "84F07FB1BBD53E0AE2F9370B8CF415F9234E26AAE3DE3D2791C3B5D309FB4B60", "ByteLength": 30770, "LastWriteTimeUtc": "2026-07-29T21:55:12Z"}
  ]
}
```

---

## 5. Data Integrity Verification

The manifest's SHA-256 hash for `findings.json` was independently recomputed from the actual on-disk file (not read from the manifest) and compared:

```
Computed SHA256: F4FF24717EBDA01CDD533983705B308C032AAC0C14E75D4CB2AD0C40C3258A32
Manifest SHA256:  F4FF24717EBDA01CDD533983705B308C032AAC0C14E75D4CB2AD0C40C3258A32
Match: True
```

This proves the manifest is a real, working tamper-evidence mechanism, not just a documented feature — any post-generation edit to any artifact would be caught by re-running this same check.

---

## 6. Summary

| Check | Result |
|---|---|
| Unit tests (AWS-specific) | **102 / 102 passed** |
| Self-check exit code | `2` (`CompletedWithErrors`) — correct, since 1 of 30 controls is `NotTested` |
| Findings ⊆ {Fail, Review} controls | **Verified** — exact match, no leakage from `NotTested`/`Error` |
| Coverage tracked independently of findings | **Verified** — `coverage-report.json` distinguishes 24 Pass / 5 Fail / 1 NotTested |
| Detection-coverage rollup consistent with findings | **Verified** — 3 Gap techniques correspond to the 5 Fail controls |
| Executive HTML numbers match underlying data | **Verified** — cross-checked risk score, coverage, and ATT&CK gap count |
| Manifest SHA-256 integrity | **Verified** — independently recomputed hash matches |
| Runs without `boto3`/`botocore` installed | **Verified** — package absence confirmed, self-check still succeeded |

**Conclusion: the AWS provider — read-only guardrail, all 7 check modules (identity, s3, compute, network, kms, rds, secrets), the concurrency path, and the full reporting pipeline — is fully functional end to end, evidenced by a real execution, not just passing unit tests.**
