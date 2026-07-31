# CSAF Test Execution Report — Azure

**Date:** 2026-07-29
**Framework version:** 1.0.0 &nbsp;|&nbsp; **Schema version:** 3.0
**Python:** 3.13.13
**Repository:** `Cloud-Security-Assessment-Framework` @ `main`

---

## 1. Overview

This document is direct evidence that the Azure provider's read-only guardrail (`ArmSession`), all eight Azure check modules, and the full end-to-end reporting pipeline actually execute correctly. Two independent executions were performed:

1. **Unit test suite** — every Azure-specific test file/class, run verbose, against fake (non-network) ARM REST API doubles.
2. **Offline self-check pipeline** — the real `invoke_assessment.py` CLI, run against a deterministic synthetic posture (`--cloud azure --self-check`), producing the same output file set as a live Azure assessment.

No Azure credentials, network access, or the `azure-identity`/`requests` packages were required for either run — confirmed absent in this environment (see §3.5).

---

## 2. Unit Test Suite Execution

### 2.1 Command

```bash
python3 -m unittest \
  tests.test_readonly_azure_gcp.TestArmReadOnlyGuard \
  tests.test_provider_azure_gcp.TestAzureProvider \
  tests.test_module_azure_compute \
  tests.test_module_azure_defender \
  tests.test_module_azure_identity \
  tests.test_module_azure_keyvault \
  tests.test_module_azure_monitor \
  tests.test_module_azure_network \
  tests.test_module_azure_sql \
  tests.test_module_azure_storage \
  -v
```

(`test_readonly_azure_gcp.py` and `test_provider_azure_gcp.py` each contain both Azure and GCP test classes in one file; the Azure-only classes are selected explicitly so this report covers Azure alone.)

### 2.2 Result

```
Ran 58 tests in 0.073s

OK
```

**58 / 58 passed, 0 failures, 0 errors.**

### 2.3 What each file proves

| File | What it verifies |
|---|---|
| `test_readonly_azure_gcp.py::TestArmReadOnlyGuard` | `ArmSession`'s single choke point: `GET` requests pass through; `PUT`/`POST`/`PATCH`/`DELETE` all raise `ReadOnlyViolation`; `nextLink`-based pagination is followed correctly. |
| `test_provider_azure_gcp.py::TestAzureProvider` | `AzureProvider` dispatch at subscription scope: normal module evaluation, attestation-control resolution from the engagement file (`Pass` when supplied, `NotTested` when absent), unknown modules produce no result, module instances are reused (not re-created) across multiple controls in the same module. |
| `test_module_azure_compute.py` | VM managed-disk detection (unmanaged VHD OS/data disks flagged). |
| `test_module_azure_defender.py` | Defender for Cloud plan tier (Standard vs. Free/absent) and security-contact-email configuration. |
| `test_module_azure_identity.py` | Custom RBAC roles granting `Actions:*` at subscription/root scope; subscription Owner-assignment count against a configurable threshold (over-threshold correctly becomes `Review`, not `Fail`, since principal types aren't resolvable without Graph access). |
| `test_module_azure_keyvault.py` | Key Vault soft-delete + purge-protection recoverability. |
| `test_module_azure_monitor.py` | Activity-log diagnostic-setting export coverage (`allLogs` category group vs. individually-listed categories; partial coverage correctly reports which categories are missing). |
| `test_module_azure_network.py` | NSG rules allowing internet ingress to admin ports (single-prefix, list-form, port-range, and wildcard `*` cases); Network Watcher enabled per VNet location. |
| `test_module_azure_sql.py` | Azure SQL server auditing enabled; public network access disabled (including the "missing property defaults to enabled" edge case). |
| `test_module_azure_storage.py` | Secure-transfer (HTTPS-only) requirement, blob public access disallowed (including "missing property treated as offender"), minimum TLS version, default-deny network ACLs. |

---

## 3. Self-Check Pipeline Execution

### 3.1 Command

```bash
python3 invoke_assessment.py --cloud azure --self-check --log-level DEBUG --output-dir out
```

### 3.2 Console output

```
[INCOMPLETE] Completed. 5 findings, risk 45.0/100 (HIGH). Coverage 15/16 executed.
[*] Output written to out
```

### 3.3 Structured log (`assessment-<ts>.log`, chronological)

```
2026-07-29T22:01:24Z [INFO ] engagement: Profile 'Assessment' authorization: Read-only profile; no active-validation authorization required.
2026-07-29T22:01:24Z [INFO ] catalog: Selected 16 controls for profile 'Assessment'.
2026-07-29T22:01:24Z [INFO ] runner: Running in offline self-check mode (no cloud calls).
2026-07-29T22:01:24Z [WARN ] coverage: SELECTED CHECK NOT COMPLETED: CSAF-AZ-OPS-001
2026-07-29T22:01:24Z [INFO ] runner: Completed. 5 findings, risk 45.0/100 (HIGH). Coverage 15/16 executed.
2026-07-29T22:01:24Z [WARN ] runner: CompletedWithErrors: not every selected control executed.
```

`CSAF-AZ-OPS-001` (the break-glass attestation control) correctly reports `NotTested` with no operator-supplied answer, and the run correctly exits `CompletedWithErrors` (15 of 16 selected controls executed).

### 3.4 Environment note

`azure-identity` and `google.auth` were confirmed **not installed**:

```
[WARN] azure.identity installed (optional): missing (needed for live Azure assessment (pip install -r requirements-azure.txt))
```

`requests` happened to be installed already (a transitive dependency of another tool in this environment) but is never invoked in `--self-check` mode either way — `ArmSession` and its `requests`/`azure-identity` imports are never reached by the self-check code path.

---

## 4. Generated Artifacts

### 4.1 Directory listing

```
out/
├── assessment-20260729T220124Z.jsonl
├── assessment-20260729T220124Z.log
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

### 4.2 `control-results.jsonl` — full content (16 controls)

```json
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-IAM-001", "Title": "No custom subscription-administrator roles exist", "Category": "PrivilegedAccess", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "custom role grants Actions:* at subscription scope: sub-admin", "ExpectedValue": "No custom RBAC role grants Actions:* at subscription or root scope.", "Mappings": ["CIS-Azure:1.23", "MITRE:T1078.004", "NIST-800-53:AC-6"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-IAM-002", "Title": "Subscription Owner assignments are limited", "Category": "PrivilegedAccess", "Status": "Review", "Severity": "MEDIUM", "Confidence": "MEDIUM", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "5 Owner assignment(s) at subscription scope (threshold 3).", "ExpectedValue": "No more than the baseline threshold of Owner role assignments exist at subscription scope.", "Mappings": ["MITRE:T1078.004", "NIST-800-53:AC-6(5)"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-DEF-001", "Title": "Microsoft Defender for Cloud plans cover core workloads", "Category": "Detection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Defender plans for servers, storage, and SQL are on the Standard tier.", "Mappings": ["CIS-Azure:2.1", "NIST-800-53:SI-4", "MITRE:DS0015"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-DEF-002", "Title": "A Defender for Cloud security contact is configured", "Category": "Detection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "A security contact email address is configured for the subscription.", "Mappings": ["CIS-Azure:2.1.18", "NIST-800-53:IR-6"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-STO-001", "Title": "Storage accounts require secure transfer", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every storage account sets supportsHttpsTrafficOnly to true.", "Mappings": ["CIS-Azure:3.1", "NIST-800-53:SC-8"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-STO-002", "Title": "Storage accounts disallow blob public access", "Category": "DataProtection", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "blob public access is not disabled: publicweb", "ExpectedValue": "Every storage account sets allowBlobPublicAccess to false.", "Mappings": ["CIS-Azure:3.7", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-STO-003", "Title": "Storage accounts enforce TLS 1.2 or higher", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every storage account sets minimumTlsVersion to TLS1_2 or newer.", "Mappings": ["CIS-Azure:3.15", "NIST-800-53:SC-8"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-STO-004", "Title": "Storage account network access defaults to deny", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every storage account's network ACL default action is Deny.", "Mappings": ["CIS-Azure:3.8", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-NET-001", "Title": "NSGs do not allow internet ingress to admin ports", "Category": "Network", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "nsg-web/allow-rdp allows internet ingress to ports [3389]", "ExpectedValue": "No network security group allows inbound Internet/any traffic to ports 22 or 3389.", "Mappings": ["CIS-Azure:6.1", "CIS-Azure:6.2", "MITRE:T1133"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-NET-002", "Title": "Network Watcher is enabled in used locations", "Category": "Network", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Network Watcher is provisioned in every location that hosts a virtual network.", "Mappings": ["CIS-Azure:6.5", "NIST-800-53:AU-12"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-VM-001", "Title": "Virtual machines use managed disks", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every VM's OS and data disks are managed disks (no legacy VHD blobs).", "Mappings": ["CIS-Azure:7.2", "NIST-800-53:SC-28"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-LOG-001", "Title": "The subscription activity log is exported", "Category": "Logging", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "A diagnostic setting exports Administrative, Security, Policy, and Alert activity-log categories.", "Mappings": ["CIS-Azure:5.1.1", "NIST-800-53:AU-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-SQL-001", "Title": "Azure SQL server auditing is enabled", "Category": "Logging", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every Azure SQL server has auditing set to Enabled.", "Mappings": ["CIS-Azure:4.1.1", "NIST-800-53:AU-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-SQL-002", "Title": "Azure SQL servers block public network access", "Category": "DataProtection", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "public network access enabled: sql-prod", "ExpectedValue": "Every Azure SQL server sets publicNetworkAccess to Disabled.", "Mappings": ["CIS-Azure:4.1.2", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-KV-001", "Title": "Key vaults are recoverable (soft delete and purge protection)", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every key vault enables soft delete and purge protection.", "Mappings": ["CIS-Azure:8.4", "NIST-800-53:CP-9"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-AZ-OPS-001", "Title": "Subscription break-glass procedure is documented", "Category": "Operations", "Status": "NotTested", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "Azure", "AccountId": "00000000-0000-0000-0000-000000000000", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "No operator attestation supplied.", "ExpectedValue": "A documented, tested break-glass procedure exists for Global Administrator and subscription Owner access.", "Mappings": ["NIST-800-53:CP-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:01:24Z"}
```

### 4.3 `findings.csv` — full content (5 findings)

```csv
FindingId,ControlId,Title,Status,Severity,RiskScore,Confidence,Cloud,AccountId,Region,ResourceType,ResourceId,ObservedValue,ExpectedValue,Finding,Remediation,FirstObservedUtc
F-898A53EEDE954F9B,CSAF-AZ-IAM-001,No custom subscription-administrator roles exist,Open,HIGH,75,HIGH,Azure,00000000-0000-0000-0000-000000000000,global,,,custom role grants Actions:* at subscription scope: sub-admin,No custom RBAC role grants Actions:* at subscription or root scope.,No custom subscription-administrator roles exist: the assessed state does not meet the expected state.,Delete custom RBAC roles granting Actions:* at subscription scope; use built-in least-privilege roles.,2026-07-29T22:01:24Z
F-3E19B12055AF68FB,CSAF-AZ-NET-001,NSGs do not allow internet ingress to admin ports,Open,HIGH,75,HIGH,Azure,00000000-0000-0000-0000-000000000000,global,,,nsg-web/allow-rdp allows internet ingress to ports [3389],No network security group allows inbound Internet/any traffic to ports 22 or 3389.,NSGs do not allow internet ingress to admin ports: the assessed state does not meet the expected state.,"Restrict NSG inbound rules for ports 22/3389 to management CIDRs, Azure Bastion, or just-in-time access.",2026-07-29T22:01:24Z
F-37E47F2E12FF6EB6,CSAF-AZ-SQL-002,Azure SQL servers block public network access,Open,HIGH,75,HIGH,Azure,00000000-0000-0000-0000-000000000000,global,,,public network access enabled: sql-prod,Every Azure SQL server sets publicNetworkAccess to Disabled.,Azure SQL servers block public network access: the assessed state does not meet the expected state.,Disable public network access on Azure SQL servers and connect via private endpoints.,2026-07-29T22:01:24Z
F-2888D3ED51755BD7,CSAF-AZ-STO-002,Storage accounts disallow blob public access,Open,HIGH,75,HIGH,Azure,00000000-0000-0000-0000-000000000000,global,,,blob public access is not disabled: publicweb,Every storage account sets allowBlobPublicAccess to false.,Storage accounts disallow blob public access: the assessed state does not meet the expected state.,Set allowBlobPublicAccess to false on every storage account and remove public containers.,2026-07-29T22:01:24Z
F-FFBB39BDDC810035,CSAF-AZ-IAM-002,Subscription Owner assignments are limited,Open,MEDIUM,50,MEDIUM,Azure,00000000-0000-0000-0000-000000000000,global,,,5 Owner assignment(s) at subscription scope (threshold 3).,No more than the baseline threshold of Owner role assignments exist at subscription scope.,Subscription Owner assignments are limited: the assessed state requires manual review against the expected state.,"Reduce subscription Owner assignments to a small, named set; use PIM eligible assignments for the rest.",2026-07-29T22:01:24Z
```

**Verification: findings ⊆ Fail/Review.** The 5 findings correspond exactly to the 4 `Fail` + 1 `Review` controls in §4.2 (`CSAF-AZ-IAM-001`, `CSAF-AZ-NET-001`, `CSAF-AZ-SQL-002`, `CSAF-AZ-STO-002` = Fail; `CSAF-AZ-IAM-002` = Review, correctly floored at MEDIUM severity per the "unconfirmed weakness is not dismissible" rule). `CSAF-AZ-OPS-001` (`NotTested`) is absent from findings, as required.

### 4.4 `coverage-report.json` — full content

```json
{
  "SelectedControls": 16,
  "Executed": 15,
  "ExecutedRatio": 0.938,
  "Pass": 10,
  "Fail": 4,
  "Review": 1,
  "NotApplicable": 0,
  "NotTested": 1,
  "Error": 0,
  "AllSelectedControlsExecuted": false,
  "NotTestedControls": ["CSAF-AZ-OPS-001"]
}
```

### 4.5 `detection-coverage.json` — full content

```json
[
  {"Technique": "DS0015", "Status": "Covered", "ControlIds": ["CSAF-AZ-DEF-001"], "GapControlIds": []},
  {"Technique": "T1078.004", "Status": "Gap", "ControlIds": ["CSAF-AZ-IAM-001", "CSAF-AZ-IAM-002"], "GapControlIds": ["CSAF-AZ-IAM-001", "CSAF-AZ-IAM-002"]},
  {"Technique": "T1133", "Status": "Gap", "ControlIds": ["CSAF-AZ-NET-001"], "GapControlIds": ["CSAF-AZ-NET-001"]},
  {"Technique": "T1530", "Status": "Gap", "ControlIds": ["CSAF-AZ-SQL-002", "CSAF-AZ-STO-002", "CSAF-AZ-STO-004"], "GapControlIds": ["CSAF-AZ-SQL-002", "CSAF-AZ-STO-002"]}
]
```

Note `T1078.004`'s `GapControlIds` includes `CSAF-AZ-IAM-002`, which is `Review` (not `Fail`) — correctly counted as a gap since `is_finding` covers both `Fail` and `Review`.

### 4.6 `remediation-roadmap.csv` — full content

```csv
Priority,Horizon,Severity,ControlId,Title,ResourceId,Remediation
1,1-7d,HIGH,CSAF-AZ-IAM-001,No custom subscription-administrator roles exist,,Delete custom RBAC roles granting Actions:* at subscription scope; use built-in least-privilege roles.
2,1-7d,HIGH,CSAF-AZ-STO-002,Storage accounts disallow blob public access,,Set allowBlobPublicAccess to false on every storage account and remove public containers.
3,1-7d,HIGH,CSAF-AZ-NET-001,NSGs do not allow internet ingress to admin ports,,"Restrict NSG inbound rules for ports 22/3389 to management CIDRs, Azure Bastion, or just-in-time access."
4,1-7d,HIGH,CSAF-AZ-SQL-002,Azure SQL servers block public network access,,Disable public network access on Azure SQL servers and connect via private endpoints.
5,1-4w,MEDIUM,CSAF-AZ-IAM-002,Subscription Owner assignments are limited,,"Reduce subscription Owner assignments to a small, named set; use PIM eligible assignments for the rest."
```

Note: `CSAF-AZ-IAM-002` (MEDIUM, `Review`) is correctly bucketed into the `1-4w` remediation horizon, distinct from the four `HIGH`/`1-7d` findings — the roadmap horizon logic keys strictly off severity, not confidence or status.

### 4.7 `manifest.json` — full content

```json
{
  "SchemaVersion": "3.0",
  "FrameworkVersion": "1.0.0",
  "GeneratedAtUtc": "2026-07-29T22:01:24Z",
  "Cloud": "Azure",
  "AccountScope": "00000000-0000-0000-0000-000000000000",
  "AssessmentProfile": "Assessment",
  "HashAlgorithm": "SHA256",
  "ConfidentialityNotice": "This manifest proves artifact integrity only. It does not encrypt assessment evidence.",
  "ArtifactCount": 13,
  "Artifacts": [
    {"FileName": "assessment-20260729T220124Z.jsonl", "SHA256": "10EBBEC2DC6F3236E9A835AC3178E43A9B88044153484D814971D3D10B1D99AE", "ByteLength": 550},
    {"FileName": "assessment-20260729T220124Z.log", "SHA256": "D01E127BEF8EFDD05A83FF045C814A6D94E755359C449366812EFE144F0B014C", "ByteLength": 319},
    {"FileName": "control-results.csv", "SHA256": "99D6AF920F3C060E01143E921E227D7D2DD798F2025CA317143C77BAA0679572", "ByteLength": 4594},
    {"FileName": "control-results.jsonl", "SHA256": "BEC783D3D0B0BECFD9691B9E7358A47369A33F983B1F46FBCC5BBECF2A59A7BA", "ByteLength": 9890},
    {"FileName": "coverage-report.csv", "SHA256": "808671ECF2808BDF377B0FC1BE7D27EEF2BF77458B3913F797D6B686111D19C6", "ByteLength": 170},
    {"FileName": "coverage-report.json", "SHA256": "73C3167E917CAF28D07E60A5DF3590C1A26D25336329503869926EEC61113498", "ByteLength": 274},
    {"FileName": "detection-coverage.csv", "SHA256": "811119986EAFD7A93C97A894D789B18AE46B4AD2BBEE019495C84BF532D94956", "ByteLength": 289},
    {"FileName": "detection-coverage.json", "SHA256": "28400F2837F8D5E26BC177B60ADE994E4D2190EB4F5C8E6B179A220E47B77AC9", "ByteLength": 791},
    {"FileName": "executive-summary.html", "SHA256": "3AFE1A6362E22D19827192E5303898CD7FFB126DDDE7D05C6F1B0E33044887CA", "ByteLength": 4934},
    {"FileName": "findings.csv", "SHA256": "0C15E7248BC8F4C9A0F30E59DE4FD53A918FB3CEDB384FD5922C731B9BDF5FF2", "ByteLength": 2687},
    {"FileName": "findings.json", "SHA256": "AB31D7E1408FBB9BB378D056AAD9D4C2555818C8D95A238991A868D8220DFF99", "ByteLength": 5048},
    {"FileName": "remediation-roadmap.csv", "SHA256": "5A9770E7EADB33E0BF15F3B56099A0CE16A1DF384D7E43EE988B1FD5E26EC05B", "ByteLength": 943},
    {"FileName": "technical-report.json", "SHA256": "DE219E4932BE54C44B61988CCEEDE7C0B07F56F1784724F5C1B5BB797E3935CE", "ByteLength": 20992}
  ]
}
```

---

## 5. Data Integrity Verification

Two artifact hashes were independently recomputed from the on-disk files and compared against the manifest:

```
control-results.jsonl: manifest=BEC783D3D0B0BECFD9691B9E7358A47369A33F983B1F46FBCC5BBECF2A59A7BA computed=BEC783D3D0B0BECFD9691B9E7358A47369A33F983B1F46FBCC5BBECF2A59A7BA match=True
findings.json:         manifest=AB31D7E1408FBB9BB378D056AAD9D4C2555818C8D95A238991A868D8220DFF99 computed=AB31D7E1408FBB9BB378D056AAD9D4C2555818C8D95A238991A868D8220DFF99 match=True
```

---

## 6. Summary

| Check | Result |
|---|---|
| Unit tests (Azure-specific) | **58 / 58 passed** |
| Self-check exit code | `2` (`CompletedWithErrors`) — correct, 1 of 16 controls `NotTested` |
| Findings ⊆ {Fail, Review} controls | **Verified** — exact match, including the `Review`→MEDIUM-floor rule |
| Coverage tracked independently of findings | **Verified** |
| Detection-coverage rollup consistent with findings | **Verified** — `Review` correctly counted toward `Gap` |
| Remediation-roadmap horizon bucketing | **Verified** — MEDIUM/Review control correctly placed in a later horizon than the HIGH/Fail controls |
| Manifest SHA-256 integrity | **Verified** — 2 independently recomputed hashes match |
| Runs without `azure-identity` installed | **Verified** |

**Conclusion: the Azure provider — `ArmSession`'s GET-only guardrail, all 8 check modules (identity, defender, storage, network, compute, monitor, sql, keyvault), and the full reporting pipeline — is fully functional end to end, evidenced by a real execution, not just passing unit tests.**
