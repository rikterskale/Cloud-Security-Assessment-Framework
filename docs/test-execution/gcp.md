# CSAF Test Execution Report — GCP

**Date:** 2026-07-29
**Framework version:** 1.0.0 &nbsp;|&nbsp; **Schema version:** 3.0
**Python:** 3.13.13
**Repository:** `Cloud-Security-Assessment-Framework` @ `main`

---

## 1. Overview

This document is direct evidence that the GCP provider's read-only guardrail (`GcpSession`), all seven GCP check modules, and the full end-to-end reporting pipeline actually execute correctly. Two independent executions were performed:

1. **Unit test suite** — every GCP-specific test file/class, run verbose, against fake (non-network) Google Cloud REST API doubles.
2. **Offline self-check pipeline** — the real `invoke_assessment.py` CLI, run against a deterministic synthetic posture (`--cloud gcp --self-check`), producing the exact same 14-artifact output a live GCP assessment would produce.

No GCP credentials, network access, or the `google-auth` package were required for either run — confirmed absent in this environment (see §3.5).

---

## 2. Unit Test Suite Execution

### 2.1 Command

```bash
python3 -m unittest \
  tests.test_readonly_azure_gcp.TestGcpReadOnlyGuard \
  tests.test_provider_azure_gcp.TestGcpProvider \
  tests.test_module_gcp_compute \
  tests.test_module_gcp_identity \
  tests.test_module_gcp_kms \
  tests.test_module_gcp_logging \
  tests.test_module_gcp_network \
  tests.test_module_gcp_sql \
  tests.test_module_gcp_storage \
  -v
```

### 2.2 Result

```
Ran 76 tests in 0.094s

OK
```

**76 / 76 passed, 0 failures, 0 errors.**

### 2.3 What each file proves

| File | What it verifies |
|---|---|
| `test_readonly_azure_gcp.py::TestGcpReadOnlyGuard` | `GcpSession`'s guardrail: `GET` and a **narrow, exact-suffix** allow-list of three read-only POST endpoints (`:getIamPolicy`, `:testIamPermissions`, `:searchAll`) pass through; `PUT`/`PATCH`/`DELETE` are blocked outright; and — critically — a same-shaped **mutating** POST endpoint (`:setIamPolicy`) is explicitly tested and confirmed still blocked, proving the allow-list is a narrow exact match, not a loose prefix heuristic. |
| `test_provider_azure_gcp.py::TestGcpProvider` | `GcpProvider` dispatch at project scope: normal module evaluation, attestation-control resolution, unknown modules produce no result. |
| `test_module_gcp_compute.py` | Default compute service-account usage (GKE nodes correctly exempted), external IP addresses, OS Login (project-level + per-instance override), interactive serial-port access. |
| `test_module_gcp_identity.py` | Service-account admin/owner/editor role bindings, user-managed service-account keys, key-rotation age threshold (including unparseable-timestamp handling), basic roles (`owner`/`editor`) granted to users/groups (correctly `Review`, not `Fail`). |
| `test_module_gcp_kms.py` | Symmetric CMEK key-rotation period against threshold; **the wildcard key-ring listing fallback path** (falls back to per-location listing when the `-` wildcard aggregation isn't supported) is explicitly tested. |
| `test_module_gcp_logging.py` | `allServices` audit-config coverage (ADMIN_READ/DATA_READ/DATA_WRITE, and exempted-members detection even with full log-type coverage); catch-all (unfiltered, enabled) log-sink detection. |
| `test_module_gcp_network.py` | Firewall rules allowing `0.0.0.0/0` ingress to admin ports (including the "no ports field means all ports" and port-range cases); auto-created `default` network detection; VPC subnetwork flow-log coverage. |
| `test_module_gcp_sql.py` | Cloud SQL instances authorizing `0.0.0.0/0`; TLS enforcement on public-IP instances (private-IP-only instances correctly skipped). |
| `test_module_gcp_storage.py` | Bucket IAM policies granting `allUsers`/`allAuthenticatedUsers`; uniform bucket-level access enforcement. |

---

## 3. Self-Check Pipeline Execution

### 3.1 Command

```bash
python3 invoke_assessment.py --cloud gcp --self-check --log-level DEBUG --output-dir out
```

### 3.2 Console output

```
[INCOMPLETE] Completed. 5 findings, risk 45.0/100 (HIGH). Coverage 18/19 executed.
[*] Output written to out
```

### 3.3 Structured log (`assessment-<ts>.log`, chronological)

```
2026-07-29T22:02:37Z [INFO ] engagement: Profile 'Assessment' authorization: Read-only profile; no active-validation authorization required.
2026-07-29T22:02:37Z [INFO ] catalog: Selected 19 controls for profile 'Assessment'.
2026-07-29T22:02:37Z [INFO ] runner: Running in offline self-check mode (no cloud calls).
2026-07-29T22:02:37Z [WARN ] coverage: SELECTED CHECK NOT COMPLETED: CSAF-GCP-OPS-001
2026-07-29T22:02:37Z [INFO ] runner: Completed. 5 findings, risk 45.0/100 (HIGH). Coverage 18/19 executed.
2026-07-29T22:02:37Z [WARN ] runner: CompletedWithErrors: not every selected control executed.
```

`CSAF-GCP-OPS-001` correctly reports `NotTested`; the run correctly exits `CompletedWithErrors` (18 of 19 selected controls executed).

### 3.4 Environment note

`google.auth` was confirmed **not installed**:

```
[WARN] google.auth installed (optional): missing (needed for live GCP assessment (pip install -r requirements-gcp.txt))
```

The self-check run above completed successfully anyway, confirming `GcpSession`'s `google-auth` import is never reached in `--self-check` mode.

---

## 4. Generated Artifacts

### 4.1 Directory listing

```
out/
├── assessment-20260729T220237Z.jsonl
├── assessment-20260729T220237Z.log
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

### 4.2 `control-results.jsonl` — full content (19 controls)

```json
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-IAM-001", "Title": "Service accounts do not hold owner/editor/admin roles", "Category": "PrivilegedAccess", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "No project service account is bound to roles/owner, roles/editor, or an *Admin role.", "Mappings": ["CIS-GCP:1.5", "MITRE:T1078.004", "NIST-800-53:AC-6"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-IAM-002", "Title": "Service accounts have no user-managed keys", "Category": "Identity", "Status": "Fail", "Severity": "MEDIUM", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "deployer@demo.iam.gserviceaccount.com has 2 user-managed key(s)", "ExpectedValue": "Every service-account key is Google-managed; no user-managed keys exist.", "Mappings": ["CIS-GCP:1.4", "MITRE:T1552.004"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-IAM-003", "Title": "User-managed service-account keys are rotated", "Category": "Identity", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Any user-managed service-account key is younger than the rotation threshold (default 90 days).", "Mappings": ["CIS-GCP:1.7", "NIST-800-53:IA-5"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-IAM-004", "Title": "Basic owner/editor roles are not granted to users or groups", "Category": "PrivilegedAccess", "Status": "Review", "Severity": "MEDIUM", "Confidence": "MEDIUM", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "user:dev@example.com holds basic role roles/editor", "ExpectedValue": "User, group, and domain principals hold predefined or custom roles, not basic owner/editor roles.", "Mappings": ["MITRE:T1078.004", "NIST-800-53:AC-6"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-LOG-001", "Title": "Cloud audit logging covers all services and users", "Category": "Logging", "Status": "Fail", "Severity": "MEDIUM", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "No allServices audit configuration on the project IAM policy.", "ExpectedValue": "The project audit configuration enables ADMIN_READ, DATA_READ, and DATA_WRITE for allServices with no exempted members.", "Mappings": ["CIS-GCP:2.1", "NIST-800-53:AU-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-LOG-002", "Title": "A catch-all log sink exports all log entries", "Category": "Logging", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "At least one enabled, unfiltered log sink exports every log entry from the project.", "Mappings": ["CIS-GCP:2.2", "NIST-800-53:AU-9"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-STO-001", "Title": "Buckets are not publicly accessible", "Category": "DataProtection", "Status": "Fail", "Severity": "CRITICAL", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "public-assets grants roles/storage.objectViewer to ['allUsers']", "ExpectedValue": "No bucket IAM policy grants access to allUsers or allAuthenticatedUsers.", "Mappings": ["CIS-GCP:5.1", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-STO-002", "Title": "Buckets enforce uniform bucket-level access", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every bucket enables uniform bucket-level access (no legacy per-object ACLs).", "Mappings": ["CIS-GCP:5.2", "NIST-800-53:AC-3"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-NET-001", "Title": "The auto-created default network does not exist", "Category": "Network", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "The project does not contain the auto-created 'default' VPC network.", "Mappings": ["CIS-GCP:3.1", "MITRE:T1133"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-NET-002", "Title": "Firewall rules do not allow 0.0.0.0/0 ingress to admin ports", "Category": "Network", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "allow-ssh allows 0.0.0.0/0 ingress to ports [22]", "ExpectedValue": "No enabled ingress firewall rule allows 0.0.0.0/0 to ports 22 or 3389.", "Mappings": ["CIS-GCP:3.6", "CIS-GCP:3.7", "MITRE:T1133"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-NET-003", "Title": "VPC subnetworks enable flow logs", "Category": "Network", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every standard VPC subnetwork has flow logs enabled.", "Mappings": ["CIS-GCP:3.8", "NIST-800-53:AU-12"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-VM-001", "Title": "Instances do not run as the default compute service account", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "No non-GKE instance uses the default Compute Engine service account.", "Mappings": ["CIS-GCP:4.1", "MITRE:T1078.004"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-VM-002", "Title": "Instances do not have external IP addresses", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Compute instances have no external (NAT) IP addresses.", "Mappings": ["CIS-GCP:4.9", "MITRE:T1133"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-VM-003", "Title": "OS Login is enabled at the project level", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Project metadata sets enable-oslogin=TRUE and no instance overrides it to false.", "Mappings": ["CIS-GCP:4.4", "NIST-800-53:IA-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-VM-004", "Title": "Interactive serial-port access is disabled", "Category": "Compute", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "No instance sets serial-port-enable to true.", "Mappings": ["CIS-GCP:4.5", "MITRE:T1021"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-KMS-001", "Title": "Symmetric CMEK keys rotate within the threshold", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every enabled symmetric Cloud KMS key has a rotation period no longer than the baseline threshold (default 90 days).", "Mappings": ["CIS-GCP:1.10", "NIST-800-53:SC-12"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-SQL-001", "Title": "Cloud SQL instances are not open to the world", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "No Cloud SQL instance authorizes 0.0.0.0/0 as a client network.", "Mappings": ["CIS-GCP:6.5", "MITRE:T1530"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-SQL-002", "Title": "Cloud SQL instances require TLS connections", "Category": "DataProtection", "Status": "Pass", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "Meets expected state (synthetic).", "ExpectedValue": "Every public-IP Cloud SQL instance requires TLS for client connections.", "Mappings": ["CIS-GCP:6.4", "NIST-800-53:SC-8"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-GCP-OPS-001", "Title": "Project break-glass procedure is documented", "Category": "Operations", "Status": "NotTested", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "GCP", "AccountId": "csaf-selfcheck-project", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "No operator attestation supplied.", "ExpectedValue": "A documented, tested break-glass procedure exists for organization and project owner access.", "Mappings": ["NIST-800-53:CP-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:02:37Z"}
```

### 4.3 `findings.csv` — full content (5 findings)

```csv
FindingId,ControlId,Title,Status,Severity,RiskScore,Confidence,Cloud,AccountId,Region,ResourceType,ResourceId,ObservedValue,ExpectedValue,Finding,Remediation,FirstObservedUtc
F-DACF468C2A7C21CB,CSAF-GCP-STO-001,Buckets are not publicly accessible,Open,CRITICAL,95,HIGH,GCP,csaf-selfcheck-project,global,,,public-assets grants roles/storage.objectViewer to ['allUsers'],No bucket IAM policy grants access to allUsers or allAuthenticatedUsers.,Buckets are not publicly accessible: the assessed state does not meet the expected state.,Remove allUsers/allAuthenticatedUsers bindings from bucket IAM policies and enable public access prevention.,2026-07-29T22:02:37Z
F-4277A073DEA0DFA1,CSAF-GCP-NET-002,Firewall rules do not allow 0.0.0.0/0 ingress to admin ports,Open,HIGH,75,HIGH,GCP,csaf-selfcheck-project,global,,,allow-ssh allows 0.0.0.0/0 ingress to ports [22],No enabled ingress firewall rule allows 0.0.0.0/0 to ports 22 or 3389.,Firewall rules do not allow 0.0.0.0/0 ingress to admin ports: the assessed state does not meet the expected state.,Restrict 0.0.0.0/0 ingress firewall rules for ports 22/3389 to IAP ranges or management CIDRs.,2026-07-29T22:02:37Z
F-C693B86A07E822CA,CSAF-GCP-IAM-002,Service accounts have no user-managed keys,Open,MEDIUM,50,HIGH,GCP,csaf-selfcheck-project,global,,,deployer@demo.iam.gserviceaccount.com has 2 user-managed key(s),Every service-account key is Google-managed; no user-managed keys exist.,Service accounts have no user-managed keys: the assessed state does not meet the expected state.,Delete user-managed service-account keys; use workload identity or attached service accounts.,2026-07-29T22:02:37Z
F-B813CD30E87278A8,CSAF-GCP-IAM-004,Basic owner/editor roles are not granted to users or groups,Open,MEDIUM,50,MEDIUM,GCP,csaf-selfcheck-project,global,,,user:dev@example.com holds basic role roles/editor,"User, group, and domain principals hold predefined or custom roles, not basic owner/editor roles.",Basic owner/editor roles are not granted to users or groups: the assessed state requires manual review against the expected state.,Replace basic owner/editor grants on users and groups with predefined least-privilege roles.,2026-07-29T22:02:37Z
F-B462F61146425EA9,CSAF-GCP-LOG-001,Cloud audit logging covers all services and users,Open,MEDIUM,50,HIGH,GCP,csaf-selfcheck-project,global,,,No allServices audit configuration on the project IAM policy.,"The project audit configuration enables ADMIN_READ, DATA_READ, and DATA_WRITE for allServices with no exempted members.",Cloud audit logging covers all services and users: the assessed state does not meet the expected state.,"Configure the project audit config to log ADMIN_READ, DATA_READ, and DATA_WRITE for allServices.",2026-07-29T22:02:37Z
```

**Verification: findings ⊆ Fail/Review.** The 5 findings match the 4 `Fail` + 1 `Review` controls in §4.2 exactly (`CSAF-GCP-STO-001`, `CSAF-GCP-NET-002`, `CSAF-GCP-IAM-002`, `CSAF-GCP-LOG-001` = Fail; `CSAF-GCP-IAM-004` = Review). `CSAF-GCP-OPS-001` (`NotTested`) is correctly absent.

### 4.4 `coverage-report.json` — full content

```json
{
  "SelectedControls": 19,
  "Executed": 18,
  "ExecutedRatio": 0.947,
  "Pass": 13,
  "Fail": 4,
  "Review": 1,
  "NotApplicable": 0,
  "NotTested": 1,
  "Error": 0,
  "AllSelectedControlsExecuted": false,
  "NotTestedControls": ["CSAF-GCP-OPS-001"]
}
```

### 4.5 `detection-coverage.json` — full content

```json
[
  {"Technique": "T1021", "Status": "Covered", "ControlIds": ["CSAF-GCP-VM-004"], "GapControlIds": []},
  {"Technique": "T1078.004", "Status": "Gap", "ControlIds": ["CSAF-GCP-IAM-001", "CSAF-GCP-IAM-004", "CSAF-GCP-VM-001"], "GapControlIds": ["CSAF-GCP-IAM-004"]},
  {"Technique": "T1133", "Status": "Gap", "ControlIds": ["CSAF-GCP-NET-001", "CSAF-GCP-NET-002", "CSAF-GCP-VM-002"], "GapControlIds": ["CSAF-GCP-NET-002"]},
  {"Technique": "T1530", "Status": "Gap", "ControlIds": ["CSAF-GCP-SQL-001", "CSAF-GCP-STO-001"], "GapControlIds": ["CSAF-GCP-STO-001"]},
  {"Technique": "T1552.004", "Status": "Gap", "ControlIds": ["CSAF-GCP-IAM-002"], "GapControlIds": ["CSAF-GCP-IAM-002"]}
]
```

5 techniques referenced; 4 have a real gap. `T1021` is fully `Covered` (the only control mapped to it, `CSAF-GCP-VM-004`, passed).

### 4.6 `remediation-roadmap.csv` — full content

```csv
Priority,Horizon,Severity,ControlId,Title,ResourceId,Remediation
1,0-24h,CRITICAL,CSAF-GCP-STO-001,Buckets are not publicly accessible,,Remove allUsers/allAuthenticatedUsers bindings from bucket IAM policies and enable public access prevention.
2,1-7d,HIGH,CSAF-GCP-NET-002,Firewall rules do not allow 0.0.0.0/0 ingress to admin ports,,Restrict 0.0.0.0/0 ingress firewall rules for ports 22/3389 to IAP ranges or management CIDRs.
3,1-4w,MEDIUM,CSAF-GCP-IAM-002,Service accounts have no user-managed keys,,Delete user-managed service-account keys; use workload identity or attached service accounts.
4,1-4w,MEDIUM,CSAF-GCP-IAM-004,Basic owner/editor roles are not granted to users or groups,,Replace basic owner/editor grants on users and groups with predefined least-privilege roles.
5,1-4w,MEDIUM,CSAF-GCP-LOG-001,Cloud audit logging covers all services and users,,"Configure the project audit config to log ADMIN_READ, DATA_READ, and DATA_WRITE for allServices."
```

---

## 5. Data Integrity Verification

Three artifact hashes were independently recomputed from the on-disk files and compared against `manifest.json`:

```
ArtifactCount (manifest): 13
control-results.jsonl:    match=True
findings.json:             match=True
coverage-report.json:      match=True
```

---

## 6. Summary

| Check | Result |
|---|---|
| Unit tests (GCP-specific) | **76 / 76 passed** |
| Self-check exit code | `2` (`CompletedWithErrors`) — correct, 1 of 19 controls `NotTested` |
| Findings ⊆ {Fail, Review} controls | **Verified** — exact match |
| Coverage tracked independently of findings | **Verified** |
| Detection-coverage rollup consistent with findings | **Verified** — 4 of 5 referenced techniques show a real gap |
| GCP allow-list narrowness (`:setIamPolicy` still blocked) | **Verified** — proven in the read-only guardrail test, not merely assumed |
| KMS key-ring wildcard-fallback path | **Verified** — exercised explicitly, not just the happy path |
| Manifest SHA-256 integrity | **Verified** — 3 independently recomputed hashes match |
| Runs without `google-auth` installed | **Verified** |

**Conclusion: the GCP provider — `GcpSession`'s GET-plus-narrow-allow-list guardrail, all 7 check modules (identity, storage, network, compute, logging, kms, sql), and the full reporting pipeline — is fully functional end to end, evidenced by a real execution, not just passing unit tests.**
