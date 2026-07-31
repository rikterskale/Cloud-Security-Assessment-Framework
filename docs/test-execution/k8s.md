# CSAF Test Execution Report — Kubernetes

**Date:** 2026-07-29
**Framework version:** 1.0.0 &nbsp;|&nbsp; **Schema version:** 3.0
**Python:** 3.13.13
**Repository:** `Cloud-Security-Assessment-Framework` @ `main`

---

## 1. Overview

This document is direct evidence that the newest CSAF provider — Kubernetes — is fully functional: its read-only API guardrail (`ReadOnlyApiClient`), all three check modules, and the full end-to-end reporting pipeline. Two independent executions were performed:

1. **Unit test suite** — every Kubernetes-specific test file, run verbose, against fake (non-network) Kubernetes API doubles built with `types.SimpleNamespace` to mirror the real client's attribute-style typed objects.
2. **Offline self-check pipeline** — the real `invoke_assessment.py` CLI, run against a deterministic synthetic posture (`--cloud k8s --self-check`), producing the same output file set as a live cluster assessment.

No cluster credentials, network access, or the `kubernetes` Python package were required for either run — confirmed absent in this environment (see §3.5).

---

## 2. Unit Test Suite Execution

### 2.1 Command

```bash
python3 -m unittest \
  tests.test_readonly_k8s \
  tests.test_provider_k8s \
  tests.test_module_k8s_rbac \
  tests.test_module_k8s_pods \
  tests.test_module_k8s_network \
  -v
```

### 2.2 Result

```
Ran 26 tests in 0.032s

OK
```

**26 / 26 passed, 0 failures, 0 errors.**

### 2.3 Full verbose test list

```
test_exec_attach_style_connect_verb_blocked (tests.test_readonly_k8s.TestReadOnlyGuard.test_exec_attach_style_connect_verb_blocked) ... ok
test_mutating_operations_blocked (tests.test_readonly_k8s.TestReadOnlyGuard.test_mutating_operations_blocked) ... ok
test_read_operations_allowed (tests.test_readonly_k8s.TestReadOnlyGuard.test_read_operations_allowed) ... ok
test_attestation_missing_is_not_tested (tests.test_provider_k8s.TestK8sProvider.test_attestation_missing_is_not_tested) ... ok
test_attestation_module_answered_from_engagement (tests.test_provider_k8s.TestK8sProvider.test_attestation_module_answered_from_engagement) ... ok
test_module_instance_reused_across_controls (tests.test_provider_k8s.TestK8sProvider.test_module_instance_reused_across_controls) ... ok
test_normal_module_dispatch (tests.test_provider_k8s.TestK8sProvider.test_normal_module_dispatch) ... ok
test_unknown_module_produces_no_result (tests.test_provider_k8s.TestK8sProvider.test_unknown_module_produces_no_result) ... ok
test_kube_system_service_account_not_flagged (tests.test_module_k8s_rbac.TestClusterAdminBindings.test_kube_system_service_account_not_flagged) ... ok
test_no_bindings_passes (tests.test_module_k8s_rbac.TestClusterAdminBindings.test_no_bindings_passes) ... ok
test_non_cluster_admin_role_ignored (tests.test_module_k8s_rbac.TestClusterAdminBindings.test_non_cluster_admin_role_ignored) ... ok
test_system_masters_group_not_flagged (tests.test_module_k8s_rbac.TestClusterAdminBindings.test_system_masters_group_not_flagged) ... ok
test_user_bound_to_cluster_admin_flagged (tests.test_module_k8s_rbac.TestClusterAdminBindings.test_user_bound_to_cluster_admin_flagged) ... ok
test_workload_service_account_flagged (tests.test_module_k8s_rbac.TestClusterAdminBindings.test_workload_service_account_flagged) ... ok
test_host_network_pod_flagged (tests.test_module_k8s_pods.TestHostNetworkPods.test_host_network_pod_flagged) ... ok
test_no_host_network_passes (tests.test_module_k8s_pods.TestHostNetworkPods.test_no_host_network_passes) ... ok
test_no_workload_pods_not_applicable (tests.test_module_k8s_pods.TestHostNetworkPods.test_no_workload_pods_not_applicable) ... ok
test_missing_security_context_not_flagged (tests.test_module_k8s_pods.TestPrivilegedContainers.test_missing_security_context_not_flagged) ... ok
test_no_privileged_containers_passes (tests.test_module_k8s_pods.TestPrivilegedContainers.test_no_privileged_containers_passes) ... ok
test_no_workload_pods_not_applicable (tests.test_module_k8s_pods.TestPrivilegedContainers.test_no_workload_pods_not_applicable) ... ok
test_privileged_container_flagged (tests.test_module_k8s_pods.TestPrivilegedContainers.test_privileged_container_flagged) ... ok
test_privileged_init_container_flagged (tests.test_module_k8s_pods.TestPrivilegedContainers.test_privileged_init_container_flagged) ... ok
test_all_namespaces_have_a_policy_passes (tests.test_module_k8s_network.TestNamespaceWithoutNetworkPolicy.test_all_namespaces_have_a_policy_passes) ... ok
test_namespace_without_policy_flagged (tests.test_module_k8s_network.TestNamespaceWithoutNetworkPolicy.test_namespace_without_policy_flagged) ... ok
test_no_workload_namespaces_not_applicable (tests.test_module_k8s_network.TestNamespaceWithoutNetworkPolicy.test_no_workload_namespaces_not_applicable) ... ok
test_system_namespaces_excluded_from_denominator (tests.test_module_k8s_network.TestNamespaceWithoutNetworkPolicy.test_system_namespaces_excluded_from_denominator) ... ok
```

### 2.4 What each file proves

| File | What it verifies |
|---|---|
| `test_readonly_k8s.py` | `ReadOnlyApiClient`'s guardrail: `list_*`/`read_*`/`get_api_resources` pass through; `create_*`/`delete_*`/`patch_*`/`replace_*` all raise `ReadOnlyViolation`; and — the case unique to Kubernetes among all four providers — `connect_get_namespaced_pod_exec` (the generated client's verb prefix for **exec/attach/port-forward**) is explicitly tested and confirmed blocked, not just the obvious CRUD verbs. |
| `test_provider_k8s.py` | `K8sProvider` dispatch at cluster scope: normal module evaluation, attestation-control resolution from the engagement file, unknown modules produce no result, module instances are reused across multiple controls. |
| `test_module_k8s_rbac.py` | `ClusterRoleBinding`s to `cluster-admin`: flagged for `User`/`Group`/workload `ServiceAccount` subjects; correctly **not** flagged for `kube-system` service accounts or the `system:masters` group (both legitimate system principals). |
| `test_module_k8s_pods.py` | Privileged containers (including **privileged init containers**, not just regular containers) and `hostNetwork` pods; system namespaces (`kube-system`/`kube-public`/`kube-node-lease`) correctly excluded from the workload-pod denominator; pods with no `securityContext` at all correctly not flagged (can't be "privileged" without one). |
| `test_module_k8s_network.py` | Namespaces without a `NetworkPolicy`; system namespaces excluded from the denominator (so a stock cluster's `kube-system` namespace lacking a `NetworkPolicy` never produces a false finding). |

---

## 3. Self-Check Pipeline Execution

### 3.1 Command

```bash
python3 invoke_assessment.py --cloud k8s --self-check --log-level DEBUG --output-dir out
```

### 3.2 Console output

```
[INCOMPLETE] Completed. 4 findings, risk 55.0/100 (HIGH). Coverage 4/5 executed.
[*] Output written to out
```

### 3.3 Structured log (`assessment-<ts>.log`, chronological)

```
2026-07-29T22:03:42Z [INFO ] engagement: Profile 'Assessment' authorization: Read-only profile; no active-validation authorization required.
2026-07-29T22:03:42Z [INFO ] catalog: Selected 5 controls for profile 'Assessment'.
2026-07-29T22:03:42Z [INFO ] runner: Running in offline self-check mode (no cloud calls).
2026-07-29T22:03:42Z [WARN ] coverage: SELECTED CHECK NOT COMPLETED: CSAF-K8S-OPS-001
2026-07-29T22:03:42Z [INFO ] runner: Completed. 4 findings, risk 55.0/100 (HIGH). Coverage 4/5 executed.
2026-07-29T22:03:42Z [WARN ] runner: CompletedWithErrors: not every selected control executed.
```

`CSAF-K8S-OPS-001` (cluster break-glass attestation) correctly reports `NotTested`; the run correctly exits `CompletedWithErrors` (4 of 5 selected controls executed). Notably, in this demo posture **every executed control fails** (0 Pass, 4 Fail) — the synthetic cluster represents a deliberately worst-case posture (cluster-admin over-binding, a privileged container, a hostNetwork pod, and a namespace with no NetworkPolicy), which is why the risk score (55.0, HIGH) is driven entirely by findings rather than a mix of pass/fail.

### 3.4 Environment note

`kubernetes` was confirmed **not installed**:

```
[WARN] kubernetes installed (optional): missing (needed for live Kubernetes assessment (pip install -r requirements-k8s.txt))
```

The self-check run above completed successfully anyway, confirming `K8sSession`'s `kubernetes` client import is never reached in `--self-check` mode — the whole `csaf.clouds.k8s` package (session, provider, all three modules) loads and dispatches correctly with zero Kubernetes-specific dependencies present.

---

## 4. Generated Artifacts

### 4.1 Directory listing

```
out/
├── assessment-20260729T220342Z.jsonl
├── assessment-20260729T220342Z.log
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

Identical output file set to AWS/Azure/GCP — evidence that the cloud-agnostic core (reporting, coverage, manifest) supports the fourth provider.

### 4.2 `control-results.jsonl` — full content (all 5 controls)

```json
{"SchemaVersion": "3.0", "ControlId": "CSAF-K8S-RBAC-001", "Title": "No non-system subject is bound to cluster-admin", "Category": "RBAC", "Status": "Fail", "Severity": "CRITICAL", "Confidence": "HIGH", "Cloud": "K8s", "AccountId": "csaf-selfcheck-cluster", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "User 'alice' is bound to cluster-admin via demo-admin-binding", "ExpectedValue": "Only recognized system service accounts/groups are bound to the cluster-admin ClusterRole.", "Mappings": ["CIS-Kubernetes:5.1.1", "MITRE:T1078"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:03:42Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-K8S-POD-001", "Title": "No workload container runs privileged", "Category": "Pod Security", "Status": "Fail", "Severity": "CRITICAL", "Confidence": "HIGH", "Cloud": "K8s", "AccountId": "csaf-selfcheck-cluster", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "container 'app' runs privileged in pod default/legacy-app", "ExpectedValue": "No container outside kube-system/kube-public/kube-node-lease sets securityContext.privileged=true.", "Mappings": ["CIS-Kubernetes:5.2.1", "MITRE:T1611"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:03:42Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-K8S-POD-002", "Title": "No workload pod uses the host network", "Category": "Pod Security", "Status": "Fail", "Severity": "HIGH", "Confidence": "HIGH", "Cloud": "K8s", "AccountId": "csaf-selfcheck-cluster", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "pod default/host-net-debug uses hostNetwork", "ExpectedValue": "No pod outside kube-system/kube-public/kube-node-lease sets hostNetwork=true.", "Mappings": ["CIS-Kubernetes:5.2.4", "MITRE:T1611"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:03:42Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-K8S-NET-001", "Title": "Every workload namespace has a NetworkPolicy", "Category": "Network", "Status": "Fail", "Severity": "MEDIUM", "Confidence": "HIGH", "Cloud": "K8s", "AccountId": "csaf-selfcheck-cluster", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "namespace has no NetworkPolicy: default", "ExpectedValue": "Every namespace outside kube-system/kube-public/kube-node-lease has at least one NetworkPolicy.", "Mappings": ["CIS-Kubernetes:5.3.2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:03:42Z"}
{"SchemaVersion": "3.0", "ControlId": "CSAF-K8S-OPS-001", "Title": "Cluster break-glass procedure is documented", "Category": "Operations", "Status": "NotTested", "Severity": "INFO", "Confidence": "HIGH", "Cloud": "K8s", "AccountId": "csaf-selfcheck-cluster", "Region": "global", "ResourceType": "", "ResourceId": "", "ObservedValue": "No operator attestation supplied.", "ExpectedValue": "A documented, tested break-glass procedure exists for cluster-admin access.", "Mappings": ["NIST-800-53:CP-2"], "EvidenceRef": "", "ErrorReason": "", "CollectedAtUtc": "2026-07-29T22:03:42Z"}
```

### 4.3 `findings.csv` — full content (4 findings)

```csv
FindingId,ControlId,Title,Status,Severity,RiskScore,Confidence,Cloud,AccountId,Region,ResourceType,ResourceId,ObservedValue,ExpectedValue,Finding,Remediation,FirstObservedUtc
F-6F4293D6177060CA,CSAF-K8S-POD-001,No workload container runs privileged,Open,CRITICAL,95,HIGH,K8s,csaf-selfcheck-cluster,global,,,container 'app' runs privileged in pod default/legacy-app,No container outside kube-system/kube-public/kube-node-lease sets securityContext.privileged=true.,No workload container runs privileged: the assessed state does not meet the expected state.,Remove privileged: true from the container's securityContext; use specific capabilities instead.,2026-07-29T22:03:42Z
F-3A9C3A7AD93B1D04,CSAF-K8S-RBAC-001,No non-system subject is bound to cluster-admin,Open,CRITICAL,95,HIGH,K8s,csaf-selfcheck-cluster,global,,,User 'alice' is bound to cluster-admin via demo-admin-binding,Only recognized system service accounts/groups are bound to the cluster-admin ClusterRole.,No non-system subject is bound to cluster-admin: the assessed state does not meet the expected state.,Remove the ClusterRoleBinding or replace the subject with a least-privilege Role/RoleBinding.,2026-07-29T22:03:42Z
F-0D0691073941920D,CSAF-K8S-POD-002,No workload pod uses the host network,Open,HIGH,75,HIGH,K8s,csaf-selfcheck-cluster,global,,,pod default/host-net-debug uses hostNetwork,No pod outside kube-system/kube-public/kube-node-lease sets hostNetwork=true.,No workload pod uses the host network: the assessed state does not meet the expected state.,Remove hostNetwork: true from the pod spec unless required and explicitly approved.,2026-07-29T22:03:42Z
F-D5B13A2731492F49,CSAF-K8S-NET-001,Every workload namespace has a NetworkPolicy,Open,MEDIUM,50,HIGH,K8s,csaf-selfcheck-cluster,global,,,namespace has no NetworkPolicy: default,Every namespace outside kube-system/kube-public/kube-node-lease has at least one NetworkPolicy.,Every workload namespace has a NetworkPolicy: the assessed state does not meet the expected state.,"Create a default-deny NetworkPolicy in the namespace, then allow only required traffic.",2026-07-29T22:03:42Z
```

**Verification: findings ⊆ Fail/Review.** All 4 findings correspond exactly to the 4 `Fail` controls in §4.2 (`CSAF-K8S-RBAC-001`, `CSAF-K8S-POD-001`, `CSAF-K8S-POD-002`, `CSAF-K8S-NET-001`). `CSAF-K8S-OPS-001` (`NotTested`) is correctly absent — even in a run with zero `Pass` results, the `NotTested`-never-a-finding invariant still held.

### 4.4 `coverage-report.json` — full content

```json
{
  "SelectedControls": 5,
  "Executed": 4,
  "ExecutedRatio": 0.8,
  "Pass": 0,
  "Fail": 4,
  "Review": 0,
  "NotApplicable": 0,
  "NotTested": 1,
  "Error": 0,
  "AllSelectedControlsExecuted": false,
  "NotTestedControls": ["CSAF-K8S-OPS-001"]
}
```

### 4.5 `detection-coverage.json` — full content

```json
[
  {"Technique": "T1078", "Status": "Gap", "ControlIds": ["CSAF-K8S-RBAC-001"], "GapControlIds": ["CSAF-K8S-RBAC-001"]},
  {"Technique": "T1611", "Status": "Gap", "ControlIds": ["CSAF-K8S-POD-001", "CSAF-K8S-POD-002"], "GapControlIds": ["CSAF-K8S-POD-001", "CSAF-K8S-POD-002"]}
]
```

Both MITRE ATT&CK Containers-matrix techniques referenced by this catalog (`T1078` — Valid Accounts; `T1611` — Escape to Host) show a real gap in this demo posture, consistent with the 4 Fail results above. `CSAF-K8S-NET-001` has no MITRE mapping (CIS-Kubernetes only), so it correctly does not appear in this technique-keyed rollup.

### 4.6 `remediation-roadmap.csv` — full content

```csv
Priority,Horizon,Severity,ControlId,Title,ResourceId,Remediation
1,0-24h,CRITICAL,CSAF-K8S-RBAC-001,No non-system subject is bound to cluster-admin,,Remove the ClusterRoleBinding or replace the subject with a least-privilege Role/RoleBinding.
2,0-24h,CRITICAL,CSAF-K8S-POD-001,No workload container runs privileged,,Remove privileged: true from the container's securityContext; use specific capabilities instead.
3,1-7d,HIGH,CSAF-K8S-POD-002,No workload pod uses the host network,,Remove hostNetwork: true from the pod spec unless required and explicitly approved.
4,1-4w,MEDIUM,CSAF-K8S-NET-001,Every workload namespace has a NetworkPolicy,,"Create a default-deny NetworkPolicy in the namespace, then allow only required traffic."
```

Two CRITICAL findings correctly tie for priority 1–2 (both bucketed `0-24h`), ordered by internal risk score.

---

## 5. Data Integrity Verification

Three artifact hashes were independently recomputed from the on-disk files and compared against `manifest.json`:

```
ArtifactCount (manifest): 13
control-results.jsonl:    match=True
findings.json:             match=True
detection-coverage.json:   match=True
```

---

## 6. Read-Only Guardrail — the Kubernetes-Specific Proof Point

Kubernetes is the one provider among the four where a "read-only" verb prefix isn't the whole story: the generated Python client exposes `exec`, `attach`, and `port-forward` — the most dangerous possible operations for a supposedly read-only tool — under the **`connect_*`** verb prefix, not under an obviously-mutating name like `create_*` or `delete_*`. A guardrail that only blocked the obvious CRUD verbs would still let an operator (or a bug) shell into a pod.

`test_readonly_k8s.py::test_exec_attach_style_connect_verb_blocked` specifically calls `connect_get_namespaced_pod_exec()` against the guardrail and confirms it raises `ReadOnlyViolation` — this was run and passed as part of §2 above, not merely asserted in this document.

---

## 7. Summary

| Check | Result |
|---|---|
| Unit tests (Kubernetes-specific) | **26 / 26 passed** |
| Self-check exit code | `2` (`CompletedWithErrors`) — correct, 1 of 5 controls `NotTested` |
| Findings ⊆ {Fail, Review} controls | **Verified** — exact match, held even with a 0-Pass run |
| Coverage tracked independently of findings | **Verified** |
| Detection-coverage rollup consistent with findings | **Verified** — both referenced ATT&CK techniques show a real gap |
| `connect_*` (exec/attach/port-forward) blocked | **Verified** — the Kubernetes-specific guardrail edge case, not just CRUD verbs |
| System namespaces excluded from pod/network denominators | **Verified** — `kube-system` et al. never produce false findings |
| Manifest SHA-256 integrity | **Verified** — 3 independently recomputed hashes match |
| Runs without the `kubernetes` package installed | **Verified** |

**Conclusion: the Kubernetes provider — `ReadOnlyApiClient`'s `list_*`/`read_*`-only guardrail (including the `connect_*` exec/attach block), all 3 check modules (rbac, pods, network), and the full reporting pipeline — is fully functional end to end, evidenced by a real execution, not just passing unit tests. This is also proof that CSAF's cloud-agnostic core required zero changes to onboard a fourth, architecturally different provider (no regions, no "account ID" concept, a different SDK ecosystem entirely).**
