# Doc 2 — AWS Security Testing Methodology

## From Windows & Kali Linux Boxes in Amazon Web Services

**Version:** 2.0 — Production-Ready  
**Classification:** CONFIDENTIAL — Internal Use Only  
**Compliance Targets:** SOC 2 Type II · ISO 27001 · HIPAA · PCI-DSS  
**All tools:** 100 % open-source (Apache / MIT / GPL), zero telemetry

---

## Table of Contents

1. [Document Overview](#1-document-overview)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Configuration & Misconfiguration Assessment](#3-configuration--misconfiguration-assessment)
4. [Identity & Access (IAM, Roles, Federation)](#4-identity--access-iam-roles-federation)
5. [Network & Perimeter Security](#5-network--perimeter-security)
6. [Data Protection & Encryption](#6-data-protection--encryption)
7. [Runtime, Container & Serverless Security](#7-runtime-container--serverless-security)
8. [Supply-Chain & CI/CD Security](#8-supply-chain--cicd-security)
9. [Automated Reconnaissance & Validation Pipelines](#9-automated-reconnaissance--validation-pipelines)
10. [IAM / Path Analysis at Scale (Pacu Deep Dive)](#10-iam--path-analysis-at-scale-pacu-deep-dive)
11. [Neo4j Attack-Path Setup & Visualization](#11-neo4j-attack-path-setup--visualization)
12. [Multi-Cloud Attack-Surface Mapping](#12-multi-cloud-attack-surface-mapping)
13. [Hybrid Cloud Security Tools (Steampipe, CloudQuery, Cartography)](#13-hybrid-cloud-security-tools-steampipe-cloudquery-cartography)
14. [Aggregator Integration](#14-aggregator-integration)
15. [Gap Analysis & Filled Gaps](#15-gap-analysis--filled-gaps)
16. [Report Generation & Compliance Artifacts](#16-report-generation--compliance-artifacts)
17. [Appendices](#17-appendices)

---

## 1. Document Overview

### 1.1 Purpose

This document provides a self-contained, production-ready methodology for security testing an AWS environment. All checks are executed from:

| Platform | OS | Notes |
|---|---|---|
| **AWS Windows Box** | Windows Server 2022 | EC2 instance, Chocolatey package manager |
| **AWS Kali Linux Box** | Kali Linux 2024.x | EC2 instance, full Kali toolset + custom additions |

### 1.2 Scope Matrix

| Domain | Section |
|---|---|
| Configuration / Misconfigurations | §3 |
| Identity & Access (IAM, Roles, SSO, Federation) | §4 |
| Network / Perimeter | §5 |
| Data Protection / Encryption | §6 |
| Runtime / Container / Serverless | §7 |
| Supply-Chain / CI/CD | §8 |
| Automated Recon + Validation Pipelines | §9 |
| IAM / Path Analysis at Scale (Pacu) | §10 |
| Neo4j Attack-Path Visualization | §11 |
| Multi-Cloud Attack Surface Mapping | §12 |
| Hybrid Cloud Tools | §13 |
| Aggregator (unified JSON / HTML / Neo4j) | §14 |

### 1.3 Conventions

- `WIN>` = Command executed on the Windows box.
- `KALI>` = Command executed on the Kali Linux box.
- `BOTH>` = Identical on either platform.
- All output samples are truncated for brevity.
- SHA-256 hashes are generated for every report artifact.

---

## 2. Prerequisites & Environment Setup

### 2.1 AWS Account Preparation

```text
Required IAM Policy for the testing user/role (minimum):
  arn:aws:iam::policy/SecurityAudit           (AWS-managed read audit)
  arn:aws:iam::policy/ViewOnlyAccess           (broad read access)

  Plus custom policy for:
    iam:GetAccountAuthorizationDetails
    iam:SimulatePrincipalPolicy
    iam:GenerateCredentialReport
    organizations:Describe*
    organizations:List*
    sts:GetCallerIdentity
    ecr:GetAuthorizationToken
    ecr:BatchGetImage
    lambda:GetFunction
    lambda:GetPolicy
    lambda:ListFunctions
    ecs:Describe*
    eks:Describe*
    eks:ListClusters
    s3:GetBucketPolicy
    s3:GetBucketAcl
    s3:GetBucketEncryption
    s3:GetBucketPublicAccessBlock
    s3:ListAllMyBuckets
    kms:ListKeys
    kms:DescribeKey
    kms:GetKeyRotationStatus
    secretsmanager:ListSecrets
    secretsmanager:DescribeSecret
    rds:DescribeDBInstances
    ec2:Describe*
    cloudtrail:DescribeTrails
    cloudtrail:GetTrailStatus
    config:Describe*
    guardduty:ListDetectors
    guardduty:GetFindings
    ssm:DescribeInstanceInformation
```

Create an IAM user or assume a role with these permissions:

```bash
KALI> aws configure
# AWS Access Key ID: AKIAEXAMPLE...
# AWS Secret Access Key: ****
# Default region: us-east-1
# Default output format: json

KALI> aws sts get-caller-identity
```

**Expected Output:**

```json
{
  "UserId": "AIDAEXAMPLE",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/sec-tester"
}
```

### 2.2 Kali Linux Box Setup (EC2)

#### 2.2.1 System Updates & Core Packages

```bash
KALI> sudo apt update && sudo apt full-upgrade -y
KALI> sudo apt install -y \
        git curl wget unzip jq python3 python3-pip python3-venv \
        nmap nikto dnsutils whois net-tools build-essential \
        default-jre docker.io docker-compose golang \
        awscli dirb gobuster seclists wordlists \
        enum4linux smbclient hydra john hashcat
KALI> sudo usermod -aG docker $USER && newgrp docker
```

#### 2.2.2 AWS CLI v2

```bash
KALI> curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
KALI> unzip awscliv2.zip && sudo ./aws/install
KALI> aws --version
# Expected: aws-cli/2.x.x Python/3.x.x Linux/...
```

#### 2.2.3 Python Virtual Environment

```bash
KALI> python3 -m venv ~/sectest-venv
KALI> source ~/sectest-venv/bin/activate
KALI> pip install --upgrade pip setuptools wheel
```

#### 2.2.4 Tool Installation — Kali Linux

**ScoutSuite (AWS CIS Scanner)**

```bash
KALI> cd ~ && git clone https://github.com/nccgroup/ScoutSuite.git
KALI> cd ScoutSuite && pip install -r requirements.txt
KALI> python scout.py aws --help
# Expected: usage: scout.py aws [-h] [--profile ...] ...
```

**Prowler (AWS-native compliance)**

```bash
KALI> pip install prowler
KALI> prowler aws --help
# Expected: usage: prowler aws [-h] ...
```

**Pacu (AWS Exploitation Framework)**

```bash
KALI> cd ~ && git clone https://github.com/RhinoSecurityLabs/pacu.git
KALI> cd pacu && pip install -r requirements.txt
KALI> python3 cli.py
# Expected: Pacu (AWS Exploitation Framework) interactive console
# Pacu> help
```

**CloudMapper (AWS network visualization)**

```bash
KALI> cd ~ && git clone https://github.com/duo-labs/cloudmapper.git
KALI> cd cloudmapper && pip install -r requirements.txt
KALI> python cloudmapper.py --help
# Expected: usage: cloudmapper.py ...
```

**Cartography**

```bash
KALI> pip install cartography
KALI> cartography --help
```

**Steampipe + AWS Plugin**

```bash
KALI> sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
KALI> steampipe plugin install aws
KALI> steampipe query "select 1 as test"
# Expected:
# +------+
# | test |
# +------+
# | 1    |
# +------+
```

**CloudQuery**

```bash
KALI> curl -L https://github.com/cloudquery/cloudquery/releases/latest/download/cloudquery_linux_amd64 \
       -o /usr/local/bin/cloudquery && chmod +x /usr/local/bin/cloudquery
KALI> cloudquery --help
```

**CloudFox**

```bash
KALI> wget https://github.com/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip
KALI> unzip cloudfox-linux-amd64.zip -d /usr/local/bin/
KALI> cloudfox aws --help
# Expected: Available Commands: access-keys, buckets, ecr, eks, endpoints, env-vars,
#           iam-simulator, instances, lambda, permissions, principals, ...
```

**trivy**

```bash
KALI> curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
        sudo sh -s -- -b /usr/local/bin
KALI> trivy --version
```

**checkov**

```bash
KALI> pip install checkov
KALI> checkov --version
```

**kube-bench**

```bash
KALI> curl -L https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_linux_amd64.tar.gz | \
        tar xz -C /usr/local/bin
KALI> kube-bench version
```

**kube-hunter**

```bash
KALI> pip install kube-hunter
KALI> kube-hunter --help
```

**Falco**

```bash
KALI> curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
KALI> echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
        https://download.falco.org/packages/deb stable main" | \
        sudo tee /etc/apt/sources.list.d/falcosecurity.list
KALI> sudo apt update && sudo apt install -y falco
KALI> falco --version
```

**syft + grype**

```bash
KALI> curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
KALI> curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
KALI> syft version && grype version
```

**Neo4j Community Edition**

```bash
KALI> wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
KALI> echo 'deb https://debian.neo4j.com stable latest' | \
        sudo tee /etc/apt/sources.list.d/neo4j.list
KALI> sudo apt update && sudo apt install -y neo4j
KALI> sudo systemctl enable neo4j && sudo systemctl start neo4j
```

**Recon Tools**

```bash
KALI> go install github.com/projectdiscovery/httpx/cmd/httpx@latest
KALI> go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
KALI> go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
KALI> nuclei -update-templates
```

**enumerate-iam**

```bash
KALI> cd ~ && git clone https://github.com/andresriancho/enumerate-iam.git
KALI> cd enumerate-iam && pip install -r requirements.txt
KALI> python enumerate-iam.py --help
```

**aws_consoleme / Principal Mapper (pmapper)**

```bash
KALI> pip install principalmapper
KALI> pmapper --help
# Expected: usage: pmapper [-h] ...
```

### 2.3 Windows Box Setup (Windows Server 2022 on EC2)

#### 2.3.1 Chocolatey & Core Packages

```powershell
WIN> Set-ExecutionPolicy Bypass -Scope Process -Force
WIN> [System.Net.ServicePointManager]::SecurityProtocol = `
       [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
WIN> iex ((New-Object System.Net.WebClient).DownloadString(
       'https://community.chocolatey.org/install.ps1'))
WIN> choco install -y git python3 nmap jq curl wget `
       openjdk17 golang docker-desktop nodejs-lts 7zip awscli
```

#### 2.3.2 AWS CLI Configuration (Windows)

```powershell
WIN> aws configure
WIN> aws sts get-caller-identity
```

#### 2.3.3 Python Tools (Windows)

```powershell
WIN> python -m venv C:\sectest-venv
WIN> C:\sectest-venv\Scripts\Activate.ps1
WIN> pip install scoutsuite prowler checkov kube-hunter principalmapper
WIN> git clone https://github.com/RhinoSecurityLabs/pacu.git C:\tools\pacu
WIN> cd C:\tools\pacu && pip install -r requirements.txt
```

#### 2.3.4 Steampipe (Windows)

```powershell
WIN> choco install -y steampipe
WIN> steampipe plugin install aws
WIN> steampipe query "select 1 as test"
```

#### 2.3.5 PowerShell AWS Tools

```powershell
WIN> Install-Module -Name AWS.Tools.Installer -Force
WIN> Install-AWSToolsModule AWS.Tools.EC2,AWS.Tools.IAM,AWS.Tools.S3,AWS.Tools.SecurityHub `
       -Force -CleanUp
WIN> Get-AWSPowerShellVersion
```

#### 2.3.6 Neo4j Desktop (Windows)

Download from https://neo4j.com/download-center/ and install.

### 2.4 Environment Validation

```bash
#!/usr/bin/env bash
# validate_aws_tools.sh
TOOLS=(
  "awscli:aws --version"
  "scout:python scout.py --help"
  "prowler:prowler --help"
  "pacu:python3 ~/pacu/cli.py --help"
  "steampipe:steampipe --version"
  "cloudquery:cloudquery --version"
  "cloudfox:cloudfox --help"
  "trivy:trivy --version"
  "checkov:checkov --version"
  "kube-bench:kube-bench version"
  "kube-hunter:kube-hunter --help"
  "falco:falco --version"
  "syft:syft version"
  "grype:grype version"
  "nuclei:nuclei --version"
  "nmap:nmap --version"
  "neo4j:neo4j version"
  "cartography:cartography --help"
  "pmapper:pmapper --help"
  "enumerate-iam:python enumerate-iam.py --help"
  "cloudmapper:python ~/cloudmapper/cloudmapper.py --help"
)
for entry in "${TOOLS[@]}"; do
  IFS=":" read -r name cmd <<< "$entry"
  if $cmd &>/dev/null; then echo "[OK]   $name"
  else echo "[FAIL] $name"; fi
done
```

---

## 3. Configuration & Misconfiguration Assessment

### 3.1 ScoutSuite — Full AWS Scan

```bash
KALI> cd ~/ScoutSuite
KALI> python scout.py aws \
        --profile default \
        --report-dir ~/reports/scoutsuite \
        --no-browser
```

**Expected Output (truncated):**

```text
Fetching data for account 123456789012 ...
  iam              [##########] 100%   87 resources
  ec2              [##########] 100%  234 resources
  s3               [##########] 100%   45 resources
  rds              [##########] 100%   12 resources
  lambda           [##########] 100%   67 resources
  ...
Processing data ...
  Rules evaluated: 247
  Dangers:         22
  Warnings:        58
  Passing:         167

Report saved to ~/reports/scoutsuite/aws-123456789012.html
```

### 3.2 Prowler — AWS CIS & PCI-DSS

```bash
KALI> prowler aws \
        --output-formats json-ocsf,html,csv \
        --output-directory ~/reports/prowler \
        --severity critical high \
        --compliance cis_aws_2.0 pci_3.2.1
```

**Expected Output (truncated):**

```text
Prowler v4.x.x — AWS Provider
Account: 123456789012 | Region: us-east-1

[CRITICAL] aws_iam_root_access_key_exists: Root account has active access keys → FAIL
[CRITICAL] aws_s3_bucket_public_access: Bucket "dev-uploads" allows public access → FAIL
[HIGH]     aws_ec2_security_group_ingress_open: SG sg-0abc123 allows 0.0.0.0/0 on port 22 → FAIL
[HIGH]     aws_cloudtrail_multi_region_disabled: CloudTrail not enabled in all regions → FAIL
...
Results: 128 PASS | 22 FAIL (8 CRITICAL, 14 HIGH) | 5 MANUAL
```

### 3.3 AWS Config — Compliance Rule Status

```bash
KALI> aws configservice describe-compliance-by-config-rule \
        --compliance-types NON_COMPLIANT \
        --output json > ~/reports/config/non-compliant-rules.json
```

**Expected Output:**

```json
{
  "ComplianceByConfigRules": [
    {
      "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
      "Compliance": { "ComplianceType": "NON_COMPLIANT" }
    },
    {
      "ConfigRuleName": "iam-password-policy",
      "Compliance": { "ComplianceType": "NON_COMPLIANT" }
    }
  ]
}
```

### 3.4 Steampipe — SQL-Based AWS Compliance

```bash
KALI> steampipe query "
  SELECT
    name,
    server_side_encryption_configuration IS NOT NULL AS encrypted,
    block_public_acls,
    block_public_policy,
    restrict_public_buckets,
    ignore_public_acls
  FROM aws_s3_bucket
  ORDER BY encrypted;
"
```

**Expected Output:**

```text
+-------------------+-----------+------------------+--------------------+------------------------+-------------------+
| name              | encrypted | block_public_acls| block_public_policy| restrict_public_buckets| ignore_public_acls|
+-------------------+-----------+------------------+--------------------+------------------------+-------------------+
| dev-uploads       | false     | false            | false              | false                  | false             |
| prod-data         | true      | true             | true               | true                  | true              |
| logs-bucket       | true      | true             | true               | true                  | true              |
+-------------------+-----------+------------------+--------------------+------------------------+-------------------+
```

### 3.5 checkov — Terraform / CloudFormation Scanning

```bash
KALI> checkov -d ~/infra/terraform/ \
        --framework terraform \
        --output json \
        --output-file-path ~/reports/checkov/ \
        --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_20,CKV_AWS_21,CKV_AWS_23,CKV_AWS_24
```

**Expected Output:**

```text
Passed checks: 67, Failed checks: 12, Skipped checks: 3

Check: CKV_AWS_18: "Ensure AWS access logging is enabled on S3 bucket"
  FAILED for resource: aws_s3_bucket.uploads
  File: /modules/s3/main.tf:22-38

Check: CKV_AWS_23: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
  FAILED for resource: aws_security_group.ssh_open
  File: /modules/ec2/security.tf:5-20
```

---

## 4. Identity & Access (IAM, Roles, Federation)

### 4.1 IAM Credential Report

```bash
KALI> aws iam generate-credential-report
KALI> aws iam get-credential-report --output json | \
        jq -r '.Content' | base64 -d > ~/reports/iam/credential-report.csv
```

**Expected CSV columns:**

```text
user, arn, user_creation_time, password_enabled, password_last_used,
password_last_changed, mfa_active, access_key_1_active, access_key_1_last_rotated,
access_key_1_last_used_date, access_key_2_active, ...
```

Flag: `mfa_active = false` for console users, `access_key_1_last_rotated` > 90 days.

### 4.2 IAM Access Analyzer

```bash
KALI> aws accessanalyzer list-analyzers --output json
KALI> aws accessanalyzer list-findings \
        --analyzer-arn $(aws accessanalyzer list-analyzers \
          --query 'analyzers[0].arn' --output text) \
        --filter '{"status": {"eq": ["ACTIVE"]}}' \
        --output json > ~/reports/iam/access-analyzer-findings.json
```

**Expected Output:**

```json
{
  "findings": [
    {
      "id": "abc123",
      "resourceType": "AWS::S3::Bucket",
      "resource": "arn:aws:s3:::dev-uploads",
      "condition": {},
      "principal": { "AWS": "*" },
      "action": ["s3:GetObject"],
      "status": "ACTIVE",
      "isPublic": true
    }
  ]
}
```

### 4.3 Full IAM Authorization Details

```bash
KALI> aws iam get-account-authorization-details \
        --output json > ~/reports/iam/full-auth-details.json

# Find users with inline policies (bad practice)
KALI> cat ~/reports/iam/full-auth-details.json | \
        jq '[.UserDetailList[] | select(.UserPolicyList | length > 0) |
             {user: .UserName, inline_policies: [.UserPolicyList[].PolicyName]}]'
```

**Expected Output:**

```json
[
  {
    "user": "legacy-deploy",
    "inline_policies": ["FullAdminAccess"]
  }
]
```

### 4.4 enumerate-iam — Permission Brute Force

```bash
KALI> cd ~/enumerate-iam
KALI> python enumerate-iam.py \
        --access-key $AWS_ACCESS_KEY_ID \
        --secret-key $AWS_SECRET_ACCESS_KEY \
        --region us-east-1
```

**Expected Output:**

```text
[*] Testing 2987 API calls ...
[+] iam.list_users                      → Allowed
[+] iam.list_roles                      → Allowed
[+] s3.list_buckets                     → Allowed
[+] ec2.describe_instances              → Allowed
[+] lambda.list_functions               → Allowed
[-] iam.create_user                     → Denied
[-] ec2.run_instances                   → Denied
...
[*] Completed: 147 allowed, 2840 denied
```

### 4.5 Principal Mapper (pmapper) — IAM Graph Analysis

```bash
KALI> pmapper graph create
KALI> pmapper visualize --filetype png
KALI> pmapper query "who can do iam:CreateUser with *"
```

**Expected Output:**

```text
Pulling data for account 123456789012 ...
Graph created: 87 principals, 142 edges

Results for "who can do iam:CreateUser with *":
  admin-user (User)
  deploy-role (Role) — via iam:PassRole chain
  org-admin-role (Role) — direct permission
```

```bash
# Find all privilege escalation paths
KALI> pmapper query "preset privesc *"
```

**Expected Output:**

```text
Privilege escalation paths found:
  [1] legacy-deploy (User) → iam:CreatePolicyVersion → Admin
  [2] lambda-role (Role) → iam:PassRole + lambda:CreateFunction → Admin
  [3] dev-team (Group) → iam:AttachUserPolicy → Admin
```

### 4.6 SSO & Federation Audit

```bash
# List SSO instances
KALI> aws sso-admin list-instances --output json > ~/reports/iam/sso-instances.json

# List permission sets
KALI> INSTANCE_ARN=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text)
KALI> aws sso-admin list-permission-sets \
        --instance-arn $INSTANCE_ARN \
        --output json > ~/reports/iam/sso-permission-sets.json

# List SAML providers (federation)
KALI> aws iam list-saml-providers --output json > ~/reports/iam/saml-providers.json

# List OIDC providers
KALI> aws iam list-open-id-connect-providers --output json > ~/reports/iam/oidc-providers.json
```

### 4.7 STS Assume Role Chain Analysis

```bash
# Find all roles that can be assumed from outside the account
KALI> cat ~/reports/iam/full-auth-details.json | \
        jq '[.RoleDetailList[] |
             select(.AssumeRolePolicyDocument.Statement[] |
               .Principal.AWS? // .Principal.Federated? // empty |
               tostring | test("^(?!arn:aws:iam::123456789012)")) |
             {role: .RoleName, trust: .AssumeRolePolicyDocument.Statement[].Principal}]'
```

---

## 5. Network & Perimeter Security

### 5.1 Security Group Analysis

```bash
# Find SGs with 0.0.0.0/0 ingress
KALI> aws ec2 describe-security-groups \
        --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
        --output json > ~/reports/network/open-sgs.json

# Parse critical open ports
KALI> cat ~/reports/network/open-sgs.json | \
        jq '[.SecurityGroups[] |
             {id: .GroupId, name: .GroupName,
              open_ports: [.IpPermissions[] |
                select(.IpRanges[]?.CidrIp == "0.0.0.0/0") |
                "\(.FromPort)-\(.ToPort)/\(.IpProtocol)"]}]'
```

**Expected Output:**

```json
[
  {
    "id": "sg-0abc123def",
    "name": "web-sg",
    "open_ports": ["80-80/tcp", "443-443/tcp"]
  },
  {
    "id": "sg-0xyz789",
    "name": "debug-sg",
    "open_ports": ["0-65535/tcp"]
  }
]
```

### 5.2 VPC Analysis

```bash
KALI> aws ec2 describe-vpcs --output json > ~/reports/network/vpcs.json
KALI> aws ec2 describe-subnets --output json > ~/reports/network/subnets.json

# Find subnets with auto-assign public IP
KALI> aws ec2 describe-subnets \
        --filters Name=map-public-ip-on-launch,Values=true \
        --query 'Subnets[].{SubnetId:SubnetId,VpcId:VpcId,CIDR:CidrBlock,AZ:AvailabilityZone}' \
        --output table
```

### 5.3 Elastic IP & Public Instance Enumeration

```bash
# All instances with public IPs
KALI> aws ec2 describe-instances \
        --filters Name=instance-state-name,Values=running \
        --query 'Reservations[].Instances[?PublicIpAddress!=null].{
          ID:InstanceId,Name:Tags[?Key==`Name`].Value|[0],
          PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,
          SGs:SecurityGroups[].GroupId}' \
        --output json > ~/reports/network/public-instances.json
```

### 5.4 CloudMapper — Network Visualization

```bash
KALI> cd ~/cloudmapper
KALI> python cloudmapper.py collect --account myaccount --profile default
KALI> python cloudmapper.py prepare --account myaccount
KALI> python cloudmapper.py webserver --account myaccount
# Open http://localhost:8000 for network topology visualization
```

### 5.5 VPC Flow Logs Verification

```bash
KALI> steampipe query "
  SELECT
    vpc_id,
    flow_logs IS NOT NULL AS has_flow_logs,
    jsonb_array_length(flow_logs) AS flow_log_count
  FROM aws_vpc;
"
```

Flag any VPC with `has_flow_logs = false`.

### 5.6 Nmap — Network Scanning

```bash
KALI> sudo nmap -sS -sV -O --top-ports 1000 \
        -oA ~/reports/network/nmap-vpc-scan \
        10.0.0.0/16
```

### 5.7 nuclei — External Endpoint Scanning

```bash
# Collect all ELB/ALB DNS names
KALI> aws elbv2 describe-load-balancers \
        --query 'LoadBalancers[].DNSName' --output text | tr '\t' '\n' > /tmp/targets.txt
KALI> aws elb describe-load-balancers \
        --query 'LoadBalancerDescriptions[].DNSName' --output text | tr '\t' '\n' >> /tmp/targets.txt

KALI> nuclei -l /tmp/targets.txt \
        -t cves/ -t misconfiguration/ -t exposures/ \
        -severity critical,high \
        -o ~/reports/network/nuclei-results.txt
```

### 5.8 WAF & Shield Status

```bash
KALI> aws wafv2 list-web-acls --scope REGIONAL --output json > ~/reports/network/waf-acls.json
KALI> aws shield describe-subscription --output json > ~/reports/network/shield.json 2>/dev/null || \
        echo '{"status":"NOT_SUBSCRIBED"}' > ~/reports/network/shield.json
```

---

## 6. Data Protection & Encryption

### 6.1 S3 Bucket Security Audit

```bash
# Comprehensive S3 audit
KALI> for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ===" >> ~/reports/data/s3-audit.txt

  # Encryption
  aws s3api get-bucket-encryption --bucket $bucket 2>&1 >> ~/reports/data/s3-audit.txt

  # Public access block
  aws s3api get-public-access-block --bucket $bucket 2>&1 >> ~/reports/data/s3-audit.txt

  # Bucket policy
  aws s3api get-bucket-policy --bucket $bucket 2>&1 >> ~/reports/data/s3-audit.txt

  # ACL
  aws s3api get-bucket-acl --bucket $bucket 2>&1 >> ~/reports/data/s3-audit.txt

  # Versioning
  aws s3api get-bucket-versioning --bucket $bucket 2>&1 >> ~/reports/data/s3-audit.txt

  # Logging
  aws s3api get-bucket-logging --bucket $bucket 2>&1 >> ~/reports/data/s3-audit.txt
done
```

### 6.2 KMS Key Audit

```bash
KALI> for key_id in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  key_meta=$(aws kms describe-key --key-id $key_id --output json)
  rotation=$(aws kms get-key-rotation-status --key-id $key_id --output json 2>/dev/null || echo '{}')
  echo "$key_meta" | jq --argjson rot "$rotation" '{
    KeyId: .KeyMetadata.KeyId,
    Description: .KeyMetadata.Description,
    KeyState: .KeyMetadata.KeyState,
    Origin: .KeyMetadata.Origin,
    RotationEnabled: $rot.KeyRotationEnabled
  }'
done > ~/reports/data/kms-audit.json
```

### 6.3 Secrets Manager Audit

```bash
KALI> aws secretsmanager list-secrets --output json > ~/reports/data/secrets-list.json

# Check rotation configuration
KALI> cat ~/reports/data/secrets-list.json | \
        jq '[.SecretList[] | {
          Name: .Name,
          RotationEnabled: .RotationEnabled,
          LastRotatedDate: .LastRotatedDate,
          DaysSinceRotation: (now - (.LastRotatedDate // 0 | tonumber) | . / 86400 | floor)
        }]'
```

### 6.4 RDS Encryption & Public Access

```bash
KALI> steampipe query "
  SELECT
    db_instance_identifier,
    engine, engine_version,
    storage_encrypted,
    kms_key_id,
    publicly_accessible,
    deletion_protection,
    auto_minor_version_upgrade,
    multi_az
  FROM aws_rds_db_instance;
"
```

**Expected Output:**

```text
+--------------------------+----------+--------+-------------------+-------------+--------------------+---------------------+---------+
| db_instance_identifier   | engine   | version| storage_encrypted | kms_key_id  | publicly_accessible| deletion_protection | multi_az|
+--------------------------+----------+--------+-------------------+-------------+--------------------+---------------------+---------+
| prod-db                  | postgres | 15.4   | true              | arn:aws:kms… | false              | true                | true    |
| dev-db                   | mysql    | 8.0    | false             | null        | true               | false               | false   |
+--------------------------+----------+--------+-------------------+-------------+--------------------+---------------------+---------+
```

### 6.5 EBS Volume Encryption

```bash
KALI> steampipe query "
  SELECT volume_id, size, state, encrypted, kms_key_id,
         attachments -> 0 ->> 'InstanceId' AS instance_id
  FROM aws_ebs_volume
  WHERE NOT encrypted;
"
```

### 6.6 CloudTrail Encryption

```bash
KALI> aws cloudtrail describe-trails --output json | \
        jq '[.trailList[] | {
          Name: .Name,
          S3BucketName: .S3BucketName,
          KmsKeyId: .KmsKeyId,
          LogFileValidation: .LogFileValidationEnabled,
          IsMultiRegion: .IsMultiRegionTrail
        }]'
```

---

## 7. Runtime, Container & Serverless Security

### 7.1 EKS Cluster Security

```bash
# List and audit EKS clusters
KALI> for cluster in $(aws eks list-clusters --query 'clusters[]' --output text); do
  aws eks describe-cluster --name $cluster --output json
done > ~/reports/runtime/eks-clusters.json

# Check for critical settings
KALI> cat ~/reports/runtime/eks-clusters.json | \
        jq '{
          name: .cluster.name,
          version: .cluster.version,
          endpoint_public: .cluster.resourcesVpcConfig.endpointPublicAccess,
          endpoint_private: .cluster.resourcesVpcConfig.endpointPrivateAccess,
          public_cidrs: .cluster.resourcesVpcConfig.publicAccessCidrs,
          encryption: .cluster.encryptionConfig,
          logging: .cluster.logging.clusterLogging
        }'
```

**Expected Output:**

```json
{
  "name": "prod-eks",
  "version": "1.28",
  "endpoint_public": true,
  "endpoint_private": true,
  "public_cidrs": ["203.0.113.0/24"],
  "encryption": [{"provider": {"keyArn": "arn:aws:kms:..."}, "resources": ["secrets"]}],
  "logging": [{"types": ["api","audit","authenticator"], "enabled": true}]
}
```

### 7.2 kube-bench — EKS CIS Benchmark

```bash
KALI> aws eks update-kubeconfig --name prod-eks --region us-east-1
KALI> kube-bench run --targets=node,policies \
        --benchmark eks-1.3.0 \
        --json --outputfile ~/reports/runtime/kube-bench-eks.json
```

### 7.3 kube-hunter — EKS Penetration Testing

```bash
KALI> ENDPOINT=$(aws eks describe-cluster --name prod-eks \
        --query 'cluster.endpoint' --output text | sed 's|https://||')
KALI> kube-hunter --remote $ENDPOINT \
        --report json > ~/reports/runtime/kube-hunter-eks.json
```

### 7.4 trivy — ECR Image Scanning

```bash
# Login to ECR
KALI> aws ecr get-login-password --region us-east-1 | \
        docker login --username AWS --password-stdin \
        123456789012.dkr.ecr.us-east-1.amazonaws.com

# Scan all images in ECR
KALI> for repo in $(aws ecr describe-repositories \
        --query 'repositories[].repositoryUri' --output text); do
  latest_tag=$(aws ecr describe-images \
    --repository-name $(echo $repo | cut -d/ -f2) \
    --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' \
    --output text)
  echo "Scanning $repo:$latest_tag"
  trivy image --severity CRITICAL,HIGH \
    --format json \
    --output ~/reports/runtime/trivy-$(echo $repo | tr '/:' '_').json \
    "$repo:$latest_tag"
done
```

### 7.5 Lambda Security Audit

```bash
KALI> cloudfox aws lambda --profile default -o ~/reports/runtime/

# Check for exposed Lambda URLs
KALI> for fn in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do
  url_config=$(aws lambda get-function-url-config --function-name $fn 2>/dev/null)
  if [ $? -eq 0 ]; then
    auth=$(echo $url_config | jq -r '.AuthType')
    if [ "$auth" == "NONE" ]; then
      echo "UNAUTHENTICATED LAMBDA URL: $fn → $(echo $url_config | jq -r '.FunctionUrl')"
    fi
  fi
done > ~/reports/runtime/public-lambdas.txt
```

### 7.6 Falco — EKS Runtime Detection

```bash
# Deploy Falco as DaemonSet on EKS
KALI> helm repo add falcosecurity https://falcosecurity.github.io/charts
KALI> helm install falco falcosecurity/falco \
        --namespace falco --create-namespace \
        --set falcosidekick.enabled=true \
        --set falcosidekick.config.customfields="cloud:aws"
```

### 7.7 ECS Security Assessment

```bash
KALI> steampipe query "
  SELECT
    cluster_arn, service_name,
    task_definition,
    launch_type,
    network_configuration,
    d.task_definition_arn,
    d.network_mode,
    d.pid_mode,
    d.ipc_mode
  FROM aws_ecs_service s
  JOIN aws_ecs_task_definition d
    ON s.task_definition = d.task_definition_arn;
"
```

---

## 8. Supply-Chain & CI/CD Security

### 8.1 ECR Repository Security

```bash
# Check repository policies and scanning config
KALI> for repo in $(aws ecr describe-repositories \
        --query 'repositories[].repositoryName' --output text); do
  echo "=== $repo ===" >> ~/reports/cicd/ecr-audit.txt
  aws ecr get-repository-policy --repository-name $repo 2>&1 >> ~/reports/cicd/ecr-audit.txt
  aws ecr describe-image-scan-findings --repository-name $repo \
    --image-id imageTag=latest 2>&1 >> ~/reports/cicd/ecr-audit.txt
done

# Check if image scanning is enabled
KALI> aws ecr describe-repositories --query 'repositories[].{
  Name:repositoryName,
  ScanOnPush:imageScanningConfiguration.scanOnPush,
  Encryption:encryptionConfiguration.encryptionType
}' --output table
```

### 8.2 CodeBuild / CodePipeline Audit

```bash
# List CodeBuild projects and check for secrets
KALI> for project in $(aws codebuild list-projects --query 'projects[]' --output text); do
  build_env=$(aws codebuild batch-get-projects --names $project \
    --query 'projects[0].environment' --output json)
  echo "$build_env" | jq --arg proj "$project" '{
    project: $proj,
    privileged_mode: .privilegedMode,
    env_vars: [.environmentVariables[] | select(.type == "PLAINTEXT") |
               {name: .name, value_preview: (.value[:20])}]
  }'
done > ~/reports/cicd/codebuild-audit.json

# List CodePipeline pipelines
KALI> aws codepipeline list-pipelines --output json > ~/reports/cicd/pipelines.json
```

### 8.3 SBOM & CVE Analysis

```bash
KALI> for repo in $(aws ecr describe-repositories \
        --query 'repositories[].repositoryUri' --output text); do
  tag=$(aws ecr describe-images \
    --repository-name $(echo $repo | cut -d/ -f2) \
    --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' \
    --output text)
  syft "$repo:$tag" -o spdx-json > ~/reports/cicd/sbom-$(echo $repo | tr '/:' '_').spdx.json
  grype sbom:~/reports/cicd/sbom-$(echo $repo | tr '/:' '_').spdx.json \
    --output json > ~/reports/cicd/vulns-$(echo $repo | tr '/:' '_').json
done
```

### 8.4 checkov — CI/CD Pipeline Scanning

```bash
KALI> checkov -d ~/repo/.github/workflows/ --framework github_actions \
        --output json --output-file-path ~/reports/cicd/checkov-gha.json
KALI> checkov -d ~/repo/ --framework cloudformation \
        --output json --output-file-path ~/reports/cicd/checkov-cfn.json
```

---

## 9. Automated Reconnaissance & Validation Pipelines

### 9.1 Full Automated Recon Script

```bash
#!/usr/bin/env bash
# aws_recon_pipeline.sh
set -euo pipefail

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_BASE=~/reports/aws-${ACCOUNT_ID}-${TIMESTAMP}
mkdir -p $REPORT_BASE/{iam,network,data,runtime,cicd,recon,compliance}

echo "[*] Phase 1: Configuration & Compliance"
prowler aws --output-formats json-ocsf \
  --output-directory $REPORT_BASE/compliance/ 2>&1 | tee $REPORT_BASE/compliance/prowler.log

echo "[*] Phase 2: IAM Enumeration"
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --output json | jq -r '.Content' | base64 -d > $REPORT_BASE/iam/credential-report.csv
aws iam get-account-authorization-details --output json > $REPORT_BASE/iam/full-auth.json
cloudfox aws iam-simulator --profile default -o $REPORT_BASE/iam/
pmapper graph create --output-file $REPORT_BASE/iam/pmapper-graph.json

echo "[*] Phase 3: Network"
aws ec2 describe-security-groups --output json > $REPORT_BASE/network/security-groups.json
aws ec2 describe-instances --output json > $REPORT_BASE/network/instances.json

echo "[*] Phase 4: Data Protection"
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api get-public-access-block --bucket $bucket >> $REPORT_BASE/data/s3-public-access.json 2>&1
done

echo "[*] Phase 5: Runtime"
for cluster in $(aws eks list-clusters --query 'clusters[]' --output text 2>/dev/null); do
  aws eks describe-cluster --name $cluster >> $REPORT_BASE/runtime/eks.json 2>&1
done

echo "[*] Phase 6: Supply Chain"
aws ecr describe-repositories --output json > $REPORT_BASE/cicd/ecr-repos.json 2>/dev/null || true

echo "[*] Phase 7: SHA-256 Manifest"
find $REPORT_BASE -type f -exec sha256sum {} \; > $REPORT_BASE/SHA256SUMS.txt

echo "[+] Complete. Report: $REPORT_BASE"
```

### 9.2 Scheduled Pipeline

```bash
KALI> crontab -e
# Weekly at 3 AM Sunday
0 3 * * 0 /home/kali/aws_recon_pipeline.sh >> /var/log/aws-recon.log 2>&1
```

---

## 10. IAM / Path Analysis at Scale (Pacu Deep Dive)

### 10.1 Pacu — Full Command Library

Pacu is the AWS exploitation framework. Below is the comprehensive module reference.

#### 10.1.1 Session Setup

```text
KALI> cd ~/pacu && python3 cli.py

Pacu> set_keys
  Access Key ID: AKIAEXAMPLE...
  Secret Access Key: ****

Pacu> whoami
  User: sec-tester
  Account: 123456789012
  ARN: arn:aws:iam::123456789012:user/sec-tester
```

#### 10.1.2 Enumeration Modules

```text
# IAM enumeration
Pacu> run iam__enum_users_roles_policies_groups
# Expected: Enumerating users ... 12 found
#           Enumerating roles ... 34 found
#           Enumerating policies ... 67 found
#           Enumerating groups ... 8 found

# EC2 enumeration
Pacu> run ec2__enum
# Expected: Found 47 instances across 4 regions

# Lambda enumeration
Pacu> run lambda__enum
# Expected: Found 23 functions across 3 regions

# S3 enumeration
Pacu> run s3__enum
# Expected: Found 45 buckets

# RDS enumeration
Pacu> run rds__enum
# Expected: Found 12 RDS instances across 2 regions

# ECS enumeration
Pacu> run ecs__enum
# Expected: Found 8 ECS clusters, 34 services

# CloudFormation enumeration
Pacu> run cfn__enum
# Expected: Found 23 stacks across 4 regions

# Secrets Manager enumeration
Pacu> run secretsmanager__enum
# Expected: Found 15 secrets

# SSM Parameter Store
Pacu> run ssm__enum
# Expected: Found 42 parameters (8 SecureString)
```

#### 10.1.3 Privilege Escalation Modules

```text
# Scan for ALL privilege escalation methods
Pacu> run iam__privesc_scan
# Expected:
# [+] Checking 21 known privesc methods ...
# [!] PRIVESC: iam:CreatePolicyVersion — user "legacy-deploy" can create new policy versions
# [!] PRIVESC: iam:PassRole + lambda:CreateFunction — role "dev-lambda-role"
# [!] PRIVESC: iam:AttachUserPolicy — group "dev-team" members can attach admin policy
# [!] PRIVESC: ec2:RunInstances + iam:PassRole — user "ci-bot" can launch instance with any role
# Results: 4 escalation paths found

# Attempt specific escalation (use with authorization only)
Pacu> run iam__privesc_scan --method CreateNewPolicyVersion
```

#### 10.1.4 Credential Discovery

```text
# Search for credentials in EC2 user data
Pacu> run ec2__download_userdata
# Expected: Downloaded user data for 47 instances
#           [!] Found AWS_SECRET_ACCESS_KEY in user data of i-0abc123

# Search Lambda environment variables
Pacu> run lambda__enum --regions all
Pacu> data Lambda
# Manually inspect for credentials in environment variables

# Search SSM parameters
Pacu> run ssm__enum
# Expected: Found 8 SecureString parameters
```

#### 10.1.5 Persistence Modules

```text
# Create backdoor access key (authorized testing only)
Pacu> run iam__backdoor_users_keys --target-user sec-tester

# Create backdoor assume-role trust
Pacu> run iam__backdoor_assume_role --role-name test-role \
        --principal arn:aws:iam::ATTACKER_ACCOUNT:root
```

#### 10.1.6 Exfiltration Testing

```text
# Test S3 data access
Pacu> run s3__download_bucket --dl-names sensitive-data-bucket

# Test EBS snapshot sharing
Pacu> run ebs__enum_snapshots
# Check for publicly shared snapshots
```

#### 10.1.7 Session Data Export

```text
Pacu> export_keys
Pacu> data all --output ~/reports/iam/pacu-session.json
```

### 10.2 CloudFox — AWS Attack Surface

```bash
KALI> cloudfox aws all-checks --profile default -o ~/reports/iam/cloudfox/
```

**Key CloudFox Outputs:**

```text
[i] cloudfox aws access-keys
    → Found 3 access keys older than 90 days

[i] cloudfox aws buckets
    → Found 2 publicly accessible buckets

[i] cloudfox aws endpoints
    → Found 15 externally accessible endpoints

[i] cloudfox aws env-vars
    → Found 4 Lambda functions with hardcoded credentials in env vars

[i] cloudfox aws iam-simulator
    → Found 6 principals with dangerous permission combinations

[i] cloudfox aws instances
    → Found 12 instances with instance profiles attached

[i] cloudfox aws permissions
    → Generated permission matrix for 87 principals
```

---

## 11. Neo4j Attack-Path Setup & Visualization

### 11.1 Neo4j Configuration

Same as Doc 1 §11.1 — configure memory, APOC plugin, and bolt access.

### 11.2 Loading AWS Data via Cartography

```bash
KALI> cartography --aws-requested-syncs iam,ec2,s3,lambda,eks,rds,secretsmanager \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password-env-var NEO4J_PASSWORD
```

**Expected Output:**

```text
INFO - Starting AWS IAM sync ...
INFO - Synced 87 users, 34 roles, 67 policies, 142 bindings
INFO - Starting AWS EC2 sync ...
INFO - Synced 47 instances, 89 security groups, 23 VPCs
INFO - Starting AWS S3 sync ...
INFO - Synced 45 buckets, 127 ACLs
INFO - Sync complete. Nodes: 892, Relationships: 4,231
```

### 11.3 AWS Attack-Path Cypher Queries

```cypher
// Internet → EC2 → IAM Role → S3 Sensitive Data
MATCH path = (internet:Internet)-[:EXPOSES]->(sg:EC2SecurityGroup)
              -[:ALLOWS_INGRESS]->(instance:EC2Instance)
              -[:ASSUMES_ROLE]->(role:AWSRole)
              -[:HAS_POLICY]->(policy:AWSPolicy)
              -[:ALLOWS]->(s3:S3Bucket)
WHERE sg.cidr = '0.0.0.0/0'
  AND s3.name CONTAINS 'prod'
RETURN path LIMIT 20;

// Cross-account assume-role chains
MATCH path = (role1:AWSRole)-[:CAN_ASSUME*1..3]->(role2:AWSRole)
WHERE role1.account <> role2.account
RETURN role1.arn, role2.arn, length(path) AS hops
ORDER BY hops;

// Lambda → Sensitive Data paths
MATCH path = (lambda:AWSLambda)-[:HAS_ROLE]->(role:AWSRole)
              -[:HAS_POLICY]->(policy:AWSPolicy)
              -[:ALLOWS]->(resource)
WHERE resource:S3Bucket OR resource:RDSInstance OR resource:SecretsManagerSecret
RETURN lambda.name, role.arn, type(last(relationships(path))), resource
LIMIT 50;

// Privilege escalation via iam:PassRole
MATCH (principal)-[:HAS_POLICY]->(policy:AWSPolicy)-[:ALLOWS {action:"iam:PassRole"}]->(target:AWSRole)
MATCH (target)-[:HAS_POLICY]->(admin_policy:AWSPolicy)
WHERE admin_policy.arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
RETURN principal, target, admin_policy;
```

### 11.4 pmapper Graph to Neo4j

```bash
KALI> pmapper graph create
KALI> pmapper visualize --filetype svg --output ~/reports/iam/pmapper-graph.svg
```

---

## 12. Multi-Cloud Attack-Surface Mapping

### 12.1 CloudFox — Full AWS Attack Surface

```bash
KALI> cloudfox aws all-checks --profile default -o ~/reports/multicloud/aws/
```

### 12.2 Steampipe — Cross-Cloud Queries

```sql
-- All public-facing resources across AWS
SELECT 'AWS' AS cloud, 'S3' AS type, name AS resource
FROM aws_s3_bucket
WHERE bucket_policy_is_public

UNION ALL

SELECT 'AWS' AS cloud, 'EC2' AS type, instance_id AS resource
FROM aws_ec2_instance
WHERE public_ip_address IS NOT NULL

UNION ALL

SELECT 'AWS' AS cloud, 'Lambda' AS type, name AS resource
FROM aws_lambda_function f
WHERE EXISTS (
  SELECT 1 FROM aws_lambda_function_url_config u
  WHERE u.function_name = f.name AND u.auth_type = 'NONE'
);
```

### 12.3 Cross-Cloud Credential Detection

```bash
# Check for GCP/Azure creds in AWS
KALI> cloudfox aws env-vars --profile default -o ~/reports/multicloud/

# Search Lambda env vars for cross-cloud secrets
KALI> aws lambda list-functions --query 'Functions[].FunctionName' --output text | \
        tr '\t' '\n' | while read fn; do
  env=$(aws lambda get-function-configuration --function-name $fn \
    --query 'Environment.Variables' --output json 2>/dev/null)
  if echo "$env" | grep -qiE '(GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|AZURE_TENANT)'; then
    echo "CROSS-CLOUD CRED: lambda=$fn" >> ~/reports/multicloud/shared-creds.txt
  fi
done

# Check SSM Parameter Store
KALI> aws ssm describe-parameters --output json | \
        jq '.Parameters[] | select(.Name | test("(?i)(gcp|google|azure)")) | .Name'
```

---

## 13. Hybrid Cloud Security Tools (Steampipe, CloudQuery, Cartography)

### 13.1 Steampipe — AWS CIS Compliance Mod

```bash
KALI> cd ~ && git clone https://github.com/turbot/steampipe-mod-aws-compliance.git
KALI> cd steampipe-mod-aws-compliance
KALI> steampipe check all --output json > ~/reports/hybrid/steampipe-aws-cis.json
```

**Expected Output (truncated):**

```json
{
  "summary": {
    "status": { "ok": 187, "alarm": 34, "error": 3, "skip": 8 }
  },
  "groups": [
    {
      "title": "CIS AWS 2.0 - 1.4 Ensure no root access keys exist",
      "status": "alarm"
    }
  ]
}
```

### 13.2 CloudQuery — AWS Asset Inventory

Create `cloudquery-aws.yml`:

```yaml
kind: source
spec:
  name: aws
  registry: cloudquery
  path: cloudquery/aws
  version: "v25.0.0"
  tables: ["*"]
  destinations: ["postgresql"]
  spec:
    regions: ["us-east-1", "us-west-2", "eu-west-1"]

---
kind: destination
spec:
  name: postgresql
  registry: cloudquery
  path: cloudquery/postgresql
  version: "v7.0.0"
  spec:
    connection_string: "postgresql://localhost:5432/cloudquery?sslmode=disable"
```

```bash
KALI> cloudquery sync cloudquery-aws.yml
# Expected: Sync complete: 12,451 total rows across 234 tables
```

### 13.3 Cartography — Cross-Cloud Graph

```bash
KALI> cartography --aws-requested-syncs all \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password-env-var NEO4J_PASSWORD
```

---

## 14. Aggregator Integration

### 14.1 AWS-Specific Aggregator Usage

```bash
KALI> python3 aggregator.py \
        --cloud aws \
        --input-dir ~/reports/aws-123456789012-20250115_030000/ \
        --output-dir ~/reports/aggregated/ \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password $NEO4J_PASSWORD \
        --compliance-frameworks "soc2,iso27001,hipaa,pci-dss"
```

**Expected Output:**

```text
[*] Scanning input directory for findings ...
[+] Parsed 22 files, extracted 412 findings
[*] Normalising to unified schema ...
[*] Generating outputs ...
    → unified-findings.json
    → dashboard.html
    → executive-summary.md
    → neo4j-import.cypher
    → AUDIT-MANIFEST.sha256
[+] Aggregation complete. 412 findings.
```

---

## 15. Gap Analysis & Filled Gaps

### 15.1 Identified Gaps

| # | Gap | Resolution | Section |
|---|-----|-----------|---------|
| 1 | No Pacu deep dive | Added full Pacu command library (21+ modules) | §10.1 |
| 2 | No credential report analysis | Added IAM credential report generation & flags | §4.1 |
| 3 | No IAM Access Analyzer | Added Access Analyzer findings enumeration | §4.2 |
| 4 | No SSO/Federation audit | Added SSO, SAML, OIDC provider enumeration | §4.6 |
| 5 | No cross-account trust analysis | Added STS assume-role chain analysis | §4.7 |
| 6 | No WAF/Shield status | Added WAFv2 and Shield checks | §5.8 |
| 7 | No VPC Flow Logs check | Added Flow Logs verification | §5.5 |
| 8 | No EBS encryption audit | Added unencrypted EBS volume detection | §6.5 |
| 9 | No CloudTrail encryption check | Added CloudTrail KMS & log validation | §6.6 |
| 10 | No Lambda URL auth check | Added unauthenticated Lambda URL detection | §7.5 |
| 11 | No ECS security assessment | Added ECS service & task definition audit | §7.7 |
| 12 | No CodeBuild secrets scan | Added environment variable secrets detection | §8.2 |
| 13 | No pmapper integration | Added Principal Mapper for IAM graph analysis | §4.5 |
| 14 | No CloudMapper network viz | Added CloudMapper collect/prepare/visualize | §5.4 |
| 15 | No GuardDuty findings check | Added below | §15.2 |
| 16 | No AWS Config compliance check | Added above | §3.3 |
| 17 | No SSM patch compliance | Added below | §15.3 |
| 18 | No account-level S3 block | Added below | §15.4 |

### 15.2 Gap Fill: GuardDuty Findings

```bash
KALI> DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
KALI> aws guardduty get-findings --detector-id $DETECTOR_ID \
        --finding-ids $(aws guardduty list-findings --detector-id $DETECTOR_ID \
          --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
          --query 'FindingIds[]' --output text) \
        --output json > ~/reports/compliance/guardduty-findings.json
```

### 15.3 Gap Fill: SSM Patch Compliance

```bash
KALI> aws ssm describe-instance-patch-states \
        --output json > ~/reports/compliance/patch-compliance.json

KALI> cat ~/reports/compliance/patch-compliance.json | \
        jq '[.InstancePatchStates[] | {
          InstanceId: .InstanceId,
          MissingCritical: .MissingCount,
          FailedCount: .FailedCount,
          InstalledCount: .InstalledCount
        }]'
```

### 15.4 Gap Fill: Account-Level S3 Public Access Block

```bash
KALI> aws s3control get-public-access-block \
        --account-id $(aws sts get-caller-identity --query Account --output text) \
        --output json
```

Flag if any of the four block settings are `false`.

---

## 16. Report Generation & Compliance Artifacts

### 16.1 SHA-256 Signed Report Bundle

```bash
#!/usr/bin/env bash
REPORT_DIR="${1:?Usage: $0 <report-dir>}"
find $REPORT_DIR -type f ! -name 'AUDIT-MANIFEST.sha256' \
  -exec sha256sum {} \; > $REPORT_DIR/AUDIT-MANIFEST.sha256
echo "[+] Manifest: $REPORT_DIR/AUDIT-MANIFEST.sha256"
```

### 16.2 Compliance Mapping

| Framework | Relevant Sections |
|-----------|-------------------|
| **SOC 2 Type II** | CC6.1 (IAM §4), CC6.6 (Network §5), CC6.7 (Encryption §6), CC7.1 (Runtime §7) |
| **ISO 27001** | A.9 (Access §4), A.13 (Network §5), A.10 (Crypto §6), A.12 (Operations §7) |
| **HIPAA** | §164.312(a) (Access §4), §164.312(e) (Encryption §6), §164.312(b) (Audit §6.6) |
| **PCI-DSS** | Req 1 (Network §5), Req 3 (Data §6), Req 7 (Access §4), Req 10 (Logging §6.6) |

---

## 17. Appendices

### Appendix A: Tool License Summary

| Tool | License | Telemetry |
|------|---------|-----------|
| ScoutSuite | GPL-2.0 | None |
| Prowler | Apache-2.0 | None |
| Pacu | BSD-3-Clause | None |
| CloudMapper | BSD-3-Clause | None |
| Cartography | Apache-2.0 | None |
| Steampipe | AGPL-3.0 | Opt-out |
| CloudQuery | MPL-2.0 | Opt-out |
| CloudFox | MIT | None |
| trivy | Apache-2.0 | None |
| checkov | Apache-2.0 | Opt-out |
| kube-bench | Apache-2.0 | None |
| kube-hunter | Apache-2.0 | None |
| Falco | Apache-2.0 | None |
| syft | Apache-2.0 | None |
| grype | Apache-2.0 | None |
| nuclei | MIT | None |
| pmapper | AGPL-3.0 | None |
| enumerate-iam | Apache-2.0 | None |
| Neo4j Community | GPL-3.0 | Opt-out |
| Nmap | NPSL (GPL-like) | None |

### Appendix B: AWS Services to Enable/Verify

```bash
# Verify critical services
KALI> aws configservice describe-configuration-recorders
KALI> aws cloudtrail describe-trails
KALI> aws guardduty list-detectors
KALI> aws accessanalyzer list-analyzers
KALI> aws securityhub describe-hub 2>/dev/null || echo "Security Hub not enabled"
```

### Appendix C: Report File Structure

```text
aws-{account}-{timestamp}/
├── iam/
│   ├── credential-report.csv
│   ├── full-auth.json
│   ├── access-analyzer-findings.json
│   ├── cloudfox-escalation.json
│   ├── pmapper-graph.json
│   └── pacu-session.json
├── network/
│   ├── security-groups.json
│   ├── open-sgs.json
│   ├── public-instances.json
│   ├── nmap-vpc-scan.xml
│   └── nuclei-results.txt
├── data/
│   ├── s3-audit.txt
│   ├── kms-audit.json
│   └── secrets-list.json
├── runtime/
│   ├── eks-clusters.json
│   ├── kube-bench-eks.json
│   ├── trivy-*.json
│   ├── public-lambdas.txt
│   └── ecs-services.json
├── cicd/
│   ├── ecr-repos.json
│   ├── ecr-audit.txt
│   ├── codebuild-audit.json
│   └── sbom-*.spdx.json
├── compliance/
│   ├── prowler-aws-*.json
│   ├── steampipe-aws-cis.json
│   ├── guardduty-findings.json
│   └── patch-compliance.json
├── multicloud/
│   └── shared-creds.txt
├── EXECUTIVE_SUMMARY.md
├── SHA256SUMS.txt
└── AUDIT-MANIFEST.sha256
```

---

**END OF DOCUMENT 2 — AWS Security Testing Methodology**
