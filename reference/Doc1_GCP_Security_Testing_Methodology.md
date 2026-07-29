# Doc 1 — GCP Security Testing Methodology

## From Windows & Linux Boxes in Google Cloud Platform

**Version:** 2.0 — Production-Ready  
**Classification:** CONFIDENTIAL — Internal Use Only  
**Compliance Targets:** SOC 2 Type II · ISO 27001 · HIPAA · PCI-DSS  
**All tools:** 100 % open-source (Apache / MIT / GPL), zero telemetry

---

## Table of Contents

1. [Document Overview](#1-document-overview)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Configuration & Misconfiguration Assessment](#3-configuration--misconfiguration-assessment)
4. [Identity & Access (IAM, Service Accounts, Federation)](#4-identity--access-iam-service-accounts-federation)
5. [Network & Perimeter Security](#5-network--perimeter-security)
6. [Data Protection & Encryption](#6-data-protection--encryption)
7. [Runtime, Container & Serverless Security](#7-runtime-container--serverless-security)
8. [Supply-Chain & CI/CD Security](#8-supply-chain--cicd-security)
9. [Automated Reconnaissance & Validation Pipelines](#9-automated-reconnaissance--validation-pipelines)
10. [IAM / Path Analysis at Scale](#10-iam--path-analysis-at-scale)
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

This document provides a self-contained, production-ready methodology for security testing a Google Cloud Platform (GCP) environment. All checks are executed from:

| Platform | OS | Notes |
|---|---|---|
| **GCP Windows Box** | Windows Server 2022 | GCE instance, Chocolatey package manager |
| **GCP Linux Box** | Ubuntu 22.04 LTS / Debian 12 | GCE instance, standard apt-based workflow |

### 1.2 Scope Matrix

| Domain | Section |
|---|---|
| Configuration / Misconfigurations | §3 |
| Identity & Access (IAM, Service Accounts, Workload Identity Federation) | §4 |
| Network / Perimeter | §5 |
| Data Protection / Encryption | §6 |
| Runtime / Container / Serverless | §7 |
| Supply-Chain / CI/CD | §8 |
| Automated Recon + Validation Pipelines | §9 |
| IAM / Path Analysis at Scale | §10 |
| Neo4j Attack-Path Visualization | §11 |
| Multi-Cloud Attack Surface Mapping | §12 |
| Hybrid Cloud Tools | §13 |
| Aggregator (unified JSON / HTML / Neo4j) | §14 |

### 1.3 Conventions

- `WIN>` = Command executed on the Windows box.
- `LIN>` = Command executed on the Linux box.
- `BOTH>` = Identical on either platform.
- All output samples are truncated for brevity; real output will be larger.
- SHA-256 hashes are generated for every report artifact.

---

## 2. Prerequisites & Environment Setup

### 2.1 GCP Project Preparation

Before any testing, ensure the following are in place within the target GCP project.

```text
Required IAM Roles for the testing service account (minimum):
  roles/viewer                        (project-wide read)
  roles/iam.securityReviewer          (IAM policy read)
  roles/cloudasset.viewer             (Cloud Asset Inventory)
  roles/container.clusterViewer       (GKE read)
  roles/cloudfunctions.viewer         (Cloud Functions read)
  roles/run.viewer                    (Cloud Run read)
  roles/compute.securityAdmin         (firewall rule read)
  roles/logging.viewer                (audit log read)
  roles/secretmanager.viewer          (Secret Manager metadata)
  roles/bigquery.dataViewer           (BigQuery metadata)
```

Create and download a service-account key (JSON) or use Workload Identity Federation (preferred for production):

```bash
LIN> gcloud iam service-accounts create sec-tester \
       --display-name="Security Testing SA"
LIN> gcloud projects add-iam-policy-binding $PROJECT_ID \
       --member="serviceAccount:sec-tester@${PROJECT_ID}.iam.gserviceaccount.com" \
       --role="roles/viewer"
# Repeat for each role above
LIN> gcloud iam service-accounts keys create ~/sa-key.json \
       --iam-account="sec-tester@${PROJECT_ID}.iam.gserviceaccount.com"
LIN> export GOOGLE_APPLICATION_CREDENTIALS=~/sa-key.json
```

### 2.2 Linux Box Setup (Ubuntu 22.04 on GCE)

#### 2.2.1 System Updates & Core Packages

```bash
LIN> sudo apt update && sudo apt upgrade -y
LIN> sudo apt install -y \
       git curl wget unzip jq python3 python3-pip python3-venv \
       apt-transport-https ca-certificates gnupg lsb-release \
       nmap nikto dnsutils whois net-tools build-essential \
       openjdk-17-jre-headless docker.io docker-compose
LIN> sudo usermod -aG docker $USER && newgrp docker
```

#### 2.2.2 Google Cloud SDK

```bash
LIN> curl https://sdk.cloud.google.com | bash
LIN> exec -l $SHELL
LIN> gcloud init
LIN> gcloud auth activate-service-account --key-file=~/sa-key.json
LIN> gcloud config set project $PROJECT_ID
```

Verify:

```bash
LIN> gcloud auth list
# Expected output:
#    ACTIVE  ACCOUNT
#    *       sec-tester@myproject.iam.gserviceaccount.com
```

#### 2.2.3 Python Virtual Environment

```bash
LIN> python3 -m venv ~/sectest-venv
LIN> source ~/sectest-venv/bin/activate
LIN> pip install --upgrade pip setuptools wheel
```

#### 2.2.4 Tool Installation — Linux

**ScoutSuite (GCP CIS Benchmark Scanner)**

```bash
LIN> cd ~ && git clone https://github.com/nccgroup/ScoutSuite.git
LIN> cd ScoutSuite && pip install -r requirements.txt
LIN> python scout.py gcp --service-account ~/sa-key.json
```

Verify installation:

```bash
LIN> python scout.py --help
# Expected: usage: scout.py [-h] {aws,azure,gcp,...} ...
```

**Prowler (GCP provider)**

```bash
LIN> pip install prowler
LIN> prowler gcp --help
# Expected: usage: prowler gcp [-h] [--credentials-file ...] ...
```

**gcp-scanner**

```bash
LIN> pip install gcp-scanner
LIN> gcp_scanner --help
# Expected: usage: gcp_scanner [-h] ...
```

**Cartography (Neo4j graph-based recon)**

```bash
LIN> pip install cartography
LIN> cartography --help
# Expected: usage: cartography [-h] ...
```

**Steampipe + GCP Plugin**

```bash
LIN> sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
LIN> steampipe plugin install gcp
LIN> steampipe query "select 1 as test"
# Expected:
# +------+
# | test |
# +------+
# | 1    |
# +------+
```

**CloudQuery**

```bash
LIN> curl -L https://github.com/cloudquery/cloudquery/releases/latest/download/cloudquery_linux_amd64 \
       -o /usr/local/bin/cloudquery && chmod +x /usr/local/bin/cloudquery
LIN> cloudquery --help
# Expected: CloudQuery CLI ...
```

**CloudFox (GCP support)**

```bash
LIN> wget https://github.com/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip
LIN> unzip cloudfox-linux-amd64.zip -d /usr/local/bin/
LIN> cloudfox gcp --help
# Expected: Available Commands: iam-simulator, instances, ...
```

**trivy (Container & IaC scanning)**

```bash
LIN> curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
       sudo sh -s -- -b /usr/local/bin
LIN> trivy --version
# Expected: Version: 0.5x.x
```

**checkov (IaC misconfiguration scanner)**

```bash
LIN> pip install checkov
LIN> checkov --version
# Expected: 3.x.x
```

**kube-bench**

```bash
LIN> curl -L https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_linux_amd64.tar.gz | \
       tar xz -C /usr/local/bin
LIN> kube-bench version
# Expected: kube-bench v0.8.x
```

**kube-hunter**

```bash
LIN> pip install kube-hunter
LIN> kube-hunter --help
# Expected: usage: kube-hunter ...
```

**Falco (runtime threat detection)**

```bash
LIN> curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
       sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
LIN> echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
       https://download.falco.org/packages/deb stable main" | \
       sudo tee /etc/apt/sources.list.d/falcosecurity.list
LIN> sudo apt update && sudo apt install -y falco
LIN> falco --version
# Expected: Falco version: 0.3x.x
```

**syft + grype (SBOM & CVE scanning)**

```bash
LIN> curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
       sudo sh -s -- -b /usr/local/bin
LIN> curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
       sudo sh -s -- -b /usr/local/bin
LIN> syft version && grype version
```

**Neo4j Community Edition**

```bash
LIN> wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
LIN> echo 'deb https://debian.neo4j.com stable latest' | \
       sudo tee /etc/apt/sources.list.d/neo4j.list
LIN> sudo apt update && sudo apt install -y neo4j
LIN> sudo systemctl enable neo4j && sudo systemctl start neo4j
# Default: http://localhost:7474  user=neo4j  pw=neo4j (change on first login)
```

**Additional Recon Tools**

```bash
LIN> go install github.com/projectdiscovery/httpx/cmd/httpx@latest
LIN> go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
LIN> go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
LIN> nuclei -update-templates
```

(Requires Go 1.21+: `sudo snap install go --classic`)

### 2.3 Windows Box Setup (Windows Server 2022 on GCE)

#### 2.3.1 Chocolatey & Core Packages

```powershell
WIN> Set-ExecutionPolicy Bypass -Scope Process -Force
WIN> [System.Net.ServicePointManager]::SecurityProtocol = `
       [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
WIN> iex ((New-Object System.Net.WebClient).DownloadString(
       'https://community.chocolatey.org/install.ps1'))
WIN> choco install -y git python3 nmap jq googlechromium curl wget `
       openjdk17 golang docker-desktop nodejs-lts 7zip
```

#### 2.3.2 Google Cloud SDK (Windows)

```powershell
WIN> choco install -y gcloudsdk
WIN> gcloud init
WIN> gcloud auth activate-service-account --key-file=C:\keys\sa-key.json
WIN> gcloud config set project $env:PROJECT_ID
```

#### 2.3.3 Python Tools (Windows)

```powershell
WIN> python -m venv C:\sectest-venv
WIN> C:\sectest-venv\Scripts\Activate.ps1
WIN> pip install scoutsuite prowler gcp-scanner cartography checkov kube-hunter
```

#### 2.3.4 Steampipe (Windows)

```powershell
WIN> choco install -y steampipe
WIN> steampipe plugin install gcp
WIN> steampipe query "select 1 as test"
```

#### 2.3.5 Go-based Tools (Windows)

```powershell
WIN> go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
WIN> go install github.com/projectdiscovery/httpx/cmd/httpx@latest
WIN> nuclei -update-templates
```

#### 2.3.6 Neo4j Desktop (Windows)

Download Neo4j Community from https://neo4j.com/download-center/ and install. Start via Services or:

```powershell
WIN> neo4j console
# Browse to http://localhost:7474
```

### 2.4 Environment Validation Checklist

Run this script on either platform to validate all tools are present:

```bash
#!/usr/bin/env bash
# validate_tools.sh — run on Linux; adapt for PowerShell on Windows
TOOLS=(
  "gcloud:gcloud --version"
  "scout:python scout.py --help"
  "prowler:prowler --help"
  "gcp_scanner:gcp_scanner --help"
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
)
for entry in "${TOOLS[@]}"; do
  IFS=":" read -r name cmd <<< "$entry"
  if $cmd &>/dev/null; then
    echo "[OK]   $name"
  else
    echo "[FAIL] $name — command: $cmd"
  fi
done
```

Expected output (all OK):

```text
[OK]   gcloud
[OK]   scout
[OK]   prowler
...
[OK]   cartography
```

---

## 3. Configuration & Misconfiguration Assessment

### 3.1 ScoutSuite — Full GCP Scan

ScoutSuite checks 150+ CIS-benchmark rules across all GCP services.

```bash
LIN> cd ~/ScoutSuite
LIN> python scout.py gcp \
       --service-account ~/sa-key.json \
       --report-dir ~/reports/scoutsuite \
       --no-browser
```

```powershell
WIN> cd C:\ScoutSuite
WIN> python scout.py gcp `
       --service-account C:\keys\sa-key.json `
       --report-dir C:\reports\scoutsuite `
       --no-browser
```

**Expected Output (truncated):**

```text
Fetching data for project myproject-123456 ...
  iam              [##########] 100%   12 resources
  compute          [##########] 100%  147 resources
  storage          [##########] 100%   34 resources
  ...
Processing data ...
  Rules evaluated: 168
  Dangers:         14
  Warnings:        37
  Passing:          117

Report saved to ~/reports/scoutsuite/gcp-myproject.html
```

Open the HTML report; it organises findings by service, severity, and CIS benchmark ID.

### 3.2 Prowler — GCP CIS & Custom Checks

```bash
LIN> prowler gcp \
       --credentials-file ~/sa-key.json \
       --output-formats json-ocsf,html,csv \
       --output-directory ~/reports/prowler \
       --severity critical high \
       --compliance cis_gcp_2.0
```

**Expected Output (truncated):**

```text
Prowler v4.x.x — GCP Provider
Scanning project: myproject-123456

[CRITICAL] gcp_compute_default_service_account_in_use: VM instance "web-prod-01"
           uses default compute SA → FAIL
[HIGH]     gcp_iam_sa_key_rotation: SA key for "deploy-bot" not rotated in 120 days → FAIL
[HIGH]     gcp_storage_bucket_public_access: Bucket "staging-assets" allows allUsers → FAIL
...
Results: 42 PASS | 14 FAIL (9 CRITICAL, 5 HIGH) | 3 MANUAL
CSV report:  ~/reports/prowler/prowler-gcp-*.csv
HTML report: ~/reports/prowler/prowler-gcp-*.html
```

### 3.3 gcp-scanner — Broad Enumeration

```bash
LIN> gcp_scanner \
       --sa-key ~/sa-key.json \
       -o ~/reports/gcp-scanner/ \
       --project-id $PROJECT_ID
```

**Expected Output:**

```text
[*] Enumerating Compute Engine instances ...
[+] Found 23 instances across 4 zones
[*] Enumerating Cloud Storage buckets ...
[+] Found 12 buckets (3 with public ACLs)
[*] Enumerating BigQuery datasets ...
[+] Found 7 datasets
...
Results written to ~/reports/gcp-scanner/results.json
```

### 3.4 Steampipe — SQL-Based Compliance Queries

Steampipe lets you query GCP resources with SQL. Create a compliance dashboard:

```bash
LIN> steampipe query "
  SELECT
    name,
    iam_configuration -> 'uniformBucketLevelAccess' ->> 'enabled' AS uniform_access,
    CASE
      WHEN iam_configuration -> 'uniformBucketLevelAccess' ->> 'enabled' = 'true'
        THEN 'PASS'
      ELSE 'FAIL'
    END AS status
  FROM gcp_storage_bucket
  ORDER BY status;
"
```

**Expected Output:**

```text
+---------------------+----------------+--------+
| name                | uniform_access | status |
+---------------------+----------------+--------+
| prod-data-lake      | true           | PASS   |
| staging-assets      | false          | FAIL   |
| backup-2024         | true           | PASS   |
+---------------------+----------------+--------+
```

More CIS queries:

```bash
# Check for VMs with public IPs
LIN> steampipe query "
  SELECT name, zone,
         n -> 'accessConfigs' AS access_configs
  FROM gcp_compute_instance,
       jsonb_array_elements(network_interfaces) AS n
  WHERE n -> 'accessConfigs' IS NOT NULL;
"

# Check for default service accounts on VMs
LIN> steampipe query "
  SELECT name, zone,
         s ->> 'email' AS sa_email
  FROM gcp_compute_instance,
       jsonb_array_elements(service_accounts) AS s
  WHERE s ->> 'email' LIKE '%-compute@developer.gserviceaccount.com';
"
```

### 3.5 checkov — IaC Scanning for Terraform / Deployment Manager

```bash
LIN> checkov -d ~/infra/terraform/ \
       --framework terraform \
       --output json \
       --output-file-path ~/reports/checkov/ \
       --check CKV_GCP_1,CKV_GCP_2,CKV_GCP_3,CKV_GCP_6,CKV_GCP_7
```

**Expected Output:**

```text
Passed checks: 42, Failed checks: 8, Skipped checks: 2

Check: CKV_GCP_6: "Ensure GKE cluster has private nodes"
  FAILED for resource: google_container_cluster.primary
  File: /modules/gke/main.tf:12-45
  Guide: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/google-cloud-policies/...

Check: CKV_GCP_7: "Ensure Legacy Authorization is disabled on GKE"
  FAILED for resource: google_container_cluster.primary
  File: /modules/gke/main.tf:12-45
```

---

## 4. Identity & Access (IAM, Service Accounts, Federation)

### 4.1 IAM Policy Enumeration

```bash
# Full project IAM policy
LIN> gcloud projects get-iam-policy $PROJECT_ID --format=json \
       > ~/reports/iam/project-policy.json

# List all service accounts
LIN> gcloud iam service-accounts list --format=json \
       > ~/reports/iam/service-accounts.json

# For each SA, list keys
LIN> for sa in $(gcloud iam service-accounts list --format='value(email)'); do
       echo "=== $sa ===" >> ~/reports/iam/sa-keys.txt
       gcloud iam service-accounts keys list --iam-account=$sa \
         --format='table(name,validAfterTime,validBeforeTime,keyType)' \
         >> ~/reports/iam/sa-keys.txt
     done
```

**Expected Output (sa-keys.txt):**

```text
=== sec-tester@myproject.iam.gserviceaccount.com ===
KEY_ID                                    VALID_AFTER              VALID_BEFORE             KEY_TYPE
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 2024-01-15T00:00:00Z     2025-01-15T00:00:00Z     USER_MANAGED
=== deploy-bot@myproject.iam.gserviceaccount.com ===
KEY_ID                                    VALID_AFTER              VALID_BEFORE             KEY_TYPE
f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5 2023-06-01T00:00:00Z     2024-06-01T00:00:00Z     USER_MANAGED  ← EXPIRED!
```

### 4.2 Overprivileged IAM Detection

```bash
# Find all members with Owner/Editor roles (overprivileged)
LIN> gcloud projects get-iam-policy $PROJECT_ID --format=json | \
       jq '[.bindings[] | select(.role == "roles/owner" or .role == "roles/editor") |
            {role: .role, members: .members}]'
```

**Expected Output:**

```json
[
  {
    "role": "roles/editor",
    "members": [
      "serviceAccount:deploy-bot@myproject.iam.gserviceaccount.com",
      "user:dev.intern@company.com"
    ]
  },
  {
    "role": "roles/owner",
    "members": [
      "user:admin@company.com"
    ]
  }
]
```

### 4.3 Workload Identity Federation Check

```bash
# List Workload Identity Pools
LIN> gcloud iam workload-identity-pools list --location=global --format=json

# For each pool, list providers
LIN> gcloud iam workload-identity-pools providers list \
       --workload-identity-pool=$POOL_ID \
       --location=global --format=json
```

### 4.4 Domain-Wide Delegation Audit

```bash
LIN> gcloud iam service-accounts list --format=json | \
       jq '.[] | select(.oauth2ClientId != null) |
           {email: .email, clientId: .oauth2ClientId, displayName: .displayName}'
```

Cross-check output against the Google Workspace Admin console → Security → API controls → Domain-wide delegation. Any SA with DWD enabled can impersonate any user in the domain.

### 4.5 Custom Role Audit

```bash
LIN> gcloud iam roles list --project=$PROJECT_ID --format=json | \
       jq '.[] | {name: .name, title: .title, permissions: (.includedPermissions | length)}'
```

Flag any custom roles with `iam.serviceAccountTokenCreator` or `iam.serviceAccountUser` — these enable lateral movement.

### 4.6 CloudFox — IAM Privilege Escalation Paths

```bash
LIN> cloudfox gcp iam-simulator --project $PROJECT_ID -o ~/reports/cloudfox/
```

**Expected Output:**

```text
[i] Enumerating IAM permissions for all principals ...
[!] PRIVESC PATH: deploy-bot@myproject.iam.gserviceaccount.com
    → has iam.serviceAccountKeys.create on sec-tester@myproject.iam.gserviceaccount.com
    → can create key and impersonate sec-tester SA
[!] PRIVESC PATH: dev.intern@company.com
    → has roles/editor (includes compute.instances.setServiceAccount)
    → can attach any SA to a VM and steal tokens
...
Results: ~/reports/cloudfox/iam-simulator.json
```

---

## 5. Network & Perimeter Security

### 5.1 Firewall Rule Enumeration

```bash
LIN> gcloud compute firewall-rules list --format=json \
       > ~/reports/network/firewall-rules.json

# Find rules allowing 0.0.0.0/0
LIN> gcloud compute firewall-rules list \
       --filter="sourceRanges:0.0.0.0/0 AND direction=INGRESS" \
       --format='table(name,allowed[].map().firewall_rule().list(),targetTags,targetServiceAccounts)'
```

**Expected Output:**

```text
NAME                 ALLOWED                  TARGET_TAGS  TARGET_SERVICE_ACCOUNTS
default-allow-ssh    tcp:22                   []           []
web-allow-http       tcp:80,tcp:443           [web-tier]   []
debug-allow-all      tcp:0-65535,udp:0-65535  []           []  ← DANGER: all ports
```

### 5.2 VPC & Subnet Analysis

```bash
LIN> gcloud compute networks list --format=json > ~/reports/network/vpcs.json
LIN> gcloud compute networks subnets list --format=json > ~/reports/network/subnets.json

# Check for subnets without Private Google Access
LIN> steampipe query "
  SELECT name, region, ip_cidr_range, private_ip_google_access
  FROM gcp_compute_subnetwork
  WHERE NOT private_ip_google_access;
"
```

### 5.3 External IP Enumeration

```bash
LIN> gcloud compute addresses list --filter="status=IN_USE AND addressType=EXTERNAL" \
       --format='table(name,address,region,users)'
```

### 5.4 Nmap — Network Scanning from Inside VPC

```bash
# Scan a specific subnet for common services
LIN> sudo nmap -sS -sV -O --top-ports 1000 \
       -oA ~/reports/network/nmap-vpc-scan \
       10.128.0.0/24
```

**Expected Output (truncated):**

```text
Nmap scan report for 10.128.0.5
Host is up (0.0012s latency).
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1
80/tcp   open  http     nginx 1.24.0
443/tcp  open  ssl/http nginx 1.24.0
3306/tcp open  mysql    MySQL 8.0.35  ← Should not be exposed!
```

### 5.5 Cloud Armor & Load Balancer Security

```bash
LIN> gcloud compute security-policies list --format=json \
       > ~/reports/network/cloud-armor-policies.json

# Check for WAF rules
LIN> for policy in $(gcloud compute security-policies list --format='value(name)'); do
       echo "=== $policy ===" >> ~/reports/network/armor-rules.txt
       gcloud compute security-policies rules list $policy \
         --format='table(priority,action,match.config.srcIpRanges,description)' \
         >> ~/reports/network/armor-rules.txt
     done
```

### 5.6 DNS Security

```bash
LIN> gcloud dns managed-zones list --format=json > ~/reports/network/dns-zones.json

# Check DNSSEC status
LIN> gcloud dns managed-zones list \
       --format='table(name,dnsName,dnssecConfig.state)'
```

### 5.7 nuclei — Web Application Vulnerability Scanning

```bash
# Collect all external endpoints
LIN> gcloud compute forwarding-rules list \
       --filter="loadBalancingScheme=EXTERNAL" \
       --format='value(IPAddress)' > /tmp/targets.txt

LIN> nuclei -l /tmp/targets.txt \
       -t cves/ -t misconfiguration/ -t exposures/ \
       -severity critical,high \
       -o ~/reports/network/nuclei-results.txt
```

**Expected Output:**

```text
[critical] [CVE-2024-XXXX] [http] https://34.120.x.x/api/debug
[high] [exposed-metrics] [http] https://34.120.x.x/metrics
[high] [misconfigured-cors] [http] https://34.120.x.x/api/v2
```

---

## 6. Data Protection & Encryption

### 6.1 Cloud Storage Bucket Security

```bash
# Check all buckets for public access
LIN> for bucket in $(gsutil ls); do
       echo "=== $bucket ===" >> ~/reports/data/bucket-acls.txt
       gsutil iam get $bucket >> ~/reports/data/bucket-acls.txt 2>&1
     done

# Find publicly accessible buckets
LIN> steampipe query "
  SELECT name, location, storage_class,
         iam_policy::text LIKE '%allUsers%' AS public_allUsers,
         iam_policy::text LIKE '%allAuthenticatedUsers%' AS public_allAuth
  FROM gcp_storage_bucket
  WHERE iam_policy::text LIKE '%allUsers%'
     OR iam_policy::text LIKE '%allAuthenticatedUsers%';
"
```

**Expected Output:**

```text
+------------------+----------+---------------+-----------------+------------------+
| name             | location | storage_class | public_allUsers | public_allAuth   |
+------------------+----------+---------------+-----------------+------------------+
| staging-assets   | US       | STANDARD      | true            | false            |
| public-docs      | US       | NEARLINE      | true            | true             |
+------------------+----------+---------------+-----------------+------------------+
```

### 6.2 CMEK / CSEK Encryption Audit

```bash
# Check if buckets use CMEK
LIN> steampipe query "
  SELECT name,
         encryption ->> 'defaultKmsKeyName' AS cmek_key,
         CASE
           WHEN encryption ->> 'defaultKmsKeyName' IS NOT NULL THEN 'CMEK'
           ELSE 'Google-Managed'
         END AS encryption_type
  FROM gcp_storage_bucket;
"

# Check KMS key rotation
LIN> for keyring in $(gcloud kms keyrings list --location=global --format='value(name)'); do
       for key in $(gcloud kms keys list --keyring=$keyring --location=global --format='value(name)'); do
         echo "Key: $key"
         gcloud kms keys describe $key --keyring=$keyring --location=global \
           --format='value(rotationPeriod,nextRotationTime)'
       done
     done
```

### 6.3 BigQuery Dataset Access

```bash
LIN> steampipe query "
  SELECT dataset_id, project_id,
         a ->> 'role' AS role,
         a ->> 'specialGroup' AS special_group,
         a -> 'userByEmail' AS user_email
  FROM gcp_bigquery_dataset,
       jsonb_array_elements(access) AS a
  WHERE a ->> 'specialGroup' IN ('allAuthenticatedUsers','projectWriters')
     OR a ->> 'role' = 'OWNER';
"
```

### 6.4 Secret Manager Audit

```bash
LIN> gcloud secrets list --format='table(name,replication.automatic,createTime)'

# Check who can access each secret
LIN> for secret in $(gcloud secrets list --format='value(name)'); do
       echo "=== $secret ===" >> ~/reports/data/secret-iam.txt
       gcloud secrets get-iam-policy $secret \
         --format=json >> ~/reports/data/secret-iam.txt
     done
```

### 6.5 Cloud SQL — Encryption & Public Access

```bash
LIN> steampipe query "
  SELECT name, database_version, region,
         ip_addresses,
         settings -> 'ipConfiguration' ->> 'requireSsl' AS require_ssl,
         settings -> 'ipConfiguration' -> 'authorizedNetworks' AS authorized_networks,
         settings -> 'dataDiskEncryptionKmsKeyName' AS cmek_key
  FROM gcp_sql_database_instance;
"
```

Flag instances where `authorizedNetworks` includes `0.0.0.0/0` or `requireSsl` is `false`.

---

## 7. Runtime, Container & Serverless Security

### 7.1 GKE Cluster Security Assessment

```bash
# Cluster configuration audit
LIN> gcloud container clusters list --format=json > ~/reports/runtime/gke-clusters.json

# Detailed check
LIN> steampipe query "
  SELECT name, location,
         private_cluster_config IS NOT NULL AS private_cluster,
         master_authorized_networks_config IS NOT NULL AS master_auth_networks,
         network_policy ->> 'enabled' AS network_policy,
         binary_authorization ->> 'enabled' AS binary_auth,
         shielded_nodes ->> 'enabled' AS shielded_nodes,
         workload_identity_config ->> 'workloadPool' AS workload_identity
  FROM gcp_container_cluster;
"
```

**Expected Output:**

```text
+----------+-----------+-----------------+---------------------+----------------+-------------+----------------+-------------------+
| name     | location  | private_cluster | master_auth_networks| network_policy | binary_auth | shielded_nodes | workload_identity |
+----------+-----------+-----------------+---------------------+----------------+-------------+----------------+-------------------+
| prod-gke | us-east1  | true            | true                | true           | true        | true           | myproj.svc.id... |
| dev-gke  | us-west1  | false           | false               | false          | false       | false          | null              |
+----------+-----------+-----------------+---------------------+----------------+-------------+----------------+-------------------+
```

### 7.2 kube-bench — CIS Kubernetes Benchmark

```bash
LIN> gcloud container clusters get-credentials prod-gke --region=us-east1
LIN> kube-bench run --targets=master,node,policies \
       --json --outputfile ~/reports/runtime/kube-bench.json
```

**Expected Output (JSON, truncated):**

```json
{
  "Totals": { "total_pass": 52, "total_fail": 11, "total_warn": 7 },
  "Tests": [
    {
      "section": "1.2 API Server",
      "tests": [
        {
          "test_number": "1.2.1",
          "test_desc": "Ensure --anonymous-auth is not enabled",
          "status": "FAIL",
          "remediation": "Set --anonymous-auth=false"
        }
      ]
    }
  ]
}
```

### 7.3 kube-hunter — Kubernetes Penetration Testing

```bash
LIN> kube-hunter --remote $(gcloud container clusters describe prod-gke \
       --region=us-east1 --format='value(endpoint)') \
       --report json > ~/reports/runtime/kube-hunter.json
```

**Expected Output:**

```json
{
  "vulnerabilities": [
    {
      "severity": "high",
      "vulnerability": "Unauthenticated access to API Server",
      "description": "The API server is accessible without authentication",
      "evidence": "Response status: 200"
    }
  ]
}
```

### 7.4 trivy — Container Image Scanning

```bash
# Scan all images running in GKE
LIN> kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | \
       sort -u > /tmp/gke-images.txt

LIN> while read -r img; do
       echo "Scanning: $img"
       trivy image --severity CRITICAL,HIGH \
         --format json --output ~/reports/runtime/trivy-$(echo $img | tr '/:' '_').json \
         "$img"
     done < /tmp/gke-images.txt
```

**Expected Output (truncated):**

```json
{
  "Results": [
    {
      "Target": "gcr.io/myproject/api-server:v1.4.2",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-3094",
          "Severity": "CRITICAL",
          "PkgName": "xz-utils",
          "InstalledVersion": "5.4.1",
          "FixedVersion": "5.4.2"
        }
      ]
    }
  ]
}
```

### 7.5 Falco — Runtime Threat Detection

```bash
LIN> sudo falco -o json_output=true \
       -o file_output.enabled=true \
       -o file_output.filename=/var/log/falco/alerts.json \
       --daemon

# Generate test alert:
LIN> kubectl exec -it test-pod -- /bin/sh -c "cat /etc/shadow"
```

**Expected alert in /var/log/falco/alerts.json:**

```json
{
  "time": "2025-01-15T10:23:45.123Z",
  "rule": "Read sensitive file untrusted",
  "priority": "Warning",
  "output": "Sensitive file opened for reading (user=root file=/etc/shadow container_id=abc123 image=gcr.io/myproject/api-server:v1.4.2)"
}
```

### 7.6 Cloud Functions & Cloud Run Security

```bash
# Cloud Functions — check for public invocation
LIN> for fn in $(gcloud functions list --format='value(name)'); do
       policy=$(gcloud functions get-iam-policy $fn --format=json 2>/dev/null)
       if echo "$policy" | jq -e '.bindings[] | select(.members[] | contains("allUsers"))' &>/dev/null; then
         echo "PUBLIC: $fn" >> ~/reports/runtime/public-functions.txt
       fi
     done

# Cloud Run — check for unauthenticated access
LIN> for svc in $(gcloud run services list --format='value(metadata.name)' --platform=managed); do
       policy=$(gcloud run services get-iam-policy $svc --platform=managed --format=json 2>/dev/null)
       if echo "$policy" | jq -e '.bindings[] | select(.members[] | contains("allUsers"))' &>/dev/null; then
         echo "PUBLIC: $svc" >> ~/reports/runtime/public-cloudrun.txt
       fi
     done
```

---

## 8. Supply-Chain & CI/CD Security

### 8.1 Artifact Registry / Container Registry Audit

```bash
# List all repositories
LIN> gcloud artifacts repositories list --format=json \
       > ~/reports/cicd/artifact-repos.json

# Check for public repositories
LIN> for repo in $(gcloud artifacts repositories list --format='value(name)'); do
       location=$(gcloud artifacts repositories describe $repo --format='value(name)' 2>/dev/null | cut -d/ -f4)
       policy=$(gcloud artifacts repositories get-iam-policy $repo --location=$location --format=json 2>/dev/null)
       if echo "$policy" | jq -e '.bindings[] | select(.members[] | contains("allUsers"))' &>/dev/null; then
         echo "PUBLIC REPO: $repo" >> ~/reports/cicd/public-repos.txt
       fi
     done
```

### 8.2 Cloud Build — Configuration Audit

```bash
LIN> gcloud builds list --limit=20 --format=json > ~/reports/cicd/recent-builds.json

# Check build triggers for insecure patterns
LIN> gcloud builds triggers list --format=json > ~/reports/cicd/build-triggers.json

# Look for hardcoded secrets in build configs
LIN> gcloud builds triggers list --format=json | \
       jq '.[].build.steps[] | select(.env != null) | .env[]' | \
       grep -iE '(password|secret|api_key|token)' || echo "No obvious secrets in env vars"
```

### 8.3 SBOM Generation & CVE Analysis

```bash
# Generate SBOM for all images in Artifact Registry
LIN> for img in $(gcloud artifacts docker images list \
       us-docker.pkg.dev/$PROJECT_ID/docker-repo --format='value(IMAGE)'); do
       syft "$img" -o spdx-json > ~/reports/cicd/sbom-$(echo $img | tr '/:' '_').spdx.json
       grype sbom:~/reports/cicd/sbom-$(echo $img | tr '/:' '_').spdx.json \
         --output json > ~/reports/cicd/vulns-$(echo $img | tr '/:' '_').json
     done
```

**Expected grype Output (truncated):**

```json
{
  "matches": [
    {
      "vulnerability": { "id": "CVE-2024-3094", "severity": "Critical" },
      "artifact": { "name": "xz-utils", "version": "5.4.1" },
      "fix": { "versions": ["5.4.2"] }
    }
  ]
}
```

### 8.4 Binary Authorization Audit

```bash
LIN> gcloud container binauthz policy export > ~/reports/cicd/binauth-policy.yaml

# Check if default rule allows all
LIN> cat ~/reports/cicd/binauth-policy.yaml | \
       grep -A5 "defaultAdmissionRule"
```

Flag if `evaluationMode: ALWAYS_ALLOW` is set (no attestation required).

### 8.5 checkov — CI/CD Pipeline Scanning

```bash
LIN> checkov -d ~/repo/.github/workflows/ \
       --framework github_actions \
       --output json \
       --output-file-path ~/reports/cicd/checkov-cicd.json

LIN> checkov -f ~/repo/cloudbuild.yaml \
       --framework cloudformation \
       --output json
```

---

## 9. Automated Reconnaissance & Validation Pipelines

### 9.1 Full Automated Recon Script

Create a master orchestration script that runs all tools in sequence:

```bash
#!/usr/bin/env bash
# gcp_recon_pipeline.sh
set -euo pipefail

PROJECT_ID="${1:?Usage: $0 <project-id>}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_BASE=~/reports/gcp-${PROJECT_ID}-${TIMESTAMP}
mkdir -p $REPORT_BASE/{iam,network,data,runtime,cicd,recon,compliance}

echo "[*] Phase 1: Configuration & Compliance"
prowler gcp --credentials-file ~/sa-key.json \
  --output-formats json-ocsf \
  --output-directory $REPORT_BASE/compliance/ 2>&1 | tee $REPORT_BASE/compliance/prowler.log

echo "[*] Phase 2: IAM Enumeration"
gcloud projects get-iam-policy $PROJECT_ID --format=json > $REPORT_BASE/iam/policy.json
gcloud iam service-accounts list --format=json > $REPORT_BASE/iam/service-accounts.json
cloudfox gcp iam-simulator --project $PROJECT_ID -o $REPORT_BASE/iam/

echo "[*] Phase 3: Network Scanning"
gcloud compute firewall-rules list --format=json > $REPORT_BASE/network/firewall-rules.json
gcloud compute addresses list --filter="status=IN_USE AND addressType=EXTERNAL" \
  --format=json > $REPORT_BASE/network/external-ips.json

echo "[*] Phase 4: Data Protection"
steampipe query --output json "
  SELECT name, location,
         iam_policy::text LIKE '%allUsers%' AS public
  FROM gcp_storage_bucket;" > $REPORT_BASE/data/public-buckets.json

echo "[*] Phase 5: Runtime / Container"
trivy image --severity CRITICAL,HIGH --format json \
  $(kubectl get pods -A -o jsonpath='{.items[0].spec.containers[0].image}') \
  > $REPORT_BASE/runtime/trivy-sample.json 2>/dev/null || true

echo "[*] Phase 6: Supply Chain"
gcloud builds triggers list --format=json > $REPORT_BASE/cicd/triggers.json

echo "[*] Phase 7: SHA-256 Manifest"
find $REPORT_BASE -type f -exec sha256sum {} \; > $REPORT_BASE/SHA256SUMS.txt

echo "[+] Complete. Report directory: $REPORT_BASE"
echo "[+] SHA-256 manifest: $REPORT_BASE/SHA256SUMS.txt"
```

### 9.2 Scheduled Pipeline (cron)

```bash
LIN> crontab -e
# Run full recon weekly at 2 AM Sunday
0 2 * * 0 /home/ubuntu/gcp_recon_pipeline.sh myproject-123456 >> /var/log/gcp-recon.log 2>&1
```

### 9.3 Validation Gates

After each pipeline run, validate results:

```bash
#!/usr/bin/env bash
# validate_results.sh
REPORT_DIR="${1:?Usage: $0 <report-dir>}"

# Check SHA-256 integrity
echo "[*] Verifying SHA-256 manifest ..."
cd $REPORT_DIR && sha256sum -c SHA256SUMS.txt
if [ $? -eq 0 ]; then
  echo "[PASS] All file hashes verified"
else
  echo "[FAIL] Hash mismatch detected — possible tampering"
  exit 1
fi

# Check for critical findings
CRITICAL_COUNT=$(find $REPORT_DIR -name '*.json' -exec grep -l '"severity":\s*"CRITICAL"' {} \; | wc -l)
echo "[*] Files with CRITICAL findings: $CRITICAL_COUNT"
if [ $CRITICAL_COUNT -gt 0 ]; then
  echo "[ALERT] Critical findings require immediate review"
fi
```

---

## 10. IAM / Path Analysis at Scale

### 10.1 Cartography — Graph-Based IAM Analysis

Cartography builds a Neo4j graph of your entire GCP environment.

```bash
LIN> cartography --gcp-requested-syncs iam,compute,storage,gke,cloudfunctions \
       --neo4j-uri bolt://localhost:7687 \
       --neo4j-user neo4j \
       --neo4j-password-env-var NEO4J_PASSWORD
```

**Expected Output:**

```text
INFO - Starting GCP IAM sync ...
INFO - Synced 142 IAM bindings
INFO - Starting GCP Compute sync ...
INFO - Synced 47 instances, 23 firewall rules
INFO - Starting GCP Storage sync ...
INFO - Synced 12 buckets, 34 ACLs
INFO - Sync complete. Nodes: 312, Relationships: 1,847
```

### 10.2 Cypher Queries for Privilege Escalation

```cypher
// Find all paths from external-facing VMs to sensitive data
MATCH path = (vm:GCPInstance)-[*1..5]->(bucket:GCPBucket)
WHERE vm.publicIp IS NOT NULL
  AND bucket.name CONTAINS 'prod'
RETURN path LIMIT 20;

// Find service accounts with Owner/Editor that are attached to VMs
MATCH (sa:GCPServiceAccount)-[:BOUND_TO]->(binding:GCPIAMBinding)
WHERE binding.role IN ['roles/owner', 'roles/editor']
MATCH (vm:GCPInstance)-[:USES_SA]->(sa)
RETURN vm.name, sa.email, binding.role;

// Find cross-project trust paths
MATCH (sa1:GCPServiceAccount)-[:CAN_IMPERSONATE]->(sa2:GCPServiceAccount)
WHERE sa1.projectId <> sa2.projectId
RETURN sa1.email, sa2.email, sa1.projectId, sa2.projectId;
```

### 10.3 CloudFox — Automated Escalation Path Discovery

```bash
LIN> cloudfox gcp iam-simulator --project $PROJECT_ID \
       --output json > ~/reports/iam/cloudfox-escalation.json
LIN> cloudfox gcp instances --project $PROJECT_ID \
       --output json > ~/reports/iam/cloudfox-instances.json
```

---

## 11. Neo4j Attack-Path Setup & Visualization

### 11.1 Neo4j Configuration for Security Analysis

Edit `/etc/neo4j/neo4j.conf`:

```properties
# Enable bolt and HTTP
server.bolt.listen_address=0.0.0.0:7687
server.http.listen_address=0.0.0.0:7474

# Memory (tune based on dataset size)
server.memory.heap.initial_size=1g
server.memory.heap.max_size=4g
server.memory.pagecache.size=2g

# APOC plugin (for advanced path analysis)
dbms.security.procedures.unrestricted=apoc.*
dbms.security.procedures.allowlist=apoc.*
```

Install APOC:

```bash
LIN> wget https://github.com/neo4j/apoc/releases/latest/download/apoc-core.jar \
       -O /var/lib/neo4j/plugins/apoc-core.jar
LIN> sudo systemctl restart neo4j
```

### 11.2 Loading Cartography Data

After running Cartography (§10.1), data is already in Neo4j. Verify:

```cypher
// Count nodes by type
MATCH (n) RETURN labels(n)[0] AS type, count(n) AS count ORDER BY count DESC;

// Expected:
// +----------------------------+-------+
// | type                       | count |
// +----------------------------+-------+
// | GCPIAMBinding              | 142   |
// | GCPInstance                 | 47    |
// | GCPServiceAccount          | 23    |
// | GCPBucket                  | 12    |
// | GCPFirewallRule             | 23    |
// +----------------------------+-------+
```

### 11.3 Attack-Path Visualization Queries

```cypher
// Full kill chain: Internet → VM → SA → Sensitive Data
MATCH path = (internet:Internet)-[:EXPOSES]->(fw:GCPFirewallRule)-[:ALLOWS]->(vm:GCPInstance)
              -[:USES_SA]->(sa:GCPServiceAccount)-[:HAS_PERMISSION]->(resource)
WHERE fw.sourceRanges CONTAINS '0.0.0.0/0'
  AND resource:GCPBucket OR resource:GCPBigQueryDataset
RETURN path;

// Lateral movement via SA impersonation
MATCH path = (attacker:GCPServiceAccount)-[:CAN_IMPERSONATE*1..3]->(target:GCPServiceAccount)
             -[:HAS_PERMISSION]->(sensitive)
WHERE sensitive:GCPBucket AND sensitive.name CONTAINS 'prod'
RETURN path;
```

### 11.4 Export Graph for Reporting

```cypher
// Export paths as JSON for the aggregator
CALL apoc.export.json.query(
  "MATCH path = (vm:GCPInstance)-[*1..4]->(b:GCPBucket) WHERE vm.publicIp IS NOT NULL RETURN path",
  "/tmp/gcp-attack-paths.json",
  {}
);
```

---

## 12. Multi-Cloud Attack-Surface Mapping

### 12.1 CloudFox — GCP Attack Surface

```bash
LIN> cloudfox gcp instances --project $PROJECT_ID -o ~/reports/multicloud/
LIN> cloudfox gcp iam-simulator --project $PROJECT_ID -o ~/reports/multicloud/
```

### 12.2 Steampipe — Cross-Cloud SQL Queries

Install both GCP and AWS plugins (for environments with cross-cloud trust):

```bash
LIN> steampipe plugin install gcp aws azure
```

```sql
-- Find all publicly accessible resources across clouds
SELECT 'GCP' AS cloud, name AS resource, 'Bucket' AS type
FROM gcp_storage_bucket
WHERE iam_policy::text LIKE '%allUsers%'

UNION ALL

SELECT 'GCP' AS cloud, name AS resource, 'VM' AS type
FROM gcp_compute_instance i,
     jsonb_array_elements(i.network_interfaces) AS n
WHERE n -> 'accessConfigs' IS NOT NULL;
```

### 12.3 Shared Credential Detection

```bash
# Check for cross-cloud credentials stored in GCP
LIN> gcloud secrets list --format='value(name)' | while read secret; do
       latest=$(gcloud secrets versions access latest --secret=$secret 2>/dev/null || true)
       if echo "$latest" | grep -qiE '(AKIA|ASIA|aws_access_key|azure.*tenant)'; then
         echo "CROSS-CLOUD CRED: secret=$secret" >> ~/reports/multicloud/shared-creds.txt
       fi
     done
```

---

## 13. Hybrid Cloud Security Tools (Steampipe, CloudQuery, Cartography)

### 13.1 Steampipe — Unified Compliance Dashboard

```bash
LIN> steampipe dashboard
# Access at http://localhost:9194

# Or run CIS benchmark mod:
LIN> cd ~ && git clone https://github.com/turbot/steampipe-mod-gcp-compliance.git
LIN> cd steampipe-mod-gcp-compliance
LIN> steampipe check all --output json > ~/reports/hybrid/steampipe-cis.json
```

**Expected Output (truncated):**

```json
{
  "summary": {
    "status": {
      "ok": 112,
      "alarm": 23,
      "error": 2,
      "skip": 5
    }
  },
  "groups": [
    {
      "title": "CIS GCP 2.0 - 1.1 Ensure IAM policies are not set at folder level",
      "status": "alarm",
      "description": "Found 3 folders with direct IAM bindings"
    }
  ]
}
```

### 13.2 CloudQuery — Asset Inventory to SQL/Parquet

Create `cloudquery.yml`:

```yaml
kind: source
spec:
  name: gcp
  registry: cloudquery
  path: cloudquery/gcp
  version: "v11.0.0"
  tables: ["*"]
  destinations: ["postgresql"]
  spec:
    project_ids: ["myproject-123456"]

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
LIN> cloudquery sync cloudquery.yml
```

**Expected Output:**

```text
Loading source gcp@v11.0.0 ...
Starting sync for project myproject-123456
  gcp_compute_instances: 47 rows
  gcp_storage_buckets: 12 rows
  gcp_iam_roles: 234 rows
  ...
Sync complete: 2,341 total rows across 89 tables
```

### 13.3 Cartography — Graph-Based Hybrid View

Cartography syncs to Neo4j and can ingest from GCP, AWS, and Azure simultaneously, creating cross-cloud relationships:

```bash
LIN> cartography --gcp-requested-syncs all \
       --aws-requested-syncs all \
       --neo4j-uri bolt://localhost:7687 \
       --neo4j-user neo4j \
       --neo4j-password-env-var NEO4J_PASSWORD
```

---

## 14. Aggregator Integration

### 14.1 Overview

The shared `aggregator.py` script (delivered separately as part of this methodology) consumes outputs from all three cloud documents and produces:

1. **Unified JSON** — all findings normalised into a single schema.
2. **Interactive HTML Dashboard** — sortable, filterable, with severity charts.
3. **Executive Summary** — markdown report with risk scores.
4. **Unified Neo4j Cypher** — loads cross-cloud findings into a single graph.
5. **Audit Manifest** — SHA-256 hashes of every input and output file.

### 14.2 GCP-Specific Aggregator Input

After running the pipeline from §9, feed all GCP outputs to the aggregator:

```bash
LIN> python3 aggregator.py \
       --cloud gcp \
       --input-dir ~/reports/gcp-myproject-20250115_020000/ \
       --output-dir ~/reports/aggregated/ \
       --neo4j-uri bolt://localhost:7687 \
       --neo4j-user neo4j \
       --neo4j-password $NEO4J_PASSWORD \
       --compliance-frameworks "soc2,iso27001,hipaa,pci-dss"
```

**Expected Output:**

```text
[*] Scanning ~/reports/gcp-myproject-20250115_020000/ for findings ...
[+] Parsed 14 files, extracted 237 findings
[*] Normalising to unified schema ...
[*] Generating unified JSON ...        → aggregated/unified-findings.json
[*] Generating HTML dashboard ...      → aggregated/dashboard.html
[*] Generating executive summary ...   → aggregated/executive-summary.md
[*] Generating Neo4j Cypher ...        → aggregated/neo4j-import.cypher
[*] Computing SHA-256 manifest ...     → aggregated/AUDIT-MANIFEST.sha256
[+] Aggregation complete. 237 findings across 1 cloud(s).
```

### 14.3 Cross-Cloud Aggregation

When you have outputs from all three docs:

```bash
LIN> python3 aggregator.py \
       --cloud all \
       --input-dir ~/reports/gcp-*/ ~/reports/aws-*/ ~/reports/azure-*/ \
       --output-dir ~/reports/unified/ \
       --neo4j-uri bolt://localhost:7687 \
       --neo4j-user neo4j \
       --neo4j-password $NEO4J_PASSWORD
```

---

## 15. Gap Analysis & Filled Gaps

### 15.1 Identified Gaps (Original Scope)

| # | Gap | Resolution | Section |
|---|-----|-----------|---------|
| 1 | No DNS security checks | Added Cloud DNS + DNSSEC audit | §5.6 |
| 2 | Missing Cloud SQL assessment | Added SQL encryption & public access checks | §6.5 |
| 3 | No Binary Authorization audit | Added binauth policy export & validation | §8.4 |
| 4 | No runtime threat detection | Added Falco deployment & alerting | §7.5 |
| 5 | No SBOM/CVE pipeline | Added syft + grype for supply-chain analysis | §8.3 |
| 6 | No Workload Identity Federation check | Added WIF pool/provider enumeration | §4.3 |
| 7 | No Domain-Wide Delegation audit | Added DWD detection for service accounts | §4.4 |
| 8 | No Cloud Armor / WAF review | Added security policy & rule enumeration | §5.5 |
| 9 | No Secret Manager audit | Added secret IAM policy review | §6.4 |
| 10 | No custom role audit | Added custom role permission enumeration | §4.5 |
| 11 | No cross-project trust analysis | Added Cartography cross-project Cypher queries | §10.2 |
| 12 | No scheduled pipeline | Added cron-based weekly scanning | §9.2 |
| 13 | No integrity verification | Added SHA-256 manifest generation & validation | §9.3 |
| 14 | No VPC Flow Logs analysis | Added below | §15.2 |
| 15 | No Org Policy constraints check | Added below | §15.3 |
| 16 | No Pub/Sub security audit | Added below | §15.4 |
| 17 | No Cloud Logging / audit log verification | Added below | §15.5 |

### 15.2 Gap Fill: VPC Flow Logs

```bash
LIN> steampipe query "
  SELECT s.name, s.region,
         s.log_config IS NOT NULL AS flow_logs_enabled,
         s.log_config ->> 'aggregationInterval' AS interval,
         s.log_config ->> 'flowSampling' AS sampling_rate
  FROM gcp_compute_subnetwork s;
"
```

All production subnets should have `flow_logs_enabled = true` with `sampling_rate >= 0.5`.

### 15.3 Gap Fill: Organization Policy Constraints

```bash
LIN> gcloud org-policies list --project=$PROJECT_ID --format=json \
       > ~/reports/compliance/org-policies.json

# Key constraints to verify:
# constraints/compute.requireShieldedVm
# constraints/iam.disableServiceAccountKeyCreation
# constraints/storage.uniformBucketLevelAccess
# constraints/compute.vmExternalIpAccess
```

### 15.4 Gap Fill: Pub/Sub Security

```bash
LIN> gcloud pubsub topics list --format=json > ~/reports/data/pubsub-topics.json

# Check for public topics
LIN> for topic in $(gcloud pubsub topics list --format='value(name)'); do
       policy=$(gcloud pubsub topics get-iam-policy $topic --format=json 2>/dev/null)
       if echo "$policy" | jq -e '.bindings[] | select(.members[] | contains("allUsers"))' &>/dev/null; then
         echo "PUBLIC TOPIC: $topic"
       fi
     done
```

### 15.5 Gap Fill: Audit Logging Verification

```bash
LIN> gcloud projects get-iam-policy $PROJECT_ID --format=json | \
       jq '.auditConfigs'

# Ensure DATA_READ and DATA_WRITE are enabled for all services
# Expected:
# [
#   {
#     "service": "allServices",
#     "auditLogConfigs": [
#       { "logType": "ADMIN_READ" },
#       { "logType": "DATA_READ" },
#       { "logType": "DATA_WRITE" }
#     ]
#   }
# ]
```

---

## 16. Report Generation & Compliance Artifacts

### 16.1 SHA-256 Signed Report Bundle

```bash
#!/usr/bin/env bash
# generate_report_bundle.sh
REPORT_DIR="${1:?Usage: $0 <report-dir>}"

echo "[*] Generating compliance bundle ..."

# Create executive summary
cat > $REPORT_DIR/EXECUTIVE_SUMMARY.md << 'EOF'
# GCP Security Assessment — Executive Summary

**Date:** $(date -I)
**Project:** $PROJECT_ID
**Methodology:** Hybrid Multi-Cloud Security Testing v2.0

## Risk Overview

| Severity | Count |
|----------|-------|
| CRITICAL | $(grep -rl '"severity".*CRITICAL' $REPORT_DIR | wc -l) |
| HIGH     | $(grep -rl '"severity".*HIGH' $REPORT_DIR | wc -l) |
| MEDIUM   | $(grep -rl '"severity".*MEDIUM' $REPORT_DIR | wc -l) |
| LOW      | $(grep -rl '"severity".*LOW' $REPORT_DIR | wc -l) |
EOF

# SHA-256 manifest for all files
find $REPORT_DIR -type f ! -name 'AUDIT-MANIFEST.sha256' \
  -exec sha256sum {} \; > $REPORT_DIR/AUDIT-MANIFEST.sha256

echo "[+] Bundle complete. Manifest: $REPORT_DIR/AUDIT-MANIFEST.sha256"
```

### 16.2 Compliance Mapping

| Framework | Relevant Sections |
|-----------|-------------------|
| **SOC 2 Type II** | CC6.1 (IAM §4), CC6.6 (Network §5), CC6.7 (Encryption §6), CC7.1 (Runtime §7) |
| **ISO 27001** | A.9 (Access §4), A.13 (Network §5), A.10 (Crypto §6), A.12 (Operations §7) |
| **HIPAA** | §164.312(a) (Access §4), §164.312(e) (Encryption §6), §164.312(b) (Audit §15.5) |
| **PCI-DSS** | Req 1 (Network §5), Req 3 (Data §6), Req 7 (Access §4), Req 10 (Logging §15.5) |

---

## 17. Appendices

### Appendix A: Tool License Summary

| Tool | License | Telemetry |
|------|---------|-----------|
| ScoutSuite | GPL-2.0 | None |
| Prowler | Apache-2.0 | None |
| gcp-scanner | Apache-2.0 | None |
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
| Neo4j Community | GPL-3.0 | Opt-out |
| Nmap | NPSL (GPL-like) | None |

### Appendix B: GCP API Enablement Checklist

```bash
LIN> gcloud services enable \
       compute.googleapis.com \
       container.googleapis.com \
       cloudasset.googleapis.com \
       iam.googleapis.com \
       cloudkms.googleapis.com \
       sqladmin.googleapis.com \
       cloudfunctions.googleapis.com \
       run.googleapis.com \
       artifactregistry.googleapis.com \
       cloudbuild.googleapis.com \
       secretmanager.googleapis.com \
       dns.googleapis.com \
       pubsub.googleapis.com \
       logging.googleapis.com \
       monitoring.googleapis.com \
       bigquery.googleapis.com
```

### Appendix C: Report File Naming Convention

```text
{cloud}-{project}-{timestamp}/
├── iam/
│   ├── project-policy.json
│   ├── service-accounts.json
│   ├── sa-keys.txt
│   └── cloudfox-escalation.json
├── network/
│   ├── firewall-rules.json
│   ├── external-ips.json
│   ├── nmap-vpc-scan.xml
│   └── nuclei-results.txt
├── data/
│   ├── bucket-acls.txt
│   ├── public-buckets.json
│   └── secret-iam.txt
├── runtime/
│   ├── gke-clusters.json
│   ├── kube-bench.json
│   ├── trivy-*.json
│   └── public-functions.txt
├── cicd/
│   ├── artifact-repos.json
│   ├── build-triggers.json
│   └── sbom-*.spdx.json
├── compliance/
│   ├── prowler-gcp-*.json
│   ├── steampipe-cis.json
│   └── org-policies.json
├── multicloud/
│   └── shared-creds.txt
├── EXECUTIVE_SUMMARY.md
├── SHA256SUMS.txt
└── AUDIT-MANIFEST.sha256
```

---

**END OF DOCUMENT 1 — GCP Security Testing Methodology**
