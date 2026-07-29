# Doc 3 — Azure Security Testing Methodology

## From Windows & Kali Linux Boxes in Microsoft Azure

**Version:** 2.0 — Production-Ready  
**Classification:** CONFIDENTIAL — Internal Use Only  
**Compliance Targets:** SOC 2 Type II · ISO 27001 · HIPAA · PCI-DSS  
**All tools:** 100 % open-source (Apache / MIT / GPL), zero telemetry

---

## Table of Contents

1. [Document Overview](#1-document-overview)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Configuration & Misconfiguration Assessment](#3-configuration--misconfiguration-assessment)
4. [Identity & Access (Entra ID, RBAC, Managed Identities)](#4-identity--access-entra-id-rbac-managed-identities)
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

This document provides a self-contained, production-ready methodology for security testing a Microsoft Azure environment. All checks are executed from:

| Platform | OS | Notes |
|---|---|---|
| **Azure Windows Box** | Windows Server 2022 | Azure VM, Chocolatey + PowerShell modules |
| **Azure Kali Linux Box** | Kali Linux 2024.x | Azure VM, full Kali toolset + Azure CLI |

### 1.2 Scope Matrix

| Domain | Section |
|---|---|
| Configuration / Misconfigurations | §3 |
| Identity & Access (Entra ID / AAD, RBAC, Managed Identities, Federation) | §4 |
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

- `WIN>` = Command executed on the Windows box (PowerShell).
- `KALI>` = Command executed on the Kali Linux box.
- `BOTH>` = Identical on either platform.
- SHA-256 hashes generated for every report artifact.

---

## 2. Prerequisites & Environment Setup

### 2.1 Azure Subscription Preparation

```text
Required RBAC Roles for testing service principal (minimum):
  Reader                          (subscription-wide)
  Security Reader                 (Microsoft Defender for Cloud)
  Key Vault Reader                (Key Vault metadata)
  Storage Blob Data Reader        (storage inspection)
  Network Contributor (read-only subset via custom role preferred)
  Managed Identity Operator       (managed identity enumeration)
  Directory Readers               (Entra ID / AAD read)
  Global Reader                   (Entra ID / AAD comprehensive read — requires admin consent)
```

Create a service principal:

```bash
KALI> az login
KALI> az ad sp create-for-rbac --name "sec-tester" \
        --role "Reader" \
        --scopes "/subscriptions/$SUBSCRIPTION_ID" \
        --output json > ~/azure-sp.json

# Expected output:
# {
#   "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
#   "password": "****",
#   "tenant": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# }

# Assign additional roles
KALI> az role assignment create \
        --assignee $(jq -r '.appId' ~/azure-sp.json) \
        --role "Security Reader" \
        --scope "/subscriptions/$SUBSCRIPTION_ID"
```

Login with the service principal:

```bash
KALI> az login --service-principal \
        --username $(jq -r '.appId' ~/azure-sp.json) \
        --password $(jq -r '.password' ~/azure-sp.json) \
        --tenant $(jq -r '.tenant' ~/azure-sp.json)

KALI> az account show
# Expected:
# {
#   "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
#   "name": "Production Subscription",
#   "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
#   "user": { "name": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "type": "servicePrincipal" }
# }
```

### 2.2 Kali Linux Box Setup (Azure VM)

#### 2.2.1 System Updates & Core Packages

```bash
KALI> sudo apt update && sudo apt full-upgrade -y
KALI> sudo apt install -y \
        git curl wget unzip jq python3 python3-pip python3-venv \
        nmap nikto dnsutils whois net-tools build-essential \
        default-jre docker.io docker-compose golang \
        dirb gobuster seclists
KALI> sudo usermod -aG docker $USER && newgrp docker
```

#### 2.2.2 Azure CLI

```bash
KALI> curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
KALI> az --version
# Expected: azure-cli 2.x.x
```

#### 2.2.3 Python Virtual Environment

```bash
KALI> python3 -m venv ~/sectest-venv
KALI> source ~/sectest-venv/bin/activate
KALI> pip install --upgrade pip setuptools wheel
```

#### 2.2.4 Tool Installation — Kali Linux

**ScoutSuite (Azure CIS Scanner)**

```bash
KALI> cd ~ && git clone https://github.com/nccgroup/ScoutSuite.git
KALI> cd ScoutSuite && pip install -r requirements.txt
KALI> python scout.py azure --help
# Expected: usage: scout.py azure [-h] [--cli | --service-principal ...] ...
```

**Prowler (Azure provider)**

```bash
KALI> pip install prowler
KALI> prowler azure --help
# Expected: usage: prowler azure [-h] ...
```

**AzureHound (BloodHound CE data collector)**

```bash
KALI> wget https://github.com/BloodHoundAD/AzureHound/releases/latest/download/azurehound-linux-amd64.zip
KALI> unzip azurehound-linux-amd64.zip -d /usr/local/bin/
KALI> azurehound --help
# Expected: AzureHound v2.x.x ...
```

**BloodHound Community Edition**

```bash
KALI> curl -L https://ghst.ly/getbhce | docker compose -f - up -d
# Access at http://localhost:8080
# Default creds displayed in docker output on first run
```

**Cartography**

```bash
KALI> pip install cartography
KALI> cartography --help
```

**Steampipe + Azure Plugin**

```bash
KALI> sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
KALI> steampipe plugin install azure azuread
KALI> steampipe query "select 1 as test"
```

**CloudQuery**

```bash
KALI> curl -L https://github.com/cloudquery/cloudquery/releases/latest/download/cloudquery_linux_amd64 \
        -o /usr/local/bin/cloudquery && chmod +x /usr/local/bin/cloudquery
```

**CloudFox (Azure support)**

```bash
KALI> wget https://github.com/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip
KALI> unzip cloudfox-linux-amd64.zip -d /usr/local/bin/
KALI> cloudfox azure --help
# Expected: Available Commands: instances, rbac, storage, ...
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
```

**kube-hunter**

```bash
KALI> pip install kube-hunter
```

**Falco**

```bash
KALI> curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
KALI> echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
        https://download.falco.org/packages/deb stable main" | \
        sudo tee /etc/apt/sources.list.d/falcosecurity.list
KALI> sudo apt update && sudo apt install -y falco
```

**syft + grype**

```bash
KALI> curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
KALI> curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
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

**ROADtools (Azure AD/Entra ID recon)**

```bash
KALI> pip install roadrecon roadlib
KALI> roadrecon --help
# Expected: usage: roadrecon [-h] ...
```

**MicroBurst (Azure security assessment)**

```bash
KALI> pip install MicroBurst 2>/dev/null || \
        git clone https://github.com/NetSPI/MicroBurst.git ~/MicroBurst
```

**PowerZure (Azure exploitation toolkit — for authorized testing)**

```bash
KALI> git clone https://github.com/hausec/PowerZure.git ~/PowerZure
```

### 2.3 Windows Box Setup (Windows Server 2022 on Azure)

#### 2.3.1 Chocolatey & Core Packages

```powershell
WIN> Set-ExecutionPolicy Bypass -Scope Process -Force
WIN> [System.Net.ServicePointManager]::SecurityProtocol = `
       [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
WIN> iex ((New-Object System.Net.WebClient).DownloadString(
       'https://community.chocolatey.org/install.ps1'))
WIN> choco install -y git python3 nmap jq curl wget `
       openjdk17 golang docker-desktop nodejs-lts 7zip azure-cli
```

#### 2.3.2 Azure PowerShell Modules

```powershell
WIN> Install-Module -Name Az -Force -AllowClobber
WIN> Install-Module -Name AzureAD -Force   # Legacy but still useful
WIN> Install-Module -Name Microsoft.Graph -Force
WIN> Install-Module -Name Az.Security -Force
WIN> Install-Module -Name Az.ResourceGraph -Force

WIN> Connect-AzAccount -ServicePrincipal `
       -ApplicationId $env:AZURE_CLIENT_ID `
       -TenantId $env:AZURE_TENANT_ID `
       -CertificateThumbprint $env:AZURE_CERT_THUMBPRINT
# OR
WIN> Connect-AzAccount  # Interactive login
WIN> Get-AzContext
```

#### 2.3.3 Python Tools (Windows)

```powershell
WIN> python -m venv C:\sectest-venv
WIN> C:\sectest-venv\Scripts\Activate.ps1
WIN> pip install scoutsuite prowler checkov kube-hunter roadrecon roadlib
```

#### 2.3.4 AzureHound (Windows)

```powershell
WIN> Invoke-WebRequest -Uri "https://github.com/BloodHoundAD/AzureHound/releases/latest/download/azurehound-windows-amd64.zip" `
       -OutFile azurehound.zip
WIN> Expand-Archive azurehound.zip -DestinationPath C:\tools\azurehound
WIN> C:\tools\azurehound\azurehound.exe --help
```

#### 2.3.5 Steampipe (Windows)

```powershell
WIN> choco install -y steampipe
WIN> steampipe plugin install azure azuread
```

#### 2.3.6 Neo4j Desktop (Windows)

Download from https://neo4j.com/download-center/ and install.

### 2.4 Environment Validation

```bash
#!/usr/bin/env bash
# validate_azure_tools.sh
TOOLS=(
  "az-cli:az --version"
  "scout:python ~/ScoutSuite/scout.py --help"
  "prowler:prowler --help"
  "azurehound:azurehound --help"
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
  "roadrecon:roadrecon --help"
)
for entry in "${TOOLS[@]}"; do
  IFS=":" read -r name cmd <<< "$entry"
  if $cmd &>/dev/null; then echo "[OK]   $name"
  else echo "[FAIL] $name"; fi
done
```

---

## 3. Configuration & Misconfiguration Assessment

### 3.1 ScoutSuite — Full Azure Scan

```bash
KALI> cd ~/ScoutSuite
KALI> python scout.py azure --cli \
        --report-dir ~/reports/scoutsuite \
        --no-browser
```

```powershell
WIN> cd C:\ScoutSuite
WIN> python scout.py azure --cli `
       --report-dir C:\reports\scoutsuite `
       --no-browser
```

**Expected Output (truncated):**

```text
Fetching data for subscription Production ...
  aad              [##########] 100%  234 resources
  storageaccounts  [##########] 100%   18 resources
  virtualmachines  [##########] 100%   56 resources
  sqldatabase      [##########] 100%    9 resources
  keyvault         [##########] 100%   12 resources
  ...
Processing data ...
  Rules evaluated: 189
  Dangers:         18
  Warnings:        42
  Passing:         129

Report saved to ~/reports/scoutsuite/azure-*.html
```

### 3.2 Prowler — Azure CIS & Custom Checks

```bash
KALI> prowler azure \
        --output-formats json-ocsf,html,csv \
        --output-directory ~/reports/prowler \
        --severity critical high \
        --compliance cis_azure_2.0
```

**Expected Output (truncated):**

```text
Prowler v4.x.x — Azure Provider
Subscription: Production (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

[CRITICAL] azure_storage_account_public_access: Storage account "devuploads" allows public blob access → FAIL
[HIGH]     azure_nsg_ssh_open: NSG "debug-nsg" allows SSH from 0.0.0.0/0 → FAIL
[HIGH]     azure_keyvault_recoverable: Key Vault "prod-secrets" does not have soft-delete enabled → FAIL
[HIGH]     azure_sql_tde_disabled: SQL Server "analytics-db" TDE not enabled → FAIL
...
Results: 97 PASS | 18 FAIL (6 CRITICAL, 12 HIGH) | 4 MANUAL
```

### 3.3 Azure Resource Graph — Compliance Queries

```bash
# Find all non-compliant resources via Resource Graph
KALI> az graph query -q "
  securityresources
  | where type == 'microsoft.security/assessments'
  | where properties.status.code == 'Unhealthy'
  | project resourceGroup, properties.displayName, properties.status.code,
            properties.metadata.severity
  | order by properties_metadata_severity desc
  | limit 50
" --output json > ~/reports/compliance/unhealthy-assessments.json
```

**Expected Output (truncated):**

```json
[
  {
    "resourceGroup": "prod-rg",
    "properties_displayName": "Storage accounts should restrict network access",
    "properties_status_code": "Unhealthy",
    "properties_metadata_severity": "High"
  }
]
```

### 3.4 Steampipe — SQL-Based Azure Compliance

```bash
KALI> steampipe query "
  SELECT
    name, resource_group, location,
    allow_blob_public_access,
    enable_https_traffic_only,
    min_tls_version,
    network_rule_default_action
  FROM azure_storage_account
  WHERE allow_blob_public_access = true
     OR min_tls_version != 'TLS1_2';
"
```

**Expected Output:**

```text
+----------------+----------------+----------+-------------------------+---------------------------+-----------------+-------------------------------+
| name           | resource_group | location | allow_blob_public_access| enable_https_traffic_only | min_tls_version | network_rule_default_action   |
+----------------+----------------+----------+-------------------------+---------------------------+-----------------+-------------------------------+
| devuploads     | dev-rg         | eastus   | true                    | true                      | TLS1_0          | Allow                         |
| legacystorage  | legacy-rg      | westus   | true                    | false                     | TLS1_0          | Allow                         |
+----------------+----------------+----------+-------------------------+---------------------------+-----------------+-------------------------------+
```

### 3.5 checkov — ARM / Bicep / Terraform Scanning

```bash
KALI> checkov -d ~/infra/terraform/ \
        --framework terraform \
        --output json \
        --output-file-path ~/reports/checkov/ \
        --check CKV_AZURE_1,CKV_AZURE_2,CKV_AZURE_3,CKV_AZURE_33,CKV_AZURE_35

KALI> checkov -d ~/infra/bicep/ \
        --framework bicep \
        --output json \
        --output-file-path ~/reports/checkov/
```

---

## 4. Identity & Access (Entra ID, RBAC, Managed Identities)

### 4.1 Entra ID (Azure AD) Enumeration — ROADtools

```bash
# Gather full Entra ID directory data
KALI> roadrecon auth --access-token $(az account get-access-token \
        --resource https://graph.microsoft.com --query accessToken -o tsv)
KALI> roadrecon gather
KALI> roadrecon gui
# Opens web interface at http://localhost:5000 with full directory visualization
```

**Expected roadrecon gather output:**

```text
[*] Gathering users ...                    234 found
[*] Gathering groups ...                    67 found
[*] Gathering applications ...              89 found
[*] Gathering service principals ...       123 found
[*] Gathering app role assignments ...     456 found
[*] Gathering directory roles ...           12 found
[*] Gathering OAuth2 permissions ...       234 found
[*] Gathering devices ...                  189 found
[*] Database written to roadrecon.db
```

### 4.2 AzureHound — BloodHound Data Collection

```bash
KALI> azurehound start \
        --tenant $(jq -r '.tenant' ~/azure-sp.json) \
        -u $(jq -r '.appId' ~/azure-sp.json) \
        -p $(jq -r '.password' ~/azure-sp.json) \
        -o ~/reports/iam/azurehound.json
```

**Expected Output:**

```text
[*] Authenticating to Azure ...
[*] Collecting Azure AD objects ...
  Users:               234
  Groups:               67
  Applications:         89
  Service Principals:  123
  Devices:             189
[*] Collecting Azure RM objects ...
  Subscriptions:         3
  Resource Groups:      34
  Virtual Machines:     56
  Key Vaults:           12
  Storage Accounts:     18
[*] Collection complete: ~/reports/iam/azurehound.json
```

Import into BloodHound CE:

```bash
KALI> # Upload via BloodHound CE web UI at http://localhost:8080
#     → Upload Data → Select azurehound.json
```

### 4.3 RBAC Role Assignment Audit

```bash
KALI> az role assignment list --all --output json > ~/reports/iam/rbac-assignments.json

# Find overprivileged assignments (Owner/Contributor at subscription level)
KALI> az role assignment list --all --output json | \
        jq '[.[] | select(
          (.roleDefinitionName == "Owner" or .roleDefinitionName == "Contributor") and
          (.scope | test("^/subscriptions/[^/]+$"))
        ) | {principal: .principalName, role: .roleDefinitionName, scope: .scope}]'
```

**Expected Output:**

```json
[
  {
    "principal": "admin@company.com",
    "role": "Owner",
    "scope": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  },
  {
    "principal": "deploy-sp",
    "role": "Contributor",
    "scope": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
]
```

### 4.4 Managed Identity Audit

```bash
# List all user-assigned managed identities
KALI> az identity list --output json > ~/reports/iam/managed-identities.json

# Find VMs with system-assigned managed identities
KALI> az vm list --query '[?identity.type != null].{
  Name:name, RG:resourceGroup,
  IdentityType:identity.type,
  UserAssigned:identity.userAssignedIdentities
}' --output json > ~/reports/iam/vm-identities.json

# Check role assignments for each managed identity
KALI> for mi in $(az identity list --query '[].principalId' --output tsv); do
  echo "=== $mi ===" >> ~/reports/iam/mi-roles.txt
  az role assignment list --assignee $mi --all --output table >> ~/reports/iam/mi-roles.txt
done
```

### 4.5 Service Principal & App Registration Audit

```bash
# List all app registrations with their secrets/certificates
KALI> az ad app list --all --output json | \
        jq '[.[] | {
          appId: .appId,
          displayName: .displayName,
          passwordCredentials: [.passwordCredentials[] | {
            keyId: .keyId,
            endDateTime: .endDateTime,
            hint: .hint
          }],
          keyCredentials: (.keyCredentials | length),
          requiredResourceAccess: [.requiredResourceAccess[] |
            {resourceAppId: .resourceAppId, permissions: (.resourceAccess | length)}]
        }]' > ~/reports/iam/app-registrations.json

# Find apps with expired or soon-expiring secrets
KALI> cat ~/reports/iam/app-registrations.json | \
        jq '[.[] | select(.passwordCredentials[] | .endDateTime < (now | todate))]'
```

### 4.6 Conditional Access Policy Review

```bash
# Requires Global Reader or higher
KALI> az rest --method get \
        --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
        --output json > ~/reports/iam/conditional-access.json

# Check for policies that exclude important groups
KALI> cat ~/reports/iam/conditional-access.json | \
        jq '[.value[] | {
          name: .displayName,
          state: .state,
          excludeUsers: .conditions.users.excludeUsers,
          excludeGroups: .conditions.users.excludeGroups,
          grantControls: .grantControls.builtInControls
        }]'
```

### 4.7 Privileged Identity Management (PIM) Status

```powershell
WIN> # Check PIM eligible role assignments
WIN> $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
WIN> $headers = @{Authorization = "Bearer $token"}
WIN> $pimAssignments = Invoke-RestMethod `
       -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" `
       -Headers $headers
WIN> $pimAssignments.value | Select-Object principalId, roleDefinitionId, status | Format-Table
```

### 4.8 Guest User Audit

```bash
KALI> az ad user list --filter "userType eq 'Guest'" --output json | \
        jq '[.[] | {
          upn: .userPrincipalName,
          displayName: .displayName,
          createdDateTime: .createdDateTime,
          accountEnabled: .accountEnabled,
          mail: .mail
        }]' > ~/reports/iam/guest-users.json

# Count and flag
KALI> echo "Guest users: $(cat ~/reports/iam/guest-users.json | jq length)"
```

---

## 5. Network & Perimeter Security

### 5.1 NSG Analysis

```bash
# Find NSGs with 0.0.0.0/0 inbound rules
KALI> az network nsg list --output json > ~/reports/network/nsgs.json

KALI> az network nsg list --output json | \
        jq '[.[] | {
          name: .name,
          rg: .resourceGroup,
          open_rules: [.securityRules[] |
            select(.direction == "Inbound" and
                   .access == "Allow" and
                   (.sourceAddressPrefix == "*" or .sourceAddressPrefix == "0.0.0.0/0")) |
            {name: .name, port: .destinationPortRange, priority: .priority}]
        } | select(.open_rules | length > 0)]'
```

**Expected Output:**

```json
[
  {
    "name": "debug-nsg",
    "rg": "dev-rg",
    "open_rules": [
      { "name": "AllowSSH", "port": "22", "priority": 100 },
      { "name": "AllowAll", "port": "*", "priority": 200 }
    ]
  }
]
```

### 5.2 VNet & Subnet Analysis

```bash
KALI> az network vnet list --output json > ~/reports/network/vnets.json

# Check for subnets without NSGs
KALI> az network vnet list --output json | \
        jq '[.[] | .subnets[] | select(.networkSecurityGroup == null) |
             {vnet: .name, subnet: .name, addressPrefix: .addressPrefix}]'
```

### 5.3 Public IP Enumeration

```bash
KALI> az network public-ip list --output json | \
        jq '[.[] | {
          name: .name,
          rg: .resourceGroup,
          address: .ipAddress,
          allocation: .publicIPAllocationMethod,
          associatedTo: .ipConfiguration.id
        }]' > ~/reports/network/public-ips.json
```

### 5.4 Azure Firewall & WAF

```bash
# Azure Firewall rules
KALI> az network firewall list --output json > ~/reports/network/firewalls.json
KALI> for fw in $(az network firewall list --query '[].name' --output tsv); do
  rg=$(az network firewall show --name $fw --query resourceGroup --output tsv)
  az network firewall network-rule collection list \
    --firewall-name $fw --resource-group $rg --output json \
    >> ~/reports/network/fw-rules.json
done

# Application Gateway WAF policies
KALI> az network application-gateway waf-policy list --output json \
        > ~/reports/network/waf-policies.json
```

### 5.5 Nmap — Network Scanning

```bash
KALI> sudo nmap -sS -sV -O --top-ports 1000 \
        -oA ~/reports/network/nmap-vnet-scan \
        10.0.0.0/16
```

### 5.6 nuclei — External Endpoint Scanning

```bash
# Collect all public endpoints
KALI> az network public-ip list --query '[].ipAddress' --output tsv | \
        grep -v null > /tmp/targets.txt

KALI> nuclei -l /tmp/targets.txt \
        -t cves/ -t misconfiguration/ -t exposures/ \
        -severity critical,high \
        -o ~/reports/network/nuclei-results.txt
```

### 5.7 Service Endpoint & Private Link Audit

```bash
KALI> steampipe query "
  SELECT
    name, resource_group, type,
    private_endpoint_connections IS NOT NULL AS has_private_endpoint,
    network_rule_set IS NOT NULL AS has_network_rules
  FROM azure_storage_account;
"

# Check for Key Vaults without private endpoints
KALI> az keyvault list --output json | \
        jq '[.[] | select(.properties.privateEndpointConnections == null or
                          (.properties.privateEndpointConnections | length) == 0) |
             {name: .name, rg: .resourceGroup}]'
```

### 5.8 DNS Zone Security

```bash
KALI> az network dns zone list --output json > ~/reports/network/dns-zones.json
KALI> az network private-dns zone list --output json > ~/reports/network/private-dns.json
```

---

## 6. Data Protection & Encryption

### 6.1 Storage Account Security Audit

```bash
KALI> steampipe query "
  SELECT
    name, resource_group,
    allow_blob_public_access,
    enable_https_traffic_only,
    min_tls_version,
    encryption_key_source,
    network_rule_default_action,
    is_hns_enabled
  FROM azure_storage_account
  ORDER BY allow_blob_public_access DESC;
"
```

```bash
# Find publicly accessible containers
KALI> for acct in $(az storage account list --query '[].name' --output tsv); do
  key=$(az storage account keys list --account-name $acct --query '[0].value' --output tsv 2>/dev/null)
  if [ -n "$key" ]; then
    az storage container list --account-name $acct --account-key $key --output json 2>/dev/null | \
      jq --arg acct "$acct" '[.[] | select(.properties.publicAccess != "off" and .properties.publicAccess != null) |
           {account: $acct, container: .name, publicAccess: .properties.publicAccess}]'
  fi
done > ~/reports/data/public-containers.json
```

### 6.2 Key Vault Security

```bash
KALI> steampipe query "
  SELECT
    name, resource_group,
    soft_delete_enabled,
    purge_protection_enabled,
    enable_rbac_authorization,
    sku_name,
    network_acls ->> 'defaultAction' AS default_network_action
  FROM azure_key_vault;
"
```

**Expected Output:**

```text
+------------------+----------------+---------------------+-------------------------+--------------------------+----------+-------------------------+
| name             | resource_group | soft_delete_enabled | purge_protection_enabled| enable_rbac_authorization| sku_name | default_network_action  |
+------------------+----------------+---------------------+-------------------------+--------------------------+----------+-------------------------+
| prod-secrets     | prod-rg        | true                | true                    | true                     | premium  | Deny                    |
| dev-keys         | dev-rg         | false               | false                   | false                    | standard | Allow                   |
+------------------+----------------+---------------------+-------------------------+--------------------------+----------+-------------------------+
```

### 6.3 SQL Database — TDE & Firewall

```bash
KALI> steampipe query "
  SELECT
    s.name AS server_name,
    d.name AS db_name,
    d.transparent_data_encryption ->> 'status' AS tde_status,
    s.minimal_tls_version,
    s.public_network_access
  FROM azure_sql_server s
  JOIN azure_sql_database d ON d.server_name = s.name;
"

# Check SQL firewall rules (0.0.0.0 = allow all Azure)
KALI> for server in $(az sql server list --query '[].name' --output tsv); do
  rg=$(az sql server show --name $server --query resourceGroup --output tsv)
  echo "=== $server ===" >> ~/reports/data/sql-firewall.txt
  az sql server firewall-rule list --server $server --resource-group $rg --output table \
    >> ~/reports/data/sql-firewall.txt
done
```

### 6.4 Disk Encryption

```bash
KALI> steampipe query "
  SELECT
    name, resource_group,
    encryption_type,
    os_type,
    disk_encryption_set_id IS NOT NULL AS uses_cmk
  FROM azure_compute_disk
  WHERE encryption_type = 'EncryptionAtRestWithPlatformKey';
"
```

### 6.5 Azure Cosmos DB Security

```bash
KALI> az cosmosdb list --output json | \
        jq '[.[] | {
          name: .name,
          rg: .resourceGroup,
          publicNetworkAccess: .publicNetworkAccess,
          disableKeyBasedMetadataWriteAccess: .disableKeyBasedMetadataWriteAccess,
          ipRules: .ipRules,
          isVirtualNetworkFilterEnabled: .isVirtualNetworkFilterEnabled
        }]' > ~/reports/data/cosmosdb-audit.json
```

### 6.6 Activity Log & Diagnostic Settings

```bash
# Check if activity logs are exported
KALI> az monitor diagnostic-settings subscription list --output json \
        > ~/reports/data/diagnostic-settings.json

# Check for key vault diagnostics
KALI> for vault in $(az keyvault list --query '[].name' --output tsv); do
  az monitor diagnostic-settings list --resource $(az keyvault show --name $vault --query id --output tsv) \
    --output json >> ~/reports/data/keyvault-diagnostics.json 2>/dev/null
done
```

---

## 7. Runtime, Container & Serverless Security

### 7.1 AKS Cluster Security

```bash
KALI> az aks list --output json > ~/reports/runtime/aks-clusters.json

# Detailed security assessment
KALI> az aks list --output json | \
        jq '[.[] | {
          name: .name,
          rg: .resourceGroup,
          version: .kubernetesVersion,
          enableRBAC: .enableRbac,
          networkPlugin: .networkProfile.networkPlugin,
          networkPolicy: .networkProfile.networkPolicy,
          privateCluster: .apiServerAccessProfile.enablePrivateCluster,
          azurePolicy: .addonProfiles.azurepolicy.enabled,
          defenderEnabled: .securityProfile.defender.securityMonitoring.enabled,
          workloadIdentity: .securityProfile.workloadIdentity.enabled,
          oidcIssuer: .oidcIssuerProfile.enabled
        }]'
```

**Expected Output:**

```json
[
  {
    "name": "prod-aks",
    "rg": "prod-rg",
    "version": "1.28.3",
    "enableRBAC": true,
    "networkPlugin": "azure",
    "networkPolicy": "calico",
    "privateCluster": true,
    "azurePolicy": true,
    "defenderEnabled": true,
    "workloadIdentity": true,
    "oidcIssuer": true
  },
  {
    "name": "dev-aks",
    "rg": "dev-rg",
    "version": "1.26.8",
    "enableRBAC": true,
    "networkPlugin": "kubenet",
    "networkPolicy": null,
    "privateCluster": false,
    "azurePolicy": false,
    "defenderEnabled": false,
    "workloadIdentity": false,
    "oidcIssuer": false
  }
]
```

### 7.2 kube-bench — AKS CIS Benchmark

```bash
KALI> az aks get-credentials --resource-group prod-rg --name prod-aks
KALI> kube-bench run --targets=node,policies \
        --benchmark aks-1.4.0 \
        --json --outputfile ~/reports/runtime/kube-bench-aks.json
```

### 7.3 kube-hunter — AKS Penetration Testing

```bash
KALI> ENDPOINT=$(az aks show --resource-group prod-rg --name prod-aks \
        --query 'fqdn' --output tsv)
KALI> kube-hunter --remote $ENDPOINT \
        --report json > ~/reports/runtime/kube-hunter-aks.json
```

### 7.4 trivy — ACR Image Scanning

```bash
# Login to Azure Container Registry
KALI> az acr login --name myregistry

# List and scan images
KALI> for repo in $(az acr repository list --name myregistry --output tsv); do
  tags=$(az acr repository show-tags --name myregistry --repository $repo \
    --top 1 --orderby time_desc --output tsv)
  for tag in $tags; do
    echo "Scanning: myregistry.azurecr.io/$repo:$tag"
    trivy image --severity CRITICAL,HIGH \
      --format json \
      --output ~/reports/runtime/trivy-$(echo ${repo}_${tag} | tr '/:' '_').json \
      "myregistry.azurecr.io/$repo:$tag"
  done
done
```

### 7.5 Azure Functions Security

```bash
# List all Function Apps and check auth settings
KALI> for app in $(az functionapp list --query '[].name' --output tsv); do
  rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
  auth=$(az functionapp auth show --name $app --resource-group $rg --output json 2>/dev/null)
  echo "$auth" | jq --arg app "$app" '{
    functionApp: $app,
    authEnabled: .properties.enabled,
    unauthenticatedAction: .properties.unauthenticatedClientAction
  }'
done > ~/reports/runtime/functionapp-auth.json

# Check for HTTP-triggered functions without auth
KALI> for app in $(az functionapp list --query '[].name' --output tsv); do
  rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
  az functionapp function list --name $app --resource-group $rg --output json | \
    jq --arg app "$app" '[.[] | select(.config.bindings[]? | .type == "httpTrigger" and .authLevel == "anonymous") |
         {app: $app, function: .name, authLevel: "ANONYMOUS"}]'
done > ~/reports/runtime/public-functions.json
```

### 7.6 Falco — AKS Runtime Detection

```bash
KALI> helm repo add falcosecurity https://falcosecurity.github.io/charts
KALI> helm install falco falcosecurity/falco \
        --namespace falco --create-namespace \
        --set falcosidekick.enabled=true \
        --set falcosidekick.config.customfields="cloud:azure"
```

### 7.7 VM Extension & Run Command Audit

```bash
# Check for suspicious VM extensions
KALI> az vm extension list --output json --ids $(az vm list --query '[].id' --output tsv) | \
        jq '[.[] | {vm: .virtualMachineExtensionProperties.publisher, name: .name, type: .type}]'

# Check for Run Command history (potential lateral movement)
KALI> for vm_id in $(az vm list --query '[].id' --output tsv); do
  vm_name=$(echo $vm_id | rev | cut -d/ -f1 | rev)
  echo "=== $vm_name ===" >> ~/reports/runtime/run-commands.txt
  az vm run-command list --vm-id $vm_id --output table >> ~/reports/runtime/run-commands.txt 2>/dev/null
done
```

---

## 8. Supply-Chain & CI/CD Security

### 8.1 Azure Container Registry Security

```bash
KALI> az acr list --output json | \
        jq '[.[] | {
          name: .name,
          sku: .sku.name,
          adminEnabled: .adminUserEnabled,
          publicNetworkAccess: .publicNetworkAccess,
          encryption: .encryption.status,
          contentTrust: .policies.trustPolicy.status,
          quarantine: .policies.quarantinePolicy.status
        }]' > ~/reports/cicd/acr-audit.json
```

Flag: `adminEnabled: true` (use service principals instead), `publicNetworkAccess: "Enabled"` for production registries.

### 8.2 Azure DevOps / GitHub Actions Audit

```bash
# If using Azure DevOps:
KALI> az devops project list --organization $ORG_URL --output json \
        > ~/reports/cicd/devops-projects.json

# Check for variable groups with secrets
KALI> az pipelines variable-group list --organization $ORG_URL --project $PROJECT \
        --output json > ~/reports/cicd/variable-groups.json

# Check pipeline YAML for insecure patterns
KALI> checkov -d ~/repo/.github/workflows/ --framework github_actions \
        --output json --output-file-path ~/reports/cicd/checkov-gha.json
KALI> checkov -d ~/repo/azure-pipelines/ --framework azure_pipelines \
        --output json --output-file-path ~/reports/cicd/checkov-azpipelines.json
```

### 8.3 SBOM & CVE Analysis

```bash
KALI> for repo in $(az acr repository list --name myregistry --output tsv); do
  tag=$(az acr repository show-tags --name myregistry --repository $repo \
    --top 1 --orderby time_desc --output tsv)
  syft "myregistry.azurecr.io/$repo:$tag" \
    -o spdx-json > ~/reports/cicd/sbom-$(echo $repo | tr '/' '_').spdx.json
  grype sbom:~/reports/cicd/sbom-$(echo $repo | tr '/' '_').spdx.json \
    --output json > ~/reports/cicd/vulns-$(echo $repo | tr '/' '_').json
done
```

### 8.4 checkov — Bicep / ARM Template Scanning

```bash
KALI> checkov -d ~/infra/bicep/ --framework bicep \
        --output json --output-file-path ~/reports/cicd/checkov-bicep.json
KALI> checkov -d ~/infra/arm/ --framework arm \
        --output json --output-file-path ~/reports/cicd/checkov-arm.json
```

---

## 9. Automated Reconnaissance & Validation Pipelines

### 9.1 Full Automated Recon Script

```bash
#!/usr/bin/env bash
# azure_recon_pipeline.sh
set -euo pipefail

SUBSCRIPTION_ID=$(az account show --query id --output tsv)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_BASE=~/reports/azure-${SUBSCRIPTION_ID}-${TIMESTAMP}
mkdir -p $REPORT_BASE/{iam,network,data,runtime,cicd,recon,compliance}

echo "[*] Phase 1: Configuration & Compliance"
prowler azure --output-formats json-ocsf \
  --output-directory $REPORT_BASE/compliance/ 2>&1 | tee $REPORT_BASE/compliance/prowler.log

echo "[*] Phase 2: Identity & Access"
az role assignment list --all --output json > $REPORT_BASE/iam/rbac-assignments.json
az ad user list --all --output json > $REPORT_BASE/iam/users.json
az ad sp list --all --output json > $REPORT_BASE/iam/service-principals.json
az ad app list --all --output json > $REPORT_BASE/iam/app-registrations.json
azurehound start -o $REPORT_BASE/iam/azurehound.json \
  --tenant $AZURE_TENANT_ID -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET 2>/dev/null || true

echo "[*] Phase 3: Network"
az network nsg list --output json > $REPORT_BASE/network/nsgs.json
az network public-ip list --output json > $REPORT_BASE/network/public-ips.json
az network vnet list --output json > $REPORT_BASE/network/vnets.json

echo "[*] Phase 4: Data Protection"
az storage account list --output json > $REPORT_BASE/data/storage-accounts.json
az keyvault list --output json > $REPORT_BASE/data/key-vaults.json

echo "[*] Phase 5: Runtime"
az aks list --output json > $REPORT_BASE/runtime/aks-clusters.json
az functionapp list --output json > $REPORT_BASE/runtime/function-apps.json

echo "[*] Phase 6: Supply Chain"
az acr list --output json > $REPORT_BASE/cicd/acr-registries.json 2>/dev/null || true

echo "[*] Phase 7: SHA-256 Manifest"
find $REPORT_BASE -type f -exec sha256sum {} \; > $REPORT_BASE/SHA256SUMS.txt

echo "[+] Complete. Report: $REPORT_BASE"
```

### 9.2 Scheduled Pipeline

```bash
KALI> crontab -e
# Weekly at 4 AM Sunday
0 4 * * 0 /home/kali/azure_recon_pipeline.sh >> /var/log/azure-recon.log 2>&1
```

---

## 10. IAM / Path Analysis at Scale

### 10.1 BloodHound CE — Azure Attack Paths

After importing AzureHound data (§4.2), use BloodHound CE built-in queries:

```text
Built-in Queries:
  → "Find all paths to Azure Subscription Owners"
  → "Find principals with Key Vault access"
  → "Find paths from Guest users to sensitive resources"
  → "Find Azure AD Global Administrator paths"
  → "Find principals that can reset passwords"
```

### 10.2 Custom Cypher Queries in BloodHound CE

```cypher
// Find paths from Service Principals to Global Admin
MATCH path = (sp:AZServicePrincipal)-[*1..5]->(admin:AZRole {displayName:"Global Administrator"})
RETURN path LIMIT 20;

// Find managed identity escalation paths
MATCH path = (mi:AZManagedIdentity)-[*1..4]->(kv:AZKeyVault)
RETURN path LIMIT 20;

// Find guest user attack paths
MATCH (guest:AZUser {userType:"Guest"})-[r*1..4]->(target)
WHERE target:AZSubscription OR target:AZKeyVault OR target:AZResourceGroup
RETURN guest.displayName, [rel in r | type(rel)], target.name;
```

### 10.3 CloudFox — Azure RBAC Analysis

```bash
KALI> cloudfox azure rbac --subscription $SUBSCRIPTION_ID -o ~/reports/iam/cloudfox/
KALI> cloudfox azure instances --subscription $SUBSCRIPTION_ID -o ~/reports/iam/cloudfox/
KALI> cloudfox azure storage --subscription $SUBSCRIPTION_ID -o ~/reports/iam/cloudfox/
```

### 10.4 Cartography — Azure Graph

```bash
KALI> cartography --azure-requested-syncs all \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password-env-var NEO4J_PASSWORD
```

---

## 11. Neo4j Attack-Path Setup & Visualization

### 11.1 Neo4j Configuration

Same as Doc 1 §11.1 — configure memory, APOC plugin, bolt access.

### 11.2 Loading Azure Data

Option A — Cartography (§10.4) loads directly into Neo4j.

Option B — AzureHound/BloodHound CE uses its own database but exposes Cypher.

### 11.3 Azure Attack-Path Cypher Queries

```cypher
// Internet → NSG → VM → Managed Identity → Key Vault
MATCH path = (internet:Internet)-[:EXPOSES]->(nsg:AzureNSG)
              -[:ALLOWS]->(vm:AzureVM)
              -[:HAS_IDENTITY]->(mi:AzureManagedIdentity)
              -[:HAS_ROLE]->(role:AzureRoleAssignment)
              -[:GRANTS_ACCESS]->(kv:AzureKeyVault)
WHERE nsg.sourceAddress = '*'
RETURN path LIMIT 20;

// Service Principal → App Registration → High-Priv Role
MATCH path = (sp:AzureServicePrincipal)-[:OWNS|HAS_APP]->(app:AzureAppRegistration)
              -[:HAS_API_PERMISSION]->(perm:AzureAPIPermission)
WHERE perm.value IN ['Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory']
RETURN path;

// Cross-subscription lateral movement
MATCH (role1:AzureRoleAssignment)-[:ASSIGNED_TO]->(principal)
MATCH (role2:AzureRoleAssignment)-[:ASSIGNED_TO]->(principal)
WHERE role1.subscription <> role2.subscription
  AND role2.roleDefinitionName IN ['Owner', 'Contributor']
RETURN principal, role1.subscription, role2.subscription;
```

---

## 12. Multi-Cloud Attack-Surface Mapping

### 12.1 CloudFox — Azure Attack Surface

```bash
KALI> cloudfox azure all-checks --subscription $SUBSCRIPTION_ID \
        -o ~/reports/multicloud/azure/
```

### 12.2 Steampipe — Cross-Cloud Queries

```sql
-- All public-facing Azure resources
SELECT 'Azure' AS cloud, 'Storage' AS type, name AS resource
FROM azure_storage_account
WHERE allow_blob_public_access = true

UNION ALL

SELECT 'Azure' AS cloud, 'VM' AS type, name AS resource
FROM azure_compute_virtual_machine v
JOIN azure_compute_virtual_machine_network_interface n
  ON v.id = ANY(n.virtual_machine_id)
WHERE n.ip_configurations @> '[{"public_ip_address": {}}]';
```

### 12.3 Cross-Cloud Credential Detection

```bash
# Check Key Vault for cross-cloud secrets
KALI> for vault in $(az keyvault list --query '[].name' --output tsv); do
  for secret in $(az keyvault secret list --vault-name $vault --query '[].name' --output tsv 2>/dev/null); do
    if echo "$secret" | grep -qiE '(aws|gcp|google)'; then
      echo "CROSS-CLOUD SECRET: vault=$vault secret=$secret" >> ~/reports/multicloud/shared-creds.txt
    fi
  done
done

# Check App Settings for cross-cloud credentials
KALI> for app in $(az functionapp list --query '[].name' --output tsv); do
  rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
  settings=$(az functionapp config appsettings list --name $app --resource-group $rg --output json 2>/dev/null)
  if echo "$settings" | grep -qiE '(AKIA|AWS_SECRET|GOOGLE_APPLICATION_CREDENTIALS)'; then
    echo "CROSS-CLOUD CRED: functionapp=$app" >> ~/reports/multicloud/shared-creds.txt
  fi
done
```

---

## 13. Hybrid Cloud Security Tools (Steampipe, CloudQuery, Cartography)

### 13.1 Steampipe — Azure CIS Compliance Mod

```bash
KALI> cd ~ && git clone https://github.com/turbot/steampipe-mod-azure-compliance.git
KALI> cd steampipe-mod-azure-compliance
KALI> steampipe check all --output json > ~/reports/hybrid/steampipe-azure-cis.json
```

### 13.2 CloudQuery — Azure Asset Inventory

Create `cloudquery-azure.yml`:

```yaml
kind: source
spec:
  name: azure
  registry: cloudquery
  path: cloudquery/azure
  version: "v14.0.0"
  tables: ["*"]
  destinations: ["postgresql"]
  spec:
    subscriptions: ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]

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
KALI> cloudquery sync cloudquery-azure.yml
# Expected: Sync complete: 8,234 total rows across 178 tables
```

### 13.3 Cartography — Cross-Cloud Graph

```bash
KALI> cartography --azure-requested-syncs all \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password-env-var NEO4J_PASSWORD
```

---

## 14. Aggregator Integration

### 14.1 Azure-Specific Aggregator Usage

```bash
KALI> python3 aggregator.py \
        --cloud azure \
        --input-dir ~/reports/azure-${SUBSCRIPTION_ID}-*/ \
        --output-dir ~/reports/aggregated/ \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password $NEO4J_PASSWORD \
        --compliance-frameworks "soc2,iso27001,hipaa,pci-dss"
```

**Expected Output:**

```text
[*] Scanning input directory for findings ...
[+] Parsed 18 files, extracted 327 findings
[*] Normalising to unified schema ...
[*] Generating outputs ...
    → unified-findings.json
    → dashboard.html
    → executive-summary.md
    → neo4j-import.cypher
    → AUDIT-MANIFEST.sha256
[+] Aggregation complete. 327 findings.
```

---

## 15. Gap Analysis & Filled Gaps

### 15.1 Identified Gaps

| # | Gap | Resolution | Section |
|---|-----|-----------|---------|
| 1 | No Entra ID deep recon | Added ROADtools full directory enumeration | §4.1 |
| 2 | No BloodHound/AzureHound integration | Added AzureHound collection + BloodHound CE | §4.2 |
| 3 | No Conditional Access audit | Added CA policy enumeration & analysis | §4.6 |
| 4 | No PIM status check | Added PIM eligible role assignment query | §4.7 |
| 5 | No guest user audit | Added guest user enumeration & flagging | §4.8 |
| 6 | No Azure Firewall/WAF audit | Added firewall rules & WAF policy collection | §5.4 |
| 7 | No Private Link / Service Endpoint check | Added storage & KV private endpoint audit | §5.7 |
| 8 | No Cosmos DB security | Added Cosmos DB network & access audit | §6.5 |
| 9 | No diagnostic settings check | Added activity log & KV diagnostic verification | §6.6 |
| 10 | No Function App auth check | Added anonymous HTTP trigger detection | §7.5 |
| 11 | No VM extension audit | Added VM extension & Run Command history check | §7.7 |
| 12 | No ACR content trust check | Added ACR quarantine, trust, encryption audit | §8.1 |
| 13 | No Managed Identity role audit | Added MI enumeration & role assignment check | §4.4 |
| 14 | No app secret expiry check | Added expired/expiring credential detection | §4.5 |
| 15 | No Defender for Cloud status | Added below | §15.2 |
| 16 | No Azure Policy compliance | Added below | §15.3 |
| 17 | No Network Watcher flow logs | Added below | §15.4 |
| 18 | No Management Group audit | Added below | §15.5 |

### 15.2 Gap Fill: Microsoft Defender for Cloud

```bash
KALI> az security assessment list --output json | \
        jq '[.[] | select(.status.code == "Unhealthy") |
             {name: .displayName, severity: .metadata.severity,
              status: .status.code, category: .metadata.category}]' \
        > ~/reports/compliance/defender-assessments.json

KALI> az security secure-score list --output json \
        > ~/reports/compliance/secure-score.json

# Expected secure-score output:
# [{"name": "compute", "currentScore": 7.2, "maxScore": 10.0}, ...]
```

### 15.3 Gap Fill: Azure Policy Compliance

```bash
KALI> az policy state summarize --output json \
        > ~/reports/compliance/policy-compliance-summary.json

KALI> az policy state list --filter "complianceState eq 'NonCompliant'" \
        --top 100 --output json \
        > ~/reports/compliance/non-compliant-resources.json
```

### 15.4 Gap Fill: Network Watcher Flow Logs

```bash
KALI> az network watcher flow-log list --output json \
        > ~/reports/network/flow-logs.json

# Check for NSGs without flow logs
KALI> for nsg_id in $(az network nsg list --query '[].id' --output tsv); do
  nsg_name=$(echo $nsg_id | rev | cut -d/ -f1 | rev)
  has_flow=$(az network watcher flow-log list --output json | \
    jq --arg id "$nsg_id" '[.[] | select(.targetResourceId == $id)] | length')
  if [ "$has_flow" -eq 0 ]; then
    echo "NO FLOW LOG: $nsg_name" >> ~/reports/network/missing-flow-logs.txt
  fi
done
```

### 15.5 Gap Fill: Management Group Hierarchy

```bash
KALI> az account management-group list --output json \
        > ~/reports/compliance/mgmt-groups.json

# Check RBAC at management group level
KALI> for mg in $(az account management-group list --query '[].name' --output tsv); do
  echo "=== $mg ===" >> ~/reports/iam/mgmt-group-rbac.txt
  az role assignment list --scope "/providers/Microsoft.Management/managementGroups/$mg" \
    --output table >> ~/reports/iam/mgmt-group-rbac.txt
done
```

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
| AzureHound | GPL-3.0 | None |
| BloodHound CE | Apache-2.0 | None |
| ROADtools | MIT | None |
| MicroBurst | BSD-3-Clause | None |
| PowerZure | BSD-3-Clause | None |
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

### Appendix B: Azure Resource Providers to Register

```bash
KALI> az provider register --namespace Microsoft.Security
KALI> az provider register --namespace Microsoft.PolicyInsights
KALI> az provider register --namespace Microsoft.KeyVault
KALI> az provider register --namespace Microsoft.ContainerRegistry
KALI> az provider register --namespace Microsoft.ContainerService
KALI> az provider register --namespace Microsoft.Network
KALI> az provider register --namespace Microsoft.Sql
KALI> az provider register --namespace Microsoft.Storage
KALI> az provider register --namespace Microsoft.Web
KALI> az provider register --namespace Microsoft.ManagedIdentity
KALI> az provider register --namespace Microsoft.Authorization
```

### Appendix C: Report File Structure

```text
azure-{subscription}-{timestamp}/
├── iam/
│   ├── rbac-assignments.json
│   ├── users.json
│   ├── service-principals.json
│   ├── app-registrations.json
│   ├── managed-identities.json
│   ├── azurehound.json
│   ├── conditional-access.json
│   ├── guest-users.json
│   └── cloudfox/
├── network/
│   ├── nsgs.json
│   ├── vnets.json
│   ├── public-ips.json
│   ├── firewalls.json
│   ├── waf-policies.json
│   ├── nmap-vnet-scan.xml
│   ├── nuclei-results.txt
│   └── missing-flow-logs.txt
├── data/
│   ├── storage-accounts.json
│   ├── public-containers.json
│   ├── key-vaults.json
│   ├── sql-firewall.txt
│   ├── cosmosdb-audit.json
│   └── diagnostic-settings.json
├── runtime/
│   ├── aks-clusters.json
│   ├── kube-bench-aks.json
│   ├── trivy-*.json
│   ├── functionapp-auth.json
│   ├── public-functions.json
│   └── run-commands.txt
├── cicd/
│   ├── acr-audit.json
│   ├── sbom-*.spdx.json
│   └── checkov-*.json
├── compliance/
│   ├── prowler-azure-*.json
│   ├── steampipe-azure-cis.json
│   ├── defender-assessments.json
│   ├── secure-score.json
│   ├── policy-compliance-summary.json
│   └── non-compliant-resources.json
├── multicloud/
│   └── shared-creds.txt
├── EXECUTIVE_SUMMARY.md
├── SHA256SUMS.txt
└── AUDIT-MANIFEST.sha256
```

---

**END OF DOCUMENT 3 — Azure Security Testing Methodology**
