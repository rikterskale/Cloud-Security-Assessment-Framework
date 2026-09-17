"""Plain-language operator playbooks for a first live assessment.

``csaf-assess --guide --cloud aws`` (or azure/gcp/k8s) prints a complete,
copy-paste path: what to install, which read-only identity to create, how to
prove login works, the exact CSAF command, and how to read the reports.

This module never contacts a cloud.
"""

from __future__ import annotations

GUIDED_CLOUDS = ("aws", "azure", "gcp", "k8s")

_HEADER = """CSAF operator guide — {label}
================================
Read this once. Copy each command as written. Replace only the ALL_CAPS words.

CSAF is read-only. It lists configuration and writes reports on this computer.
It cannot create, change, or delete anything in the cloud.

You need written permission from the owner of the {scope} before you continue.

Other clouds:
  csaf-assess --guide --cloud aws
  csaf-assess --guide --cloud azure
  csaf-assess --guide --cloud gcp
  csaf-assess --guide --cloud k8s
"""

_AWS = r"""
What you need
-------------
- An AWS account you are allowed to assess
- 10-15 minutes
- The AWS CLI on this computer (`aws --version`). If missing:
    Windows:  winget install Amazon.AWSCLI
    Linux:    see https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

Safety
------
Use a dedicated IAM user or role with the AWS managed policy SecurityAudit.
Do not use the root user. Do not attach AdministratorAccess.

Step 1 — Create a read-only IAM user (AWS Console)
--------------------------------------------------
1. Sign in to the AWS Console as an administrator (not root if you can avoid it).
2. Open IAM → Users → Create user. Name it `csaf-audit`.
3. Skip console password unless this person also needs the Console.
4. On permissions, choose "Attach policies directly".
5. Search for `SecurityAudit` (AWS managed). Attach it.
6. Create the user. Open it → Security credentials → Create access key →
   "Command Line Interface (CLI)" → Create. Save Access key ID and Secret.

CLI alternative (if you already have admin CLI access):

  aws iam create-user --user-name csaf-audit
  aws iam attach-user-policy --user-name csaf-audit \
    --policy-arn arn:aws:iam::aws:policy/SecurityAudit
  aws iam create-access-key --user-name csaf-audit

Step 2 — Store the keys on this computer
----------------------------------------
  aws configure --profile csaf-audit

Paste the access key ID, secret, default region (example: us-east-1),
and output format `json`. This writes ~/.aws/credentials (Windows:
%USERPROFILE%\.aws\credentials). Never commit that file.

Step 3 — Prove login works
--------------------------
  aws sts get-caller-identity --profile csaf-audit

You should see an Account number and an Arn ending in `csaf-audit`.
If this fails, stop and fix AWS CLI login before running CSAF.

Step 4 — CSAF preflight (still no scan)
---------------------------------------
  csaf-assess --preflight --live --cloud aws --aws-profile csaf-audit

PASS means identity, IAM read, and this machine are ready.
FAIL prints the exact command to run next.

Step 5 — Run the assessment
---------------------------
Replace REGIONS with the regions you are authorized to assess
(example: us-east-1 us-west-2):

  csaf-assess --cloud aws --aws-profile csaf-audit --regions REGIONS --output-dir out

Step 6 — Read the reports
-------------------------
Reports land in a timestamped folder under `out/`.

  1. Open out/*/executive-summary.html in a browser (the management summary).
  2. Open out/*/findings.csv — CRITICAL first; each row has a remediation.
  3. Open out/*/coverage-report.csv — every selected control should have run.
     NotTested and Error are not passes.

To see one control in plain language:

  csaf-assess --cloud aws --explain CSAF-AWS-IAM-001
"""

_AZURE = r"""
What you need
-------------
- An Azure subscription you are allowed to assess
- 10-15 minutes
- Azure CLI (`az --version`). If missing:
    Windows:  winget install Microsoft.AzureCLI
    Linux:    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

Safety
------
Use your own account or a dedicated app registration with two built-in roles
on the subscription: Reader and Security Reader. Do not use Owner.

Step 1 — Sign in
----------------
  az login
  az account list --output table
  az account set --subscription SUBSCRIPTION_ID

SUBSCRIPTION_ID is the GUID in the `id` column (not the name).

Step 2 — Grant read-only roles
------------------------------
Ask an Owner to run these (or run them if you are Owner). Replace
SUBSCRIPTION_ID and USER_OR_SP (your user principal name, e.g. you@company.com):

  az role assignment create --assignee USER_OR_SP --role Reader \
    --scope /subscriptions/SUBSCRIPTION_ID
  az role assignment create --assignee USER_OR_SP --role "Security Reader" \
    --scope /subscriptions/SUBSCRIPTION_ID

Check:

  az role assignment list --assignee USER_OR_SP --subscription SUBSCRIPTION_ID --output table

Step 3 — Prove login works
--------------------------
  az account show

You should see the subscription you set. If this fails, stop and fix `az login`.

Step 4 — CSAF preflight (still no scan)
---------------------------------------
  csaf-assess --preflight --live --cloud azure --subscription SUBSCRIPTION_ID

PASS means Azure accepted this identity for that subscription.

Step 5 — Run the assessment
---------------------------
  csaf-assess --cloud azure --subscription SUBSCRIPTION_ID --output-dir out

Step 6 — Read the reports
-------------------------
  1. Open out/*/executive-summary.html
  2. Open out/*/findings.csv (CRITICAL first)
  3. Open out/*/coverage-report.csv (NotTested is not a pass)

  csaf-assess --cloud azure --explain CSAF-AZ-STO-001
"""

_GCP = r"""
What you need
-------------
- A GCP project you are allowed to assess
- 10-15 minutes
- Google Cloud SDK (`gcloud --version`). If missing:
    https://cloud.google.com/sdk/docs/install

Safety
------
Use your user or a dedicated service account with `roles/viewer` on the project.
Do not use Owner or Editor.

Step 1 — Sign in (Application Default Credentials)
--------------------------------------------------
  gcloud auth application-default login
  gcloud config set project PROJECT_ID
  gcloud projects describe PROJECT_ID

PROJECT_ID is the id (example: `acme-prod-123`), not the display name.

Step 2 — Grant the Viewer role
------------------------------
Ask an Owner to run (replace EMAIL and PROJECT_ID):

  gcloud projects add-iam-policy-binding PROJECT_ID \
    --member=user:EMAIL --role=roles/viewer

Check:

  gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" \
    --filter="bindings.role:roles/viewer"

Step 3 — Prove login works
--------------------------
  gcloud auth application-default print-access-token
  gcloud projects describe PROJECT_ID

If either fails, stop and fix gcloud login before running CSAF.

Step 4 — CSAF preflight (still no scan)
---------------------------------------
  csaf-assess --preflight --live --cloud gcp --project PROJECT_ID

Step 5 — Run the assessment
---------------------------
  csaf-assess --cloud gcp --project PROJECT_ID --output-dir out

Step 6 — Read the reports
-------------------------
  1. Open out/*/executive-summary.html
  2. Open out/*/findings.csv (CRITICAL first)
  3. Open out/*/coverage-report.csv (NotTested is not a pass)

  csaf-assess --cloud gcp --explain CSAF-GCP-IAM-001
"""

_K8S = r"""
What you need
-------------
- A Kubernetes cluster you are allowed to assess
- A kubeconfig that already reaches that cluster
- 10 minutes
- kubectl (`kubectl version --client`). If missing:
    https://kubernetes.io/docs/tasks/tools/

Safety
------
Use a dedicated ServiceAccount (or your user) bound to the built-in `view`
ClusterRole. Do not use cluster-admin for CSAF.

Step 1 — Confirm you can see the cluster
----------------------------------------
  kubectl config get-contexts
  kubectl config current-context
  kubectl get ns

If `get ns` fails, your kubeconfig cannot read the cluster. Stop here and
ask the platform owner for a read-only context.

Step 2 — Grant read-only access (if `get ns` works you can skip this)
---------------------------------------------------------------------
Ask a cluster-admin to bind your user or a ServiceAccount to `view`.
Replace USERNAME (or use a ServiceAccount):

  kubectl create clusterrolebinding csaf-view \
    --clusterrole=view --user=USERNAME

For a ServiceAccount in namespace `csaf`:

  kubectl create namespace csaf
  kubectl create serviceaccount csaf-audit -n csaf
  kubectl create clusterrolebinding csaf-view \
    --clusterrole=view --serviceaccount=csaf:csaf-audit

Step 3 — CSAF preflight (still no scan)
---------------------------------------
If you use the current context:

  csaf-assess --preflight --live --cloud k8s

If you need a named context:

  csaf-assess --preflight --live --cloud k8s --kube-context CONTEXT_NAME

Optional custom kubeconfig file:

  csaf-assess --preflight --live --cloud k8s --kubeconfig /path/to/kubeconfig

Step 4 — Run the assessment
---------------------------
  csaf-assess --cloud k8s --kube-context CONTEXT_NAME --output-dir out

Step 5 — Read the reports
-------------------------
  1. Open out/*/executive-summary.html
  2. Open out/*/findings.csv (CRITICAL first)
  3. Open out/*/coverage-report.csv (NotTested is not a pass)

  csaf-assess --cloud k8s --explain CSAF-K8S-RBAC-001
"""

_PLAYBOOKS = {
    "aws": (_AWS, "AWS", "AWS account"),
    "azure": (_AZURE, "Azure", "Azure subscription"),
    "gcp": (_GCP, "GCP", "GCP project"),
    "k8s": (_K8S, "Kubernetes", "Kubernetes cluster"),
}


def render_guide(cloud: str) -> str:
    """Return the full operator playbook for ``cloud``."""
    if cloud not in _PLAYBOOKS:
        known = ", ".join(GUIDED_CLOUDS)
        return f"Unknown cloud {cloud!r}. Choose one of: {known}\n    Fix: csaf-assess --guide --cloud aws"
    body, label, scope = _PLAYBOOKS[cloud]
    return _HEADER.format(label=label, scope=scope) + body


def scan_command(
    cloud: str,
    *,
    aws_profile: str | None = None,
    subscription: str | None = None,
    project: str | None = None,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
    regions: list[str] | None = None,
    output_dir: str = "out",
) -> str:
    """Exact command an operator should run after a successful live preflight."""
    parts = ["csaf-assess", "--cloud", cloud]
    if cloud == "aws":
        parts.extend(["--aws-profile", aws_profile or "csaf-audit"])
        parts.extend(["--regions", *(regions or ["us-east-1"])])
    elif cloud == "azure":
        parts.extend(["--subscription", subscription or "SUBSCRIPTION_ID"])
    elif cloud == "gcp":
        parts.extend(["--project", project or "PROJECT_ID"])
    else:
        if kube_context:
            parts.extend(["--kube-context", kube_context])
        if kubeconfig:
            parts.extend(["--kubeconfig", kubeconfig])
    parts.extend(["--output-dir", output_dir])
    return " ".join(parts)


def aftercare(*, cloud: str, output_dir: str, exit_code: int, self_check: bool) -> str:
    """What to do after a run, in operator language."""
    if exit_code == 1:
        return (
            "\nWhat just happened: the assessment did not start (or stopped on a fatal error).\n"
            "Next: read the Fix line above, or print the full setup playbook:\n"
            f"      csaf-assess --guide --cloud {cloud}"
        )
    incomplete = ""
    if exit_code == 2 and self_check:
        incomplete = "\n[INCOMPLETE] is expected for the offline demo: one control is left untested on purpose.\n"
    elif exit_code == 2:
        incomplete = (
            "\nSome selected controls did not finish (NotTested or Error). "
            "That is not a clean bill of health. Open coverage-report.csv.\n"
        )
    return (
        incomplete + "\nWhat just happened: CSAF read configuration and wrote reports on this computer. "
        "It did not change the cloud.\n"
        "How to read the results:\n"
        f"  1. Open {output_dir}/executive-summary.html in a browser (management summary).\n"
        f"  2. Open {output_dir}/findings.csv — CRITICAL first; each row has a remediation.\n"
        f"  3. Open {output_dir}/coverage-report.csv — NotTested and Error are not passes.\n"
        f"Next: csaf-assess --cloud {cloud} --explain CONTROL_ID"
    )
