"""Structured operator errors: cause, affected resource, exact fix command.

Every user-facing failure should be a :class:`CsafError`. Unknown exceptions
are wrapped, never swallowed. Cloud probes in :func:`probe_cloud_access` are
read-only (STS, IAM summary, S3/EC2/CloudTrail list, ARM GET, GCP GET,
Kubernetes read).
"""

from __future__ import annotations

from dataclasses import dataclass

ERROR_CODES = {
    "ok": "CSAF-E000",
    "dependency": "CSAF-E001",
    "credentials": "CSAF-E002",
    "file": "CSAF-E003",
    "permission": "CSAF-E004",
    "authorization": "CSAF-E005",
    "tutorial": "CSAF-E006",
    "cleanup": "CSAF-E007",
    "api": "CSAF-E008",
    "unknown": "CSAF-E999",
}

_PROVIDER_EXTRAS = {
    "azure": "azure",
    "azure.identity": "azure",
    "google": "gcp",
    "google.auth": "gcp",
    "kubernetes": "k8s",
    "boto3": "aws",
    "botocore": "aws",
}

_CREDENTIAL_MARKERS = (
    "NoCredentials",
    "CredentialsError",
    "DefaultCredentialsError",
    "InvalidConfig",
    "TokenRetrieval",
    "ClientAuthentication",
    "Unauthorized",
    "ExpiredToken",
    "UnrecognizedClient",
)

_EXTRA_INSTALL = {
    "aws": "python -m pip install 'cloud-saf[aws]'",
    "azure": "python -m pip install 'cloud-saf[azure]'",
    "gcp": "python -m pip install 'cloud-saf[gcp]'",
    "k8s": "python -m pip install 'cloud-saf[k8s]'",
}

_CREDENTIAL_FIX = {
    "aws": (
        "aws sts get-caller-identity --profile YOUR_PROFILE\n"
        "         Then: csaf-assess --preflight --live --cloud aws --aws-profile YOUR_PROFILE\n"
        "         Setup playbook: csaf-assess --guide --cloud aws"
    ),
    "azure": (
        "az login\n"
        "         az account show\n"
        "         Then: csaf-assess --preflight --live --cloud azure --subscription SUBSCRIPTION_ID\n"
        "         Setup playbook: csaf-assess --guide --cloud azure"
    ),
    "gcp": (
        "gcloud auth application-default login\n"
        "         gcloud config set project PROJECT_ID\n"
        "         Then: csaf-assess --preflight --live --cloud gcp --project PROJECT_ID\n"
        "         Setup playbook: csaf-assess --guide --cloud gcp"
    ),
    "k8s": (
        "kubectl config current-context\n"
        "         kubectl get ns\n"
        "         Then: csaf-assess --preflight --live --cloud k8s\n"
        "         Setup playbook: csaf-assess --guide --cloud k8s"
    ),
}

_AWS_API_PROBES = (
    ("iam", "GetAccountSummary", lambda c: c.get_account_summary()),
    ("s3", "ListBuckets", lambda c: c.list_buckets()),
    ("ec2", "DescribeRegions", lambda c: c.describe_regions()),
    ("cloudtrail", "DescribeTrails", lambda c: c.describe_trails()),
    ("config", "DescribeConfigurationRecorders", lambda c: c.describe_configuration_recorders()),
    ("guardduty", "ListDetectors", lambda c: c.list_detectors()),
    ("securityhub", "DescribeHub", lambda c: c.describe_hub()),
    ("kms", "ListKeys", lambda c: c.list_keys(Limit=1)),
    ("rds", "DescribeDBInstances", lambda c: c.describe_db_instances()),
    ("secretsmanager", "ListSecrets", lambda c: c.list_secrets(MaxResults=1)),
)

_AZURE_ARM_PROBES = (
    ("Microsoft.Storage/storageAccounts", "2023-01-01", "storage"),
    ("Microsoft.Network/networkSecurityGroups", "2023-09-01", "network"),
    ("Microsoft.Compute/virtualMachines", "2023-09-01", "compute"),
    ("Microsoft.KeyVault/vaults", "2023-07-01", "keyvault"),
    ("Microsoft.Sql/servers", "2021-11-01", "sql"),
    ("Microsoft.Authorization/roleDefinitions", "2022-04-01", "identity"),
    ("Microsoft.Insights/diagnosticSettings", "2021-05-01-preview", "monitor"),
)

_GCP_API_PROBES = (
    ("iam:getIamPolicy", "POST", "https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy"),
    ("storage.buckets.list", "GET", "https://storage.googleapis.com/storage/v1/b?project={project}"),
    (
        "compute.instances.aggregatedList",
        "GET",
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances?maxResults=1",
    ),
    ("logging.sinks.list", "GET", "https://logging.googleapis.com/v2/projects/{project}/sinks"),
    (
        "cloudkms.keyRings.list",
        "GET",
        "https://cloudkms.googleapis.com/v1/projects/{project}/locations/global/keyRings",
    ),
    ("sql.instances.list", "GET", "https://sqladmin.googleapis.com/v1/projects/{project}/instances"),
)


@dataclass(frozen=True)
class CsafError:
    code: str
    cause: str
    resource: str
    fix: str
    blocking: bool = True

    def format(self) -> str:
        return f"[{self.code}] {self.cause}\n    Resource: {self.resource}\n    Fix: {self.fix}"


def format_error(err: CsafError) -> str:
    return err.format()


def format_fatal(exc: BaseException) -> str:
    return from_exception(exc).format()


def explain_exception(exc: BaseException) -> tuple[str, str]:
    """Backward-compatible ``(summary, hint)`` used by existing diagnostics tests."""
    err = from_exception(exc)
    summary = f"[{err.code}] {err.cause}"
    return summary, err.fix


def from_exception(exc: BaseException, *, resource: str = "", cloud: str | None = None) -> CsafError:
    """Map an exception to a structured error. Never invent a mutating fix."""
    name = type(exc).__name__
    message = str(exc)
    target = resource or getattr(exc, "filename", None) or name
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)

    if isinstance(exc, ModuleNotFoundError | ImportError):
        missing = getattr(exc, "name", "") or ""
        top = missing.split(".")[0]
        extra = next((e for mod, e in _PROVIDER_EXTRAS.items() if missing == mod or top == mod.split(".")[0]), None)
        if extra:
            fix = _EXTRA_INSTALL[extra] + "   # or: python -m pip install --require-hashes -r requirements-lock.txt"
            cause = f"A dependency for the selected cloud is not installed ({missing})."
        else:
            fix = "python -m pip install --require-hashes -r requirements-lock.txt"
            cause = f"A required dependency is not installed ({missing or 'unknown module'})."
        return CsafError(ERROR_CODES["dependency"], cause, missing or str(target), fix)

    if any(marker in name for marker in _CREDENTIAL_MARKERS) or "credential" in message.lower():
        key = cloud if cloud in _CREDENTIAL_FIX else ""
        if not key:
            for candidate, extra in (("boto", "aws"), ("azure", "azure"), ("google", "gcp"), ("kube", "k8s")):
                if candidate in message.lower() or candidate in str(target).lower():
                    key = extra
                    break
        fallback = (
            _CREDENTIAL_FIX["aws"]
            + "\n         (or --cloud azure|gcp|k8s)\n"
            + "         Tip: run with --self-check to confirm the tool works with no cloud at all."
        )
        fix = _CREDENTIAL_FIX.get(key, fallback)
        return CsafError(
            ERROR_CODES["credentials"],
            "The cloud provider could not authenticate with the configured identity.",
            str(target),
            fix,
        )

    if isinstance(exc, FileNotFoundError):
        return CsafError(
            ERROR_CODES["file"],
            f"A file the assessment needs was not found ({target}).",
            str(target),
            "Pass an existing path to --catalog / --baseline / --engagement / --engagement-key-file.",
        )

    if isinstance(exc, PermissionError):
        return CsafError(
            ERROR_CODES["permission"],
            "CSAF could not write to the output directory.",
            str(target),
            "csaf-assess --output-dir ./out    # choose a writable directory",
        )

    if "engagement" in message.lower() or "signature" in message.lower():
        return CsafError(
            ERROR_CODES["authorization"],
            message or "The engagement authorization could not be validated.",
            str(target),
            "csaf-sign-engagement --engagement engagement.json --key-file engagement.key",
        )

    aws_code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        aws_code = response.get("Error", {}).get("Code", "")
    denied = (
        aws_code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"} or "AccessDenied" in message
    )
    http_denied = status in (401, 403) or " 401" in message or " 403" in message
    if denied or http_denied:
        return CsafError(
            ERROR_CODES["permission"],
            f"Read API denied ({aws_code or status or name}): {message}",
            str(target),
            "Attach the AWS managed policy arn:aws:iam::aws:policy/SecurityAudit to this principal "
            "(or Azure Reader + Security Reader / GCP roles/viewer / Kubernetes view). "
            "Playbook: csaf-assess --guide --cloud CLOUD\n"
            "         Then: csaf-assess --preflight --live",
        )

    cloud_key = cloud if cloud in _CREDENTIAL_FIX else "aws"
    return CsafError(
        ERROR_CODES["unknown"],
        f"{name}: {message}",
        str(target) or "runner",
        f"csaf-assess --guide --cloud {cloud_key}\n"
        "         Then: csaf-assess --log-level DEBUG --self-check --output-dir out",
    )


def probe_cloud_access(
    cloud: str,
    *,
    aws_profile: str | None = None,
    subscription: str | None = None,
    project: str | None = None,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
) -> list[CsafError]:
    """Read-only identity + API probes. Never called during --self-check."""
    probes = {
        "aws": lambda: _probe_aws(aws_profile),
        "azure": lambda: _probe_azure(subscription),
        "gcp": lambda: _probe_gcp(project),
        "k8s": lambda: _probe_k8s(kubeconfig, kube_context),
    }
    if cloud not in probes:
        return [
            CsafError(
                ERROR_CODES["api"],
                f"Unknown cloud '{cloud}'.",
                cloud,
                "csaf-assess --cloud aws|azure|gcp|k8s --preflight --live",
            )
        ]
    try:
        return probes[cloud]()
    except Exception as exc:
        return [from_exception(exc, resource=cloud, cloud=cloud)]


def _probe_aws(profile: str | None) -> list[CsafError]:
    try:
        import boto3
    except ImportError as exc:
        return [from_exception(exc, resource="boto3", cloud="aws")]
    session = boto3.Session(profile_name=profile)
    sts = session.client("sts")
    try:
        ident = sts.get_caller_identity()
    except Exception as exc:
        fix_profile = profile or "default"
        err = from_exception(exc, resource=f"sts:GetCallerIdentity (profile {fix_profile})", cloud="aws")
        return [
            CsafError(
                err.code,
                err.cause,
                err.resource,
                f"aws sts get-caller-identity --profile {fix_profile}",
            )
        ]
    arn = ident.get("Arn", "")
    account = ident.get("Account", "")
    errors: list[CsafError] = [
        CsafError(
            ERROR_CODES["ok"],
            f"AWS identity ok: {arn} (account {account}).",
            arn,
            "csaf-assess --cloud aws --aws-profile "
            + (profile or "default")
            + " --regions us-east-1 --output-dir out",
            blocking=False,
        )
    ]
    for service, action, call in _AWS_API_PROBES:
        resource = f"{service}:{action} (account {account})"
        try:
            client = session.client(service)
            call(client)
            errors.append(CsafError(ERROR_CODES["ok"], f"{service}:{action} ok.", resource, "", blocking=False))
        except Exception as exc:
            errors.append(
                CsafError(
                    ERROR_CODES["permission"],
                    f"Authenticated as {arn} but {service}:{action} was denied ({exc}).",
                    resource,
                    "aws iam simulate-principal-policy --policy-source-arn "
                    f"{arn} --action-names {service}:{action}\n"
                    "         Attach arn:aws:iam::aws:policy/SecurityAudit to this principal.\n"
                    "         Playbook: csaf-assess --guide --cloud aws",
                )
            )
    return errors


def _http_status_error(status: int, resource: str, url: str, cloud: str) -> CsafError:
    if status in (401, 403):
        return CsafError(
            ERROR_CODES["permission"],
            f"{resource} returned HTTP {status}.",
            url,
            _CREDENTIAL_FIX[cloud],
        )
    return CsafError(
        ERROR_CODES["api"],
        f"{resource} returned HTTP {status}.",
        url,
        _CREDENTIAL_FIX[cloud],
        blocking=status != 404,
    )


def _probe_azure(subscription: str | None) -> list[CsafError]:
    try:
        import requests
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        return [from_exception(exc, resource="azure.identity", cloud="azure")]
    try:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default")
    except Exception as extra_exc:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                f"Azure DefaultAzureCredential failed: {extra_exc}",
                "https://management.azure.com/.default",
                "az login\n         Then: az account show\n         Playbook: csaf-assess --guide --cloud azure",
            )
        ]
    headers = {"Authorization": f"Bearer {token.token}"}
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code in (401, 403):
        return [
            CsafError(
                ERROR_CODES["permission"],
                f"ARM GET /subscriptions returned HTTP {response.status_code}.",
                url,
                "az account show\n"
                "         Ask an Owner to grant Reader + Security Reader on the subscription.\n"
                "         Playbook: csaf-assess --guide --cloud azure",
            )
        ]
    if response.status_code >= 400:
        return [
            CsafError(
                ERROR_CODES["api"],
                f"ARM GET /subscriptions returned HTTP {response.status_code}.",
                url,
                "az account list --output table",
            )
        ]
    subs = [s.get("subscriptionId") for s in response.json().get("value", [])]
    if subscription and subscription not in subs:
        return [
            CsafError(
                ERROR_CODES["authorization"],
                f"Subscription {subscription} is not visible to this identity.",
                subscription,
                f"az account set --subscription {subscription}\n         az account show",
            )
        ]
    target = subscription or (subs[0] if len(subs) == 1 else f"{len(subs)} subscriptions")
    errors = [
        CsafError(
            ERROR_CODES["ok"],
            f"Azure identity ok; visible scope: {target}.",
            str(target),
            "csaf-assess --cloud azure --subscription " + (subscription or "<id>") + " --output-dir out",
            blocking=False,
        )
    ]
    sub_id = subscription or (subs[0] if len(subs) == 1 else None)
    if not sub_id:
        return errors
    sec_url = (
        f"https://management.azure.com/subscriptions/{sub_id}"
        "/providers/Microsoft.Security/pricings?api-version=2022-03-01"
    )
    sec = requests.get(sec_url, headers=headers, timeout=30)
    if sec.status_code in (401, 403):
        errors.append(
            CsafError(
                ERROR_CODES["permission"],
                f"ARM GET Defender pricing returned HTTP {sec.status_code}.",
                sec_url,
                "Grant Security Reader on the subscription in addition to Reader.\n"
                "         Playbook: csaf-assess --guide --cloud azure",
            )
        )
    else:
        errors.append(CsafError(ERROR_CODES["ok"], "Defender-for-Cloud read ok.", sec_url, "", blocking=False))
    for provider, api, label in _AZURE_ARM_PROBES:
        probe_url = f"https://management.azure.com/subscriptions/{sub_id}/providers/{provider}?api-version={api}"
        probe = requests.get(probe_url, headers=headers, timeout=30)
        resource = f"ARM GET {provider}"
        if probe.status_code in (401, 403):
            errors.append(
                CsafError(
                    ERROR_CODES["permission"],
                    f"ARM GET {provider} returned HTTP {probe.status_code}.",
                    probe_url,
                    "Grant Reader + Security Reader on the subscription.\n"
                    f"         Then: az rest --method get --url {probe_url}\n"
                    "         Playbook: csaf-assess --guide --cloud azure",
                )
            )
        elif probe.status_code == 404:
            errors.append(
                CsafError(ERROR_CODES["ok"], f"{label} not present (HTTP 404).", resource, "", blocking=False)
            )
        elif probe.status_code >= 400:
            errors.append(_http_status_error(probe.status_code, resource, probe_url, "azure"))
        else:
            errors.append(CsafError(ERROR_CODES["ok"], f"{label} read ok.", resource, "", blocking=False))
    return errors


def _probe_gcp(project: str | None) -> list[CsafError]:
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as exc:
        return [from_exception(exc, resource="google.auth", cloud="gcp")]
    try:
        credentials, default_project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    except Exception as extra_exc:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                f"GCP Application Default Credentials failed: {extra_exc}",
                "ADC",
                "gcloud auth application-default login\n"
                "         gcloud config set project PROJECT_ID\n"
                "         Playbook: csaf-assess --guide --cloud gcp",
            )
        ]
    project_id = project or default_project
    if not project_id:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                "No GCP project resolved.",
                "project",
                "csaf-assess --cloud gcp --project PROJECT_ID --preflight --live",
            )
        ]
    http = AuthorizedSession(credentials)
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
    response = http.get(url, timeout=30)
    if response.status_code in (401, 403):
        return [
            CsafError(
                ERROR_CODES["permission"],
                f"GET {url} returned HTTP {response.status_code}.",
                project_id,
                f"gcloud projects describe {project_id}\n"
                "         Grant roles/viewer on the project (Owner must do this).\n"
                "         Playbook: csaf-assess --guide --cloud gcp",
            )
        ]
    if response.status_code >= 400:
        return [
            CsafError(
                ERROR_CODES["api"],
                f"GET {url} returned HTTP {response.status_code}: {response.text[:200]}",
                project_id,
                f"gcloud projects describe {project_id}",
            )
        ]
    errors = [
        CsafError(
            ERROR_CODES["ok"],
            f"GCP identity ok for project {project_id}.",
            project_id,
            f"csaf-assess --cloud gcp --project {project_id} --output-dir out",
            blocking=False,
        )
    ]
    for name, method, template in _GCP_API_PROBES:
        probe_url = template.format(project=project_id)
        resource = f"{name} ({project_id})"
        try:
            if method == "POST":
                probe = http.post(probe_url, json={"options": {"requestedPolicyVersion": 3}}, timeout=30)
            else:
                probe = http.get(probe_url, timeout=30)
        except Exception as extra_exc:
            errors.append(from_exception(extra_exc, resource=resource, cloud="gcp"))
            continue
        if probe.status_code in (401, 403):
            errors.append(
                CsafError(
                    ERROR_CODES["permission"],
                    f"{method} {name} returned HTTP {probe.status_code}.",
                    resource,
                    f"gcloud projects describe {project_id}\n"
                    "         Grant roles/viewer on the project.\n"
                    "         Playbook: csaf-assess --guide --cloud gcp",
                )
            )
        elif probe.status_code == 404:
            errors.append(
                CsafError(ERROR_CODES["ok"], f"{name} not present (HTTP 404).", resource, "", blocking=False)
            )
        elif probe.status_code >= 400:
            errors.append(_http_status_error(probe.status_code, resource, probe_url, "gcp"))
        else:
            errors.append(CsafError(ERROR_CODES["ok"], f"{name} ok.", resource, "", blocking=False))
    return errors


def _probe_k8s(kubeconfig: str | None, context: str | None) -> list[CsafError]:
    try:
        from kubernetes import client, config
    except ImportError as extra_exc:
        return [from_exception(extra_exc, resource="kubernetes", cloud="k8s")]
    try:
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig, context=context)
        else:
            config.load_kube_config(context=context)
        version = client.VersionApi().get_code()
    except Exception as extra_exc:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                f"Kubernetes API access failed: {extra_exc}",
                context or kubeconfig or "current-context",
                "kubectl config current-context\n         kubectl get ns\n         Playbook: csaf-assess --guide --cloud k8s",
            )
        ]
    git_version = getattr(version, "git_version", "?")
    errors = [
        CsafError(
            ERROR_CODES["ok"],
            f"Kubernetes identity ok ({git_version}).",
            context or "current-context",
            "csaf-assess --cloud k8s --kube-context " + (context or "current-context") + " --output-dir out",
            blocking=False,
        )
    ]
    core = client.CoreV1Api()
    rbac = client.RbacAuthorizationV1Api()
    net = client.NetworkingV1Api()
    k8s_probes = (
        ("namespaces", lambda: core.list_namespace(limit=1)),
        ("pods", lambda: core.list_pod_for_all_namespaces(limit=1)),
        ("clusterroles", lambda: rbac.list_cluster_role()),
        ("networkpolicies", lambda: net.list_network_policy_for_all_namespaces(limit=1)),
    )
    for name, call in k8s_probes:
        try:
            call()
            errors.append(CsafError(ERROR_CODES["ok"], f"list {name} ok.", name, "", blocking=False))
        except Exception as extra_exc:
            errors.append(
                CsafError(
                    ERROR_CODES["permission"],
                    f"Kubernetes list {name} failed: {extra_exc}",
                    context or "current-context",
                    "Bind the built-in ClusterRole view (not cluster-admin).\n"
                    f"         Then: kubectl get {name}\n"
                    "         Playbook: csaf-assess --guide --cloud k8s",
                )
            )
    return errors
