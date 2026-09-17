"""Structured operator errors: cause, affected resource, exact fix command.

Every user-facing failure should be a :class:`CsafError`. Unknown exceptions
are wrapped, never swallowed. Cloud probes in :func:`probe_cloud_access` are
read-only (STS GetCallerIdentity, ARM GET, GCP GET, Kubernetes read).
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


def from_exception(exc: BaseException, *, resource: str = "") -> CsafError:
    """Map an exception to a structured error. Never invent a mutating fix."""
    name = type(exc).__name__
    message = str(exc)
    target = resource or getattr(exc, "filename", None) or name

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
        return CsafError(
            ERROR_CODES["credentials"],
            "The cloud provider could not authenticate with the configured identity.",
            str(target),
            "AWS: aws sts get-caller-identity --profile YOUR_PROFILE\n"
            "         Azure: az login\n"
            "         GCP: gcloud auth application-default login\n"
            "         Kubernetes: kubectl config current-context\n"
            "         Then: csaf-assess --preflight --live --cloud CLOUD\n"
            "         Setup playbook: csaf-assess --guide --cloud CLOUD\n"
            "         Tip: run with --self-check to confirm the tool works with no cloud at all.",
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
    if aws_code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"} or "AccessDenied" in message:
        return CsafError(
            ERROR_CODES["permission"],
            f"Read API denied ({aws_code or name}): {message}",
            str(target),
            "Attach the AWS managed policy arn:aws:iam::aws:policy/SecurityAudit to this principal "
            "(or Azure Reader + Security Reader / GCP roles/viewer / Kubernetes view), "
            "then: csaf-assess --preflight --live",
        )

    return CsafError(
        ERROR_CODES["unknown"],
        f"{name}: {message}",
        str(target) or "runner",
        "csaf-assess --log-level DEBUG --self-check --output-dir out",
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
        return [from_exception(exc, resource=cloud)]


def _probe_aws(profile: str | None) -> list[CsafError]:
    errors: list[CsafError] = []
    try:
        import boto3
    except ImportError as exc:
        return [from_exception(exc, resource="boto3")]
    session = boto3.Session(profile_name=profile)
    sts = session.client("sts")
    try:
        ident = sts.get_caller_identity()
    except Exception as exc:
        fix_profile = profile or "default"
        err = from_exception(exc, resource=f"sts:GetCallerIdentity (profile {fix_profile})")
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
    try:
        session.client("iam").get_account_summary()
    except Exception as exc:
        errors.append(
            CsafError(
                ERROR_CODES["permission"],
                f"Authenticated as {arn} but iam:GetAccountSummary was denied ({exc}).",
                f"iam:GetAccountSummary (account {account})",
                "aws iam simulate-principal-policy --policy-source-arn "
                f"{arn} --action-names iam:GetAccountSummary iam:GenerateCredentialReport "
                "iam:ListUsers s3:ListAllMyBuckets\n"
                "         Then attach arn:aws:iam::aws:policy/SecurityAudit to this principal.",
            )
        )
    if not errors:
        errors.append(
            CsafError(
                ERROR_CODES["ok"],
                f"AWS identity ok: {arn} (account {account}).",
                arn,
                "csaf-assess --cloud aws --aws-profile "
                + (profile or "default")
                + " --regions us-east-1 --output-dir out",
                blocking=False,
            )
        )
    return errors


def _probe_azure(subscription: str | None) -> list[CsafError]:
    try:
        import requests
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        return [from_exception(exc, resource="azure.identity")]
    try:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default")
    except Exception as exc:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                f"Azure DefaultAzureCredential failed: {exc}",
                "https://management.azure.com/.default",
                "az login\n         Then: az account show",
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
                "az role assignment create --assignee $(az ad signed-in-user show --query id -o tsv) "
                "--role Reader --scope /subscriptions/SUBSCRIPTION_ID",
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
    return [
        CsafError(
            ERROR_CODES["ok"],
            f"Azure identity ok; visible scope: {target}.",
            str(target),
            "csaf-assess --cloud azure --subscription " + (subscription or "<id>") + " --output-dir out",
            blocking=False,
        )
    ]


def _probe_gcp(project: str | None) -> list[CsafError]:
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as exc:
        return [from_exception(exc, resource="google.auth")]
    try:
        credentials, default_project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    except Exception as exc:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                f"GCP Application Default Credentials failed: {exc}",
                "ADC",
                "gcloud auth application-default login\n         gcloud config set project PROJECT_ID",
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
                f"gcloud projects add-iam-policy-binding {project_id} "
                "--member=user:YOU@example.com --role=roles/viewer",
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
    return [
        CsafError(
            ERROR_CODES["ok"],
            f"GCP identity ok for project {project_id}.",
            project_id,
            f"csaf-assess --cloud gcp --project {project_id} --output-dir out",
            blocking=False,
        )
    ]


def _probe_k8s(kubeconfig: str | None, context: str | None) -> list[CsafError]:
    try:
        from kubernetes import client, config
    except ImportError as exc:
        return [from_exception(exc, resource="kubernetes")]
    try:
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig, context=context)
        else:
            config.load_kube_config(context=context)
        version = client.VersionApi().get_code()
    except Exception as exc:
        return [
            CsafError(
                ERROR_CODES["credentials"],
                f"Kubernetes API access failed: {exc}",
                context or kubeconfig or "current-context",
                "kubectl config current-context\n         kubectl get ns",
            )
        ]
    git_version = getattr(version, "git_version", "?")
    return [
        CsafError(
            ERROR_CODES["ok"],
            f"Kubernetes identity ok ({git_version}).",
            context or "current-context",
            "csaf-assess --cloud k8s --kube-context " + (context or "current-context") + " --output-dir out",
            blocking=False,
        )
    ]
