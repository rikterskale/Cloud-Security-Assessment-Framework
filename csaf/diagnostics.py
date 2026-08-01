"""Actionable diagnostics for common first-run failures (UX-ENH-001).

When an assessment aborts, a raw ``Fatal: <TypeError...>`` message helps nobody
who is running the tool for the first time. :func:`explain_exception` maps the
most common failure classes to a plain-language cause and the exact next step,
so the CLI can print guidance while keeping the full traceback available under
``--log-level DEBUG``. It is a pure function of the exception, so it is trivial
to test and adds no runtime dependency.
"""

from __future__ import annotations

# Optional provider dependency -> the extra that installs it.
_PROVIDER_EXTRAS = {
    "azure": "azure",
    "azure.identity": "azure",
    "google": "gcp",
    "google.auth": "gcp",
    "kubernetes": "k8s",
}

# Substrings that identify a credential/identity failure by exception name.
_CREDENTIAL_MARKERS = (
    "NoCredentials",
    "CredentialsError",
    "DefaultCredentialsError",
    "InvalidConfig",
    "TokenRetrieval",
    "ClientAuthentication",
    "Unauthorized",
)


def explain_exception(exc: BaseException) -> tuple[str, str]:
    """Return ``(summary, hint)`` for an exception.

    ``summary`` restates the failure in plain language; ``hint`` gives the exact
    next action. Both are safe to show a novice. Unknown failures fall back to a
    generic hint rather than pretending to diagnose.
    """
    name = type(exc).__name__
    message = str(exc)

    if isinstance(exc, ModuleNotFoundError | ImportError):
        missing = getattr(exc, "name", "") or ""
        top = missing.split(".")[0]
        extra = next((e for mod, e in _PROVIDER_EXTRAS.items() if missing == mod or top == mod.split(".")[0]), None)
        if extra:
            return (
                f"A dependency for the selected cloud is not installed ({missing}).",
                f"Install the provider extra, e.g.  pip install 'csaf[{extra}]'  "
                "(or install the locked dependencies: pip install --require-hashes -r requirements-lock.txt).",
            )
        return (
            f"A required dependency is not installed ({missing or 'unknown module'}).",
            "Install CSAF's dependencies:  pip install --require-hashes -r requirements-lock.txt",
        )

    if any(marker in name for marker in _CREDENTIAL_MARKERS) or "credential" in message.lower():
        return (
            "The cloud provider could not authenticate with read-only credentials.",
            "Configure read-only credentials first (e.g. an AWS profile with ReadOnlyAccess/SecurityAudit, "
            "Azure DefaultAzureCredential, GCP Application Default Credentials, or a kubeconfig), then retry. "
            "Tip: run with --self-check to confirm the tool works with no cloud at all.",
        )

    if isinstance(exc, FileNotFoundError):
        target = getattr(exc, "filename", None) or message
        return (
            f"A file the assessment needs was not found ({target}).",
            "Check the path you passed to --catalog / --baseline / --engagement / --engagement-key-file.",
        )

    if isinstance(exc, PermissionError):
        return (
            "CSAF could not write to the output directory.",
            "Choose a writable location with --output-dir, or fix the directory's permissions.",
        )

    if "engagement" in message.lower() or "signature" in message.lower():
        # Preserve the specific engagement error (it is already operator-readable)
        # and add guidance.
        return (
            message or "The engagement authorization could not be validated.",
            "Verify the engagement file and its signing key. Active profiles (Validation/AdversarySimulation) "
            "require a signed engagement; re-sign with csaf-sign-engagement if it was edited.",
        )

    return (
        f"{name}: {message}",
        "Re-run with --log-level DEBUG for the full traceback, or start with --self-check to verify the install.",
    )


def format_fatal(exc: BaseException) -> str:
    """Compose the one-line-plus-hint fatal message shown to the operator."""
    summary, hint = explain_exception(exc)
    return f"{summary}\n    → {hint}"
