"""Guided, dependency-free entry point for a first assessment."""

from __future__ import annotations

WELCOME = """CSAF — read-only cloud security assessment

Start here:
  csaf-assess --start                  Guided demo or live assessment
  csaf-assess --self-check --open-report
                                      Offline demo; no cloud account needed
  csaf-assess --guide --cloud aws      Cloud identity and permissions setup
  csaf-assess --help                   All options for automation

Supports AWS, Azure, GCP, and Kubernetes. Reports stay on this computer.
No assessment has started. The demo uses synthetic data.
"""


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(f"{prompt}{suffix}: ").strip() or default


def _choice(prompt: str, choices: tuple[str, ...], default: str) -> str:
    while True:
        value = _ask(prompt, default).lower()
        if value in choices:
            return value
        print("Choose " + ", ".join(choices) + ".")


def configure_start(args) -> bool:
    """Update CLI arguments after a scope preview; false means cancelled.

    Only the Assessment profile is supported. The regular runner retains
    responsibility for authorization, credential probes, and report generation.
    No credentials are collected or persisted by this flow.
    """
    print("CSAF guided start\nPress Enter to accept a default. Ctrl+C cancels.\n")
    mode = _choice("Demo with synthetic data, or live assessment? (demo/live)", ("demo", "live"), "demo")
    args.cloud = _choice("Cloud (aws/azure/gcp/k8s)", ("aws", "azure", "gcp", "k8s"), args.cloud)
    args.self_check = mode == "demo"
    if mode == "live":
        print("Use an existing read-only identity. Run --guide --cloud " + args.cloud + " for setup instructions.")
        if args.cloud == "aws":
            args.aws_profile = _ask("AWS profile (blank uses the credential chain)", args.aws_profile or "") or None
            while True:
                regions = _ask("AWS regions, separated by spaces", " ".join(args.regions)).split()
                if regions and all(not region.startswith("-") for region in regions):
                    args.regions = list(dict.fromkeys(regions))
                    break
                print("Enter at least one AWS region, for example us-east-1.")
        elif args.cloud == "azure":
            args.subscription = _ask("Azure subscription ID (blank auto-discovers)", args.subscription or "") or None
        elif args.cloud == "gcp":
            args.project = _ask("GCP project ID (blank uses the ADC default)", args.project or "") or None
        else:
            args.kube_context = (
                _ask("Kubernetes context (blank uses current context)", args.kube_context or "") or None
            )
            args.kubeconfig = _ask("Kubeconfig path (blank uses standard locations)", args.kubeconfig or "") or None
    args.output_dir = _ask("Report directory", args.output_dir)
    from .preflight import plan_assessment

    plan = plan_assessment(args.cloud, args.profile, args.catalog, args.baseline)
    print(f"\nReady: {args.cloud.upper()} / {mode} / {plan['selectedControls']} controls")
    if mode == "live":
        target = {
            "aws": args.aws_profile,
            "azure": args.subscription,
            "gcp": args.project,
            "k8s": args.kube_context,
        }[args.cloud]
        print(f"Target: {target or 'current credentials / default target'}")
        if args.cloud == "aws":
            print("Regions: " + ", ".join(args.regions))
        if args.cloud == "k8s" and args.kubeconfig:
            print("Kubeconfig: " + args.kubeconfig)
        print("The runner will check cloud access before reading configuration.")
    else:
        print("Synthetic data only. No cloud calls. One intentionally untested control produces exit 2.")
    print("Reports: " + args.output_dir)
    if _choice("Start assessment? (yes/no)", ("yes", "no"), "yes") == "no":
        print("Cancelled. No assessment was started.")
        return False
    if not args.open_report:
        args.open_report = (
            _choice("Open the report in your browser afterward? (yes/no)", ("yes", "no"), "yes") == "yes"
        )
    return True
