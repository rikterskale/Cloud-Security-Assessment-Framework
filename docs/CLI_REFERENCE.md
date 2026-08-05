# CSAF CLI Reference

> Generated from `invoke_assessment.build_parser()`; run `python tools/generate_cli_reference.py` after changing CLI options.

| Option | Default | Help |
|---|---|---|
| `--cloud` | `aws` | Cloud provider to assess (default: aws). |
| `--profile` | `Assessment` | Authorization profile (default: Assessment). |
| `--regions` | `['us-east-1']` | Authorized regions for regional AWS controls (Azure/GCP controls are subscription/project scoped). |
| `--catalog` | `none` | Path to the control catalog (default: the selected cloud's catalog). |
| `--baseline` | `none` | Path to the baseline thresholds file (default: the selected cloud's CIS baseline). |
| `--engagement` | `none` | Path to the signed engagement authorization file (required for active profiles). |
| `--engagement-key-file` | `none` | Path to the shared-secret key used to verify the signed engagement; required for Validation/AdversarySimulation (see sign_engagement.py). |
| `--previous-findings` | `none` | Path to a prior run's findings.json to diff against (adds DeltaStatus and findings-resolved.json). |
| `--aws-profile` | `none` | Named AWS credentials profile to use (read-only). |
| `--subscription` | `none` | Azure subscription ID to assess (default: discovered if unambiguous). |
| `--project` | `none` | GCP project ID to assess (default: the ADC default project). |
| `--kube-context` | `none` | Kubeconfig context to assess (default: the kubeconfig's current-context). |
| `--kubeconfig` | `none` | Path to a kubeconfig file (default: the standard kubeconfig locations/KUBECONFIG env var). |
| `--max-workers` | `1` | AWS only: evaluate this many regions concurrently (default: 1, sequential). |
| `--output-dir` | `csaf-output` | Parent directory; each assessment is written to a unique run subdirectory. |
| `--export` | `[]` | Additionally write findings in interoperability formats (SARIF 2.1.0 and/or an OSCAL assessment-results subset). Additive; does not replace findings.json/csv. |
| `--attest-key-file` | `none` | Path to a shared-secret key; when given, write attestation.json signing the run manifest (verify later with csaf-attest verify). |
| `--log-level` | `INFO` |  |
| `--explain` | `none` | Print a control's intent, expected state, mappings, and remediation, then exit (offline; uses --cloud to pick the catalog). |
| `--check-only` | `False` | Preflight: validate the profile, engagement, scope, and catalog selection, then exit without contacting the cloud or writing reports (exit 0 if a run would be authorized, 1 otherwise). |
| `--preflight` | `False` | Check Python, dependencies, packaged resources, and output access without cloud calls or reports. |
| `--plan` | `False` | Print a deterministic no-network control and scope preview, then exit. |
| `--tutorial` | `False` | Run the safe offline fixture tutorial and verify its manifest. |
| `--cleanup-tutorial` | `False` | Remove only the tutorial output directory named by --output-dir after a tutorial run. |
| `--no-color` | `False` | Use plain terminal output without color or decorative styling. |
| `--color` | `False` | Force ANSI color when stdout is not a terminal. |
| `--completion` | `none` | Print shell completion generated from this command's argparse options, then exit. |
| `--output-format` | `text` | Format --preflight or --plan output (default: text). |
| `--self-check` | `False` | Run offline with synthetic data (no cloud calls). |
| `--version` | `==SUPPRESS==` | show program's version number and exit |

## Safe first steps

1. Run `python invoke_assessment.py --preflight`.
2. Run `python invoke_assessment.py --plan --cloud aws --profile Assessment`.
3. Run `python invoke_assessment.py --tutorial --output-dir tutorial-output`.
4. Remove only tutorial output with `--cleanup-tutorial --output-dir tutorial-output`.
5. Explore a control without cloud access: `python invoke_assessment.py --explain AWS-S3-001`.
