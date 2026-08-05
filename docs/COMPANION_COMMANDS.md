# CSAF Companion Command Reference

This reference covers the console commands installed alongside `csaf-assess`.
Unless noted, they process local files only and do not contact a cloud provider.

## Engagement signing

`csaf-sign-engagement --engagement engagement.json --key-file engagement.key`

Signs an engagement JSON file with the shared secret in `--key-file`. It
overwrites `--engagement` unless `--output signed-engagement.json` is supplied.
Use `--verify-only` to verify an existing signature without writing. A missing
or empty key, unreadable input, or failed verification exits non-zero.

## Catalog authoring

`csaf-lint-catalog path/to/control-catalog.json [--cloud aws] [--no-registry] [--strict]`

Validates one or more catalog files against the schema, semantic rules, and,
by default, module/check resolution. `--cloud` overrides the cloud used for
module resolution. `--no-registry` skips that resolution check. The command
exits non-zero for errors and also for warnings when `--strict` is used.

`csaf-new-module --cloud aws --module eventbridge [--check check_example]`

Prints, but does not write, an assessment-module scaffold, catalog entry, and
the registry line needed to wire in the new module.

## Evidence and reporting

`csaf-attest sign RUN_DIR --key-file KEY_FILE`

Writes `attestation.json` over a completed run's `manifest.json`. Verify the
bundle and every artifact hash with:

`csaf-attest verify RUN_DIR --key-file KEY_FILE`

Verification exits non-zero if the attestation or any artifact hash fails.

`csaf-attest external-sign RUN_DIR [--cosign cosign]`

Writes `run-sbom.cdx.json`, an evidence descriptor, and a keyless Cosign
signature/bundle. This is opt-in and may use Sigstore only when invoked.
Third parties verify without the HMAC key:

`csaf-attest external-verify RUN_DIR --certificate-identity ID --certificate-oidc-issuer ISSUER`

`csaf-drift --previous OLD/findings.json --current NEW/findings.json [--alert-on new|resolved|any|none] [--out drift.json] [--quiet]`

Add `--history drift-history.jsonl` to append a timestamped time-series record.
An explicit SIEM webhook supports HMAC (default) or bearer authentication:
`--webhook-url URL --webhook-secret-file SECRET [--webhook-auth hmac|bearer]`.
Use `--webhook-dry-run` to inspect redacted delivery metadata without a network call.

Compares two finding sets and prints counts for new, resolved, and persisted
findings. It optionally writes the JSON report specified by `--out`. The
default `--alert-on new` exits non-zero when a new finding is present;
`resolved`, `any`, and `none` select the corresponding alert policy.

`csaf-aggregate RUN_DIR [RUN_DIR ...] --out aggregate-output`

Reads `findings.json` from each completed run directory and writes
`aggregate.json` and `aggregate.csv` into `--out`, including controls failing
across more than one scope.

`csaf-detection-pack RUN_DIR [--out detection-pack.json] [--no-markers]`

Builds `detection-pack.json` from a completed run's
`detection-coverage.json`; without `--out`, it writes inside `RUN_DIR`.
`--no-markers` omits benign validation markers.

`csaf-attack-path IAM_SNAPSHOT.json [--out attack-path.json] [--fail-on-path]`

Analyzes a supplied IAM snapshot without cloud calls and prints discovered
privilege-escalation paths. `--out` writes the JSON report. With
`--fail-on-path`, the command exits non-zero when at least one path is found.

## Assessment campaigns

`csaf-campaign create campaign.json --campaign-id ID [--cloud aws] [--profile Assessment] [--regions us-east-1] [--description TEXT] [--self-check] [--export sarif|oscal ...] [--key-file KEY_FILE]`

Creates a replayable campaign. `--key-file` signs it at creation time; signing
is optional. `--self-check` records an offline run, while a campaign without
it can assess the selected cloud when run.

`csaf-campaign sign campaign.json --key-file KEY_FILE` signs an existing
campaign in place. `csaf-campaign verify campaign.json --key-file KEY_FILE`
verifies its signature and exits non-zero on failure.

`csaf-campaign run campaign.json [--key-file KEY_FILE] [--output-dir csaf-output] [--log-level INFO] [--previous-findings PATH]`

Runs the assessment stored in the campaign. If `--key-file` is provided, a
bad campaign signature prevents execution. If a signed campaign is run without
`--key-file`, CSAF warns and runs without verifying that signature. This is the
only companion command that can contact a cloud provider; it follows the same
read-only guardrails and authorization requirements as `csaf-assess`.
