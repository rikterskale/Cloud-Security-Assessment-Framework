# Migration guide for the next CSAF release

This release hardens installation, authorization, configuration, and output
handling. Existing read-only `Assessment` runs remain supported, but automation
should account for the changes below.

## Output paths

`--output-dir PATH` now treats `PATH` as a parent. Each run writes to
`PATH/<UTC timestamp>-<random>/`. Use the final `Output written to ...` CLI line,
or the `RunResult.output_dir` value when calling Python, as the authoritative
artifact directory. Do not assume `PATH/manifest.json`.

## Active-profile authorization

`Validation` and `AdversarySimulation` now require all of the following:

1. `--engagement` points to a schema-valid engagement.
2. `--engagement-key-file` points to the nonempty HMAC key used to sign it.
3. `activeValidationApproved` is `true`.
4. Both window bounds exist and the current time is within them.
5. `authorizedAccounts` explicitly includes the target account, subscription,
   project, or Kubernetes context.
6. AWS engagements explicitly list every requested region in
   `authorizedRegions`.

Sign the finalized file after every approved edit:

```bash
python3 sign_engagement.py --engagement engagement.json --key-file engagement.key
```

If `authorizedSourceAddresses` is present, active local CLI runs fail closed
because CSAF cannot independently verify the outbound address. Enforce that
restriction at the network boundary or omit the field.

## Configuration schemas

Catalog, baseline, and engagement JSON is now validated before use. Remove
unknown fields, use `schemaVersion: "1.0"` when supplied, and correct invalid
types reported in the fatal error. Custom baseline threshold names remain
allowed, while built-in threshold names have strict types.

## Installed distributions and dependencies

The wheel now includes all default runtime JSON resources and embeds its source
revision during CI/release builds. Reproducible environments should install:

```bash
python3 -m pip install --require-hashes -r requirements-lock.txt
```

Release bundles include `SHA256SUMS`, `sbom.cdx.json`, and GitHub attestations.
