# CSAF product readiness review

CSAF has a strong assessment engine, but vendor readiness depends on safe operation, accurate claims, repeatable installation, and a clear path from first use to verified remediation. This review targets security consultants and MSPs as the working audience. The immediate improvements address onboarding, report usefulness, evidence preservation, and resolution accuracy. Live-cloud certification and release validation remain outstanding.

Reviewed on 2026-09-30 against the local checkout. No live credentials or production environments were used. Existing release and platform documents describe their own historical evidence; they are not evidence of the current checkout passing in a real cloud.

## Findings and implemented changes

| Priority | Finding in the original checkout | Resulting behavior |
|---|---|---|
| High | Cloud-controlled CSV text was written directly into spreadsheet cells. | Potential formulas are prefixed with an apostrophe in assessment and aggregate CSV exports. JSON retains original values. |
| High | A finding absent from a later scan was labeled resolved without checking coverage or scope. | Resolution requires completed control evaluation in the same cloud, account, region, and control. Other disappearances remain unverified. Drift accepts matching technical-report evidence and includes unverified disappearances in `any` alerts. |
| High | Tutorial cleanup recursively removed the whole named output directory, potentially including client reports. | Cleanup validates tutorial ownership and synthetic context, rejects links in owned runs, and deletes only those children. Neighboring reports and the output directory survive. |
| Medium | Empty CLI invocation attempted the default AWS assessment. | Empty invocation displays a welcome and makes no assessment calls. `--start` offers a guided demo or live run; explicit options remain available for scripts. |
| Medium | Report search covered only the first 50 findings; the full list duplicated those rows outside the filter. | One searchable table contains every finding once. Empty filter results explain how to recover. |
| Medium | Report resource identifiers and remediation were truncated. | Full values are visible, and titles expand to show state, scope, confidence, mappings, and evidence references. |
| Medium | Reports required users to locate separate files and execution-gap reasons. | Artifact links and recorded gap reasons appear in the HTML report. `--open-report` opens completed reports or prints a usable path. |
| Medium | Demo and inventory output could be mistaken for real assessment conclusions. | Synthetic reports and inventory mode have explicit banners. Risk explains its direction. Unevaluated compliance is labeled, and compliance rates are scoped to evaluated controls. |

The tutorial ownership marker is a local cleanup aid, not a cryptographic proof. Existing integrity manifests and optional HMAC attestations retain their distinct roles. Resolution evidence depends on collectors truthfully reporting execution completeness; live validation must test that assumption.

## Architecture strengths

The project already separates collection, control evaluation, findings, coverage, and evidence. `NotTested` and `Error` remain separate from security passes. Provider sessions enforce read-only operations, optional provider dependencies load lazily, packaged resources have drift checks, and tests cover negative fixtures and report escaping. CI defines lint, dependency auditing, packaging, cross-platform tests, and a coverage threshold. These are useful foundations for a supported product.

The product is currently a local Python CLI with offline reports. A hosted portal, tenancy service, or browser application would add a new operating and security model. It should follow a deliberate product decision and real workflow validation.

## Remaining release criteria

These are acceptance criteria for calling a release vendor ready, not claims that the checks have already passed.

| Area | Required next work | Acceptance evidence |
|---|---|---|
| Live assessment accuracy | Validate every shipped control against authorized disposable AWS, Azure, GCP, and Kubernetes fixtures. Exercise pagination, denied access, partial results, and empty inventories. Review framework mappings against the labeled benchmark editions. | Reproducible fixture definitions and results for positive, negative, and permission-denied cases; no missing collection silently becomes a pass. |
| Multi-client operation | Review campaign and multi-scope summaries. `_run_multi_scope` currently returns the final child's coverage and risk in its CLI summary while combining finding counts. Add a consistent aggregate landing report and bounded target handling. | Several scopes with deliberately different risk and coverage produce accurate totals, usable report links, and isolated output. Invalid target identifiers cannot redirect output paths. |
| Installation | Exercise the generated wheel and source distribution on clean supported Windows, Linux, and macOS environments, including spaces in paths, restricted output access, and core installs without SDKs. Review the cost of installing every provider for a first demo. | A novice completes the documented install and obtains a report without extra dependency troubleshooting. Missing optional SDKs identify the exact installation command. |
| Large environments | Measure collection and rendering with representative account sizes, API throttling, and long-running collectors. Add bounds and cancellation where measurements identify a problem. | Published test sizes, elapsed time and memory, actionable progress, predictable cancellation, and preserved diagnostics. |
| Evidence handling | Validate retention, permissions, signed bundle verification, and sharing of complete run directories. Explain limits of hashes and shared-secret attestations. | Unauthorized destinations receive no evidence automatically; copied bundles verify; users can apply their required storage and retention policy. |
| Accessibility | Validate report keyboard navigation, narrow layouts, print output, contrast, and screen-reader announcements across supported browsers. | Recorded browser matrix and manual keyboard review, plus repeatable checks for search beyond 50 findings and complete remediation text. |
| Release and support | Run all CI gates on the exact proposed release commit, refresh platform snapshots, verify provenance, and publish support and compatibility commitments. | A release-specific evidence record, signed artifacts, supported-platform matrix, and documented issue escalation. |

## Local verification

Before changes, all 637 repository tests passed. After the improvements and safety fixes, the suite passed 664 tests with 91% statement coverage, exceeding the existing 90% threshold. Ruff lint and formatting checks passed, packaged resources matched source resources, installed dependencies passed `pip check`, and wheel and source distribution builds passed metadata validation. Generated CLI documentation and completion files were refreshed.

Offline runs for AWS, Azure, GCP, and Kubernetes each produced the expected incomplete-demo exit code and passed independent checks of all 13 recorded artifact hashes. Browser checks on the generated AWS demo confirmed expandable finding details, severity filtering, live counts, and a no-match recovery state. A 75-finding browser fixture verified that searching for the final resource returns exactly one match. HTML escaping and spreadsheet formula handling have regression coverage. Tutorial cleanup tests exercise preservation of neighboring evidence, unmarked demos, rejection of forged ownership on a live report, and rejection of tampered tutorial artifacts. Resolution tests cover incomplete controls, changed target scope, and stale technical evidence.

The local environment does not have `mypy`, so type checking was not verified here. Cross-platform CI, dependency vulnerability auditing, fresh-machine installation, and live-cloud execution still need release evidence. A successful build does not substitute for those checks.

## User acceptance path

1. Install from the supported distribution or documented source installer.
2. Invoke `csaf-assess` and understand how to begin without triggering a cloud scan.
3. Run `csaf-assess --start`, accept the demo defaults, and open a visibly synthetic report.
4. Use `--guide --cloud <cloud>` to configure an existing read-only identity, then choose a live guided assessment and review its target and scope.
5. Identify the first Critical or High issue, read complete remediation and evidence, and understand every reported coverage gap.
6. Rerun in the same scope after remediation. A missing finding becomes resolved only when that control completed; missing coverage remains unverified.
7. Share the complete evidence directory with an authorized client reviewer and verify its manifest or signed attestation as required.

Measure completion and observed confusion with representative users before describing this workflow as having zero friction. Cloud authentication and authorization remain necessary parts of a trustworthy assessment.
