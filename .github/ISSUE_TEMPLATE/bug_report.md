---
name: Bug report
about: Report incorrect behavior in CSAF (not a security vulnerability)
title: "[bug] "
labels: bug
---

<!--
SECURITY ISSUES: do not use this template. Report vulnerabilities in CSAF
itself privately per SECURITY.md (Security tab -> Report a vulnerability).
-->

## What happened

<!-- A clear description of the incorrect behavior. -->

## How to reproduce

Prefer a synthetic reproduction that needs no cloud credentials:

```bash
python3 invoke_assessment.py --self-check --output-dir out
```

Steps / exact command:

## Expected result

## Actual result

<!-- Include the exit code and, if helpful, run with --log-level DEBUG. -->

## Environment

- CSAF version (`python3 invoke_assessment.py --version`):
- OS and version:
- Python version:
- Cloud (aws / azure / gcp / k8s), if applicable:

## Evidence

<!-- Redacted logs or report snippets. Never paste real credentials or account data. -->
