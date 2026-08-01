# Contributing to CSAF

Thanks for helping improve the Cloud Security Assessment Framework. CSAF is a
**read-only** posture-assessment tool; keeping it read-only and evidence-based
is the single most important contribution guideline.

## Ground rules for a security tool

- **Never introduce a mutating cloud call.** All provider access must go through
  the read-only session guards (`ReadOnlyClient`, `ArmSession`, `GcpSession`,
  `K8sSession`). New AWS operations must be non-mutating; `tests/test_readonly*.py`
  enforces this and must stay green.
- **Errors are never a pass.** A check that cannot complete must return an
  `Error`/`NotTested` result, never `Pass`. See `csaf/clouds/base.py`.
- **Active validation stays gated.** Anything beyond read-only enumeration must
  run only under the `Validation`/`AdversarySimulation` profiles behind a signed
  engagement (`AssessmentModule.active_validation`).
- **No secrets in the repo, tests, or examples.** Use synthetic/fixture data.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-lock.txt
pip install --no-deps -e .
```

## Before you open a pull request

Run the same gates CI runs:

```bash
ruff check csaf tests invoke_assessment.py sign_engagement.py test_dependencies.py setup.py
ruff format --check csaf tests
python test_dependencies.py
python -m coverage run --source=csaf,invoke_assessment -m unittest discover -s tests
python -m coverage report --fail-under=90
python tests/validate_novice_guides.py
```

Coverage must stay at or above 90%. New behavior needs tests; new CLI options
must be documented in the README (a contract test enforces this).

**Windows note:** line endings are normalized to LF via `.gitattributes`. If you
cloned before that was in place, run `git add --renormalize .` once so local
tests and `ruff format --check` match CI.

## Adding a control or a module

Use the authoring tools so your catalog stays valid:

```bash
csaf-new-module --cloud aws --module myservice     # prints a module + catalog stub
csaf-lint-catalog path/to/control-catalog.json     # validates schema + module/check resolution
```

## Reporting security issues

Do **not** open a public issue for a vulnerability in CSAF itself. Follow
[`SECURITY.md`](SECURITY.md) (private vulnerability reporting).

## Pull request expectations

Fill in the pull-request template: describe the change, its safety scope
(does it touch cloud access, authorization, or release?), the tests you added,
and any documentation updates. Keep changes focused and backward-compatible
unless a breaking change is explicitly agreed.
