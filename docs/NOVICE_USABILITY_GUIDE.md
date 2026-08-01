# CSAF Novice Usability Guide

| Field | Value |
|---|---|
| Project | Cloud Security Assessment Framework (CSAF) |
| Guide purpose | Beginner installation, first use, verification, recovery, and common operations |
| Guide status | `PARTIALLY VERIFIED` |
| Reviewed branch | `main` |
| Reviewed commit | `9d08815` |
| Detected project version | `1.0.0` (`pyproject.toml`, `csaf/__init__.py`; `csaf-assess --version` prints `CSAF v1.0.0`) |
| Last verified | 2026-08-01 |
| Verified platforms | Linux (Ubuntu 22.04, Python 3.10.12) — install + offline first run executed live |
| Validation limitations | Windows/macOS commands are statically verified (behavior identical because CSAF is pure Python); real-cloud (AWS/Azure/GCP/K8s) assessments require your own read-only credentials and were not exercised |

> **New to the terminal on Windows or Linux specifically?** This guide is cross-platform. For step-by-step, OS-specific instructions (which terminal to open, how to install Python), see the platform guides: [Windows](guides/WINDOWS_NOVICE_USABILITY_GUIDE.md) · [Linux](guides/LINUX_NOVICE_USABILITY_GUIDE.md). This guide gets you to a first success on any of Linux, macOS, or Windows.

---

## 1. What This Guide Helps You Do

By the end you will have installed CSAF, run a safe **offline** security assessment that needs no cloud account, read the results, recovered from a common error, and learned how to clean up, update, and uninstall.

## 2. Who This Guide Is For

Anyone trying CSAF for the first time — security assessors, cloud administrators, auditors, or students. No prior experience with Git, Python, or the terminal is assumed. Technical terms are defined in the **Glossary** (section 29).

## 3. What the Project Does

CSAF inspects the **configuration** of a cloud account (AWS, Azure, GCP, or Kubernetes) and reports where it does not meet a security baseline (CIS benchmarks). It loads a declarative control catalog, evaluates each control read-only, and writes findings, coverage, and reports. `Confirmed — csaf/__init__.py; csaf/runner.py`.

## 4. What the Project Does Not Do

- It does **not** create, modify, or delete cloud resources — mutating API calls are blocked in code (`csaf/clouds/*/session.py`).
- It does **not** perform exploitation or attacks.
- It is **not** a real-time monitor; each run is a point-in-time snapshot.
- It does **not** fix findings for you; it reports them with remediation guidance.

## 5. Important Safety, Cost, Data, or Authorization Notes

- The **offline demo** in this guide (`--self-check`) uses synthetic data: no cloud account, no credentials, no internet, no cost.
- Assess a real cloud only with **written authorization** and **read-only** credentials.
- Report files may describe real security weaknesses — treat the output folder as **sensitive** and do not commit it to Git (the repo's `.gitignore` already excludes `out/` and `csaf-output/`).
- CSAF never asks you to disable antivirus, a firewall, or certificate checking.

## 6. Before You Begin

| Requirement | Needed | How to check |
|---|---|---|
| Python | 3.10–3.14 | `python3 --version` (Windows: `python --version`) |
| Git (or a ZIP download) | any recent | `git --version` |
| Disk space | ~500 MB | — |
| Internet | for download + dependency install only (the demo itself is offline) | — |

No administrator/root access is required to run CSAF. Installing Python or Git may prompt for elevation once.

## 7. Basic Terms Explained

Brief definitions (full list in section 29): a **terminal** is the app where you type commands; a **command** is an instruction you run; the **working directory** is the folder your commands act in (change it with `cd`); a **virtual environment** (`.venv`) is an isolated Python folder for this project; an **exit code** is a number a command returns (0 = success).

## 8. Choose the Correct Setup Path

Use the **source checkout + virtual environment** path in this guide. It is the method the project documents and tests. There is no separate installer or container image. This is the recommended novice path because it needs only Python and Git and works identically on Linux, macOS, and Windows.

## 9. Obtain or Clone the Repository

**Objective:** download CSAF to your computer.
**Where to run:** your terminal, in your home folder. **Placeholder:** replace `<REPO_URL>` with `https://github.com/rikterskale/Cloud-Security-Assessment-Framework.git`.

```bash
git clone <REPO_URL>
```

No Git? Download the ZIP from the repository's GitHub page (green **Code** button → **Download ZIP**) and extract it.

**Verify:** a new folder `Cloud-Security-Assessment-Framework` now exists (`ls` on Linux/macOS, `dir` on Windows).

## 10. Enter the Correct Project Folder

Run every remaining command **inside** this folder.

```bash
cd Cloud-Security-Assessment-Framework
```

**Verify:** `ls` (Linux/macOS) or `dir` (Windows) shows `invoke_assessment.py`, `README.md`, and a `csaf` folder.

## 11. Install Required Software

Install **Python 3.10+** and **Git** if `python3 --version` / `git --version` failed in section 6.

- **Linux (Debian/Ubuntu):** `sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip git`
- **macOS (Homebrew):** `brew install python git`
- **Windows:** `winget install --id Python.Python.3.12 -e; winget install --id Git.Git -e`, then reopen your terminal.

**Verify:** re-run `python3 --version` (Windows: `python --version`) and confirm it prints `Python 3.10`–`3.14`.

## 12. Install Project Dependencies

Create and activate an isolated environment, then install the exact, security-pinned dependencies.

**Linux/macOS (bash):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements-lock.txt
pip install --no-deps .
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-lock.txt
pip install --no-deps .
```

**What this does:** `.venv` is a private Python folder for this project; `--require-hashes` refuses any package whose contents don't match the recorded checksum (a safety feature — do not remove it); `pip install --no-deps .` installs CSAF's commands.

#### Verify the Step

```bash
python3 test_dependencies.py
```

**Successful result:**

```text
(no error output; the command exits 0)
```

#### If Verification Fails

**Symptom or error:**

```text
ModuleNotFoundError: No module named 'jsonschema'
```

**Likely cause:** the virtual environment is not active, or dependencies were not installed.
**Confirm the cause:** your prompt should show `(.venv)`. If not, the environment is inactive.
**Fix the problem:**

```bash
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-lock.txt
```

**Expected result after the fix:** `python3 test_dependencies.py` exits with no error.
**Run the verification again:** `python3 test_dependencies.py`.

## 13. Configure the Minimum Required Settings

**Not applicable for the first run.** The offline demo needs no configuration file, credentials, or environment variables. Real cloud assessments use your existing cloud credentials (section 18); CSAF reads them through the standard cloud SDKs.

## 14. Protect Passwords, Tokens, and Other Secrets

The offline demo uses **no secrets**. For real assessments:

- Supply cloud credentials through your cloud's normal mechanism (an AWS named profile, Azure `DefaultAzureCredential`, GCP Application Default Credentials, or a kubeconfig) — **never** hard-code them.
- Active-validation profiles use a signing key file passed with `--engagement-key-file <PATH>`; keep that key out of Git.
- The `.gitignore` already excludes output folders (`out/`, `csaf-output/`) so generated reports aren't committed.

## 15. Run the Safest First Example

This is the offline demo: synthetic data, no cloud, no internet.

**Working directory:** the repository folder, with `.venv` active.

```bash
python3 invoke_assessment.py --self-check --output-dir out
```

**What this does:** runs a complete assessment against built-in synthetic data and writes a full set of reports into `out/`.

## 16. Verify the First Run Succeeded

**Expected result** (`Your values will differ` for the run ID):

```text
[INCOMPLETE] Completed. 5 findings, risk 70.0/100 (CRITICAL). Coverage 29/30 executed.
    (exit 2: completed, but some controls were NotTested or errored (e.g. a missing attestation))
Risk: 70.0/100 (CRITICAL)
Findings by severity: CRITICAL 2, HIGH 3, MEDIUM 0, LOW 0
Coverage: 29/30 executed, 1 not tested, 0 errored
[*] Output written to out/20260801T212209Z-75e00064
```

**Success indicator:** the line `Completed. 5 findings ...` and an `[*] Output written to out/<run-id>` line. The word `[INCOMPLETE]` and **exit code 2** are expected here — one demo control is intentionally left "not tested," which is normal, not a failure.

#### Verify the Step

List the generated reports:

```bash
ls out/*/          # Windows PowerShell: Get-ChildItem out\*\
```

**Successful result:** you see `findings.json`, `findings.csv`, `technical-report.json`, `executive-summary.html`, `manifest.json`, and others (section 20).

## 17. If Verification Fails: Diagnose and Fix It

Work through causes from most likely to least likely; **stop as soon as one fix works.**

**Symptom or error:**

```text
Fatal: A required dependency is not installed (jsonschema).
    → Install CSAF's dependencies:  pip install --require-hashes -r requirements-lock.txt
```

**Likely cause (1):** dependencies not installed / venv inactive. **Fix:** section 12's activate + install commands, then re-run section 15. CSAF prints the exact fix in the error itself (a guided-error feature).

**Symptom or error:**

```text
python3: command not found      (Windows: 'python' is not recognized)
```

**Likely cause (2):** Python isn't installed or isn't on your PATH. **Confirm:** `python3 --version` fails. **Fix:** section 11, then reopen the terminal.

**Symptom or error:**

```text
[FATAL] Fatal: CSAF could not write to the output directory.
    → Choose a writable location with --output-dir, or fix the directory's permissions.
```

**Likely cause (3):** the output path isn't writable. **Fix:** pick a writable folder, e.g. `--output-dir "$HOME/csaf-out"`.

If none of these apply, re-run with more detail and preserve the output:

```bash
python3 invoke_assessment.py --self-check --output-dir out --log-level DEBUG
```

If the run still fails with a traceback you cannot resolve, this is `BLOCKED`: keep the full DEBUG output and open an issue (section 27). Distinguish an environment problem (missing Python/dependency) from a possible source-code defect (an unexpected traceback with all dependencies installed) — report the latter with the exact command and output.

## 18. Common Tasks

- **Explain a control offline** (no cloud needed):

  ```bash
  python3 invoke_assessment.py --explain CSAF-AWS-IAM-001
  ```

- **Preflight before a real run** (validate profile/scope/engagement without contacting the cloud):

  ```bash
  python3 invoke_assessment.py --check-only --profile Assessment --regions us-east-1
  ```

- **Assess a real AWS account (read-only).** Replace `<AWS_PROFILE>` with a read-only AWS profile you configured (example: `audit`):

  ```bash
  python3 invoke_assessment.py --profile Assessment --regions us-east-1 --aws-profile <AWS_PROFILE> --output-dir out
  ```

- **Export findings for other tools:** add `--export sarif oscal` to any run.
- **Compare against a previous run:** add `--previous-findings out/<OLD_RUN>/findings.json`.

## 19. Command and Option Basics

`csaf-assess` (a.k.a. `python3 invoke_assessment.py`) is the main command. Key options: `--cloud {aws,azure,gcp,k8s}`, `--profile {Inventory,Assessment,Validation,AdversarySimulation}`, `--self-check`, `--output-dir`, `--explain <CONTROL_ID>`, `--check-only`, `--export {sarif,oscal}`, `--log-level {DEBUG,INFO,WARN,ERROR}`, `--version`, `--help`. Run `python3 invoke_assessment.py --help` for the full list (it also prints an exit-code cheat sheet). The full command reference is in the [README CLI reference](../README.md#cli-reference). The package also installs companion commands: `csaf-sign-engagement`, `csaf-lint-catalog`, `csaf-new-module`, `csaf-attest`, `csaf-campaign`, `csaf-drift`, `csaf-aggregate`, `csaf-detection-pack`, `csaf-attack-path` — all documented in the README.

## 20. Where Results, Logs, and Generated Files Are Stored

Each run creates one immutable subfolder under your `--output-dir` (default `csaf-output/`), named `<timestamp>-<random>`. It contains:

| File | What it is |
|---|---|
| `findings.json` / `findings.csv` | Security findings (the main result) |
| `technical-report.json` | Full machine-readable report |
| `executive-summary.html` | Human-readable summary — open in a browser |
| `control-results.jsonl` / `.csv` | One record per evaluated control |
| `coverage-report.json` / `.csv` | How many controls executed |
| `detection-coverage.json` / `.csv` | MITRE technique coverage |
| `remediation-roadmap.csv` | Prioritized fixes |
| `manifest.json` | SHA-256 checksum of every file (integrity) |
| `assessment-<run>.log` / `.jsonl` | Run logs |
| `evidence/` | Collected raw evidence |

## 21. How to Stop the Project or Running Services

CSAF runs and exits; it starts no background services or network listeners. To stop a run in progress, press **Ctrl + C** in the terminal. Because CSAF is read-only, cancelling cannot damage your cloud.

## 22. Cleanup and Rollback

- **Delete generated reports:** `rm -rf out` (Windows PowerShell: `Remove-Item -Recurse -Force out`).
- **Remove the environment:** `deactivate` then `rm -rf .venv` (Windows: `Remove-Item -Recurse -Force .venv`).
- CSAF writes nothing outside the repository folder and `.venv`, so deleting those fully restores your system.

## 23. Update or Upgrade the Project

```bash
git pull
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-lock.txt
pip install --no-deps .
```

**Rollback:** a published release is not yet tagged; to return to a known-good version use `git checkout <COMMIT>` (example: `git checkout 9d08815`). When a `v1.0.0` tag is published, `git checkout v1.0.0` will be the supported rollback.

## 24. Uninstall the Project

```bash
pip uninstall csaf
deactivate
cd ..
rm -rf Cloud-Security-Assessment-Framework   # Windows: Remove-Item -Recurse -Force Cloud-Security-Assessment-Framework
```

## 25. Troubleshooting Matrix

| Symptom or Exact Error | Most Likely Cause | Confirm the Cause | Exact Fix | Verify the Fix |
|---|---|---|---|---|
| `No module named 'jsonschema'` | venv inactive or deps not installed | prompt lacks `(.venv)` | `source .venv/bin/activate` then `pip install --require-hashes -r requirements-lock.txt` | `python3 test_dependencies.py` (no error) |
| `python3: command not found` (Win: not recognized) | Python not installed / not on PATH | `python3 --version` fails | install Python (section 11), reopen terminal | `python3 --version` prints 3.10–3.14 |
| `Activate.ps1 cannot be loaded ... not digitally signed` (Windows) | PowerShell execution policy | occurs on `.venv\Scripts\Activate.ps1` | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` (safe, scoped) | re-run the activate command |
| Run prints `[INCOMPLETE]` / exit 2 | expected in the demo (1 control NotTested) | message says "Coverage 29/30" | none — this is success | `ls out/*/` shows reports |
| `Fatal: Unauthorized profile: ...` | used `Validation`/`AdversarySimulation` without a signed engagement | you passed `--profile Validation` | use `--profile Assessment` (read-only) | run completes with exit 0/2 |
| `Fatal: ... could not write to the output directory` | output path not writable | `--output-dir` points somewhere read-only | use a writable `--output-dir` | run completes |
| `pip: command not found` | pip missing | `pip --version` fails | install `python3-pip` (section 11) | `pip --version` works |

*Representative errors are drawn from the guided-error messages in `csaf/diagnostics.py` and the runner's authorization checks.*

## 26. Known Limitations and Unsupported Scenarios

- **Real-cloud runs were not exercised in this review** — they need your own read-only credentials.
- **No published release yet:** version `1.0.0` is declared but not tagged/released on GitHub, so a `pip install csaf` from a package index is not available; install from source as above.
- **Windows/macOS commands are statically verified** (the offline run was verified live on Linux; behavior is identical because CSAF is pure Python).
- **`--max-workers` is AWS-only** by design (see README "Concurrency model").

## 27. Collect Diagnostic Information and Report a Problem

1. Re-run the failing command with `--log-level DEBUG`.
2. Note your OS, `python3 --version`, and `python3 invoke_assessment.py --version`.
3. Include the exact command and the redacted output (never paste real credentials or account data).
4. Open a bug report using the repository's issue template. **Security vulnerabilities in CSAF itself** go through private reporting per [`SECURITY.md`](../SECURITY.md), **not** a public issue.

## 28. Where to Learn More

- [README](../README.md) — overview, full CLI reference, output artifacts, safety model. *Follow this for the complete option list.*
- [Windows](guides/WINDOWS_NOVICE_USABILITY_GUIDE.md) / [Linux](guides/LINUX_NOVICE_USABILITY_GUIDE.md) platform guides — per-OS terminal and install detail.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — set up for development and run the test suite.
- [SECURITY.md](../SECURITY.md) — report a vulnerability privately.

## 29. Glossary

- **Repository:** a folder of project files tracked by Git; here, the CSAF download.
- **Clone:** download a repository with Git.
- **Terminal:** the application where you type commands.
- **Shell:** the program inside the terminal that runs commands (bash, zsh, or PowerShell).
- **Command:** an instruction you type and run.
- **Working directory / current directory:** the folder your commands act in; change it with `cd`.
- **Runtime:** the language engine that runs CSAF (Python).
- **Dependency:** another package CSAF needs (e.g. `boto3`).
- **Package manager:** installs packages (`pip` for Python; `apt`/`brew`/`winget` for the OS).
- **Virtual environment:** an isolated Python folder (`.venv`) for this project.
- **Container:** a packaged, isolated runtime; CSAF does not require one.
- **Environment variable:** a named value the system passes to programs (e.g. `KUBECONFIG`).
- **Configuration file:** a file of settings; not needed for the demo.
- **Standard output / standard error:** normal messages vs. error messages a program prints.
- **Exit code:** a number a command returns; `0` success, `2` completed-with-untested-controls, `1` fatal.
- **Control:** one security check. **Baseline:** the set of expected values. **Finding:** a control that did not meet the baseline.
- **Profile:** an authorization level — `Inventory`/`Assessment` are read-only; `Validation`/`AdversarySimulation` add non-destructive active checks behind a signed engagement.
