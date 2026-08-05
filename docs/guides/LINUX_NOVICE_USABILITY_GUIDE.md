---
guide_id: linux-novice-usability
guide_schema_version: 1
platform: linux
canonical_path: docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md
project_name: Cloud Security Assessment Framework (CSAF)
target_release: "latest locally verifiable version: 1.0.0 (untagged, commit a5771ab)"
target_commit: a5771ab3a31dd660a6d0da3dd6bbc97ce63050a9
support_status: native_supported
alternative_support_paths: []
validation_status: partially_verified
validated_on: 2026-08-01
validated_environments:
  - os: Ubuntu
    version: "22.04"
    architecture: x86_64
    shell: bash
    runtime: Python 3.10.12
    privilege: standard user (sudo only for OS package install)
primary_shells: [bash]
maintainer_source_of_truth: README.md
known_limitations:
  - "Cloud assessments (AWS/Azure/GCP/K8s) require your own read-only credentials and were not exercised in review; only the offline --self-check journey was run live."
  - "Update/rollback steps assume a published v1.0.0 tag, which does not yet exist; commit-based rollback is provided instead."
---

# CSAF Linux Novice Usability Guide

> Quickest first run from a checkout: `sh scripts/quickstart.sh`. It creates `.venv`, installs locked dependencies, and runs the safe offline `--self-check`. An `[INCOMPLETE]` result / exit code 2 is expected for that demo.

## 1. About This Guide

This guide takes you, step by step, from a fresh Linux computer to running your first CSAF security assessment safely. It assumes **no prior experience** with the terminal, Git, Python, package managers, or repositories. Every technical word is defined in the **Glossary** (section 29). Every command has an ID (like `LNX-CMD-001`), tells you where to run it, and says what to expect.

**Validation status:** *partially verified.* On 2026-08-01 the install and the offline first run (`--self-check`) were run live on Ubuntu 22.04 / Python 3.10.12 and succeeded. Steps marked *statically verified* were checked against the code but not re-run live in a pristine environment.

## 2. What This Project Does

CSAF (Cloud Security Assessment Framework) inspects the **configuration** of a cloud account (AWS, Azure, GCP, or Kubernetes) and reports where it does not meet a security baseline. It is **read-only**: it never creates, changes, or deletes anything in your cloud. It writes report files to a folder on your computer. `Confirmed — csaf/__init__.py`, `csaf/clouds/aws/session.py` (mutating operations are blocked in code).

## 3. Who Should Use It

Security assessors, auditors, cloud administrators, and students who have **written authorization** to assess a cloud account, or who just want to try the safe offline demo. You do **not** need to be a programmer to run the offline demo.

## 4. Safety, Authorization, and Data Handling

- Only assess cloud accounts you are **authorized in writing** to assess.
- The offline demo (`--self-check`, section 19) uses **synthetic data** and needs no cloud account, no credentials, and no internet. Start there.
- Report files may list security weaknesses of a real account. Treat the output folder as **sensitive**; do not share it publicly.
- This guide never asks you to turn off antivirus, a firewall, or certificate checking.

## 5. Platform Support Status

**Linux is natively supported.** CSAF is pure Python and runs on any Linux distribution with Python 3.10 or newer. It was validated on Ubuntu 22.04. Other distributions (Debian, Fedora, RHEL, etc.) work the same way; only the OS package-install command in section 12 differs.

## 6. What You Will Accomplish

By the end you will have: installed the prerequisites, downloaded CSAF, created an isolated environment, run a safe offline assessment, read the results, triggered and recovered from an error, cancelled safely, cleaned up, and learned how to update.

## 7. Before You Begin Checklist

- A Linux computer you can install software on.
- About 500 MB of free disk space.
- Internet access for the download and dependency steps (the offline demo itself needs no internet).
- Permission to use `sudo` **only** for installing system packages (section 12). Everything else runs as a normal user.
- (Only for real cloud assessments) read-only credentials for your cloud, e.g. an AWS profile with the AWS-managed `ReadOnlyAccess`/`SecurityAudit` policy.

## 8. Computer and Software Requirements

| Requirement | Needed version | How to check | Section |
|---|---|---|---|
| Python | 3.10 – 3.14 | `LNX-CMD-001` | 12 |
| Git (or a downloaded ZIP) | any recent | `LNX-CMD-002` | 12 |
| `python3-venv` / `pip` | matches Python | included by `LNX-CMD-003` | 12 |

## 9. Terms and Concepts You Need to Know

Read the **Glossary** (section 29) once before starting. The most important terms: *terminal*, *command*, *working directory*, *repository*, *virtual environment*, *dependency*, and *exit code*.

## 10. Choose the Correct Installation Path

Use the **source checkout + virtual environment** path in this guide. It is the method the project documents and tests. There is no separate installer or container image to choose.

## 11. Open the Correct Terminal or Shell

Open your terminal application (on Ubuntu: press the **Super/Windows** key, type "Terminal", press **Enter**). You will type commands here. The shell is **bash** (or a compatible shell). You can tell it is ready when you see a prompt ending in `$`.

## 12. Check and Install Prerequisites

**Command ID:** `LNX-CMD-001`
**Purpose:** Confirm Python 3.10+ is installed.
**Run in:** bash terminal · **Working directory:** any · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Expected side effects:** none · **Validation status:** verified

```bash
python3 --version
```

Expected: a line like `Python 3.10.12` (any 3.10–3.14 is fine). If you see "command not found," continue to `LNX-CMD-003`.

**Command ID:** `LNX-CMD-002`
**Purpose:** Confirm Git is installed.
**Run in:** bash · **Working directory:** any · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** verified

```bash
git --version
```

Expected: `git version 2.x`. If missing, install it with `LNX-CMD-003`.

**Command ID:** `LNX-CMD-003`
**Purpose:** Install Python, the virtual-environment tool, pip, and Git on Debian/Ubuntu.
**Run in:** bash · **Working directory:** any · **Privilege:** `sudo` (needed to install system software) · **Internet:** required · **Safe to copy/paste:** yes · **Side effects:** installs OS packages · **Validation status:** statically verified

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip git
```

On Fedora/RHEL use `sudo dnf install -y python3 python3-pip git` instead. `sudo` is required because installing system-wide software needs administrator rights; nothing else in this guide uses `sudo`.

## 13. Download or Clone the Repository

**Command ID:** `LNX-CMD-004`
**Purpose:** Download (clone) CSAF.
**Run in:** bash · **Working directory:** your home folder (e.g. `~`) · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** only after replacing the placeholder · **Replace before running:** `YOUR_REPOSITORY_URL` → `https://github.com/rikterskale/Cloud-Security-Assessment-Framework.git` · **Side effects:** creates a new folder · **Validation status:** statically verified

```bash
git clone YOUR_REPOSITORY_URL
```

## 14. Find and Enter the Repository Folder

**Command ID:** `LNX-CMD-005`
**Purpose:** Move into the downloaded folder (this becomes your working directory).
**Run in:** bash · **Working directory:** your home folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** verified

```bash
cd Cloud-Security-Assessment-Framework
```

## 15. Create an Isolated Environment

A **virtual environment** keeps CSAF's dependencies separate from the rest of your system.

**Command ID:** `LNX-CMD-006`
**Purpose:** Create the virtual environment folder `.venv`.
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** creates `.venv/` · **Validation status:** verified

```bash
python3 -m venv .venv
```

**Command ID:** `LNX-CMD-007`
**Purpose:** Activate the virtual environment (your prompt will show `(.venv)`).
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** changes this terminal only · **Validation status:** verified

```bash
source .venv/bin/activate
```

## 16. Install Project Dependencies

**Command ID:** `LNX-CMD-008`
**Purpose:** Install the exact, security-pinned dependencies.
**Run in:** bash (with `.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** yes · **Side effects:** installs Python packages into `.venv` only · **Validation status:** verified

```bash
pip install --require-hashes -r requirements-lock.txt
```

`--require-hashes` means pip refuses any package whose content does not match the recorded checksum — a safety feature, not something to disable.

## 17. Build or Install the Project

**Command ID:** `LNX-CMD-009`
**Purpose:** Install CSAF itself so its commands are available.
**Run in:** bash (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** installs the `csaf` package into `.venv` · **Validation status:** verified

```bash
pip install --no-deps .
```

There is no separate compile step; CSAF is pure Python.

## 18. Verify the Installation

**Command ID:** `LNX-CMD-010`
**Purpose:** Preflight check that dependencies are importable.
**Run in:** bash (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** verified

```bash
python3 test_dependencies.py
```

**Command ID:** `LNX-CMD-011`
**Purpose:** Confirm CSAF's version.
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** verified (Verified Runtime Output)

```bash
python3 invoke_assessment.py --version
```

Expected output (verified): `CSAF v1.0.0`

## 19. Complete the First Safe Successful Run

This is the offline demo. It uses synthetic data — no cloud, no credentials, no internet.

**Command ID:** `LNX-CMD-012`
**Purpose:** Run a complete offline assessment and write reports to `out/`.
**Run in:** bash (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** creates an `out/` folder with a timestamped run subfolder · **Validation status:** verified (Verified Runtime Output)

```bash
python3 invoke_assessment.py --self-check --output-dir out
```

Expected output (verified, your run ID will differ):

```text
[INCOMPLETE] Completed. 5 findings, risk 70.0/100 (CRITICAL). Coverage 29/30 executed.
[*] Output written to out/20260801T150342Z-11592d76
```

This is **success**. The word `[INCOMPLETE]` and exit code **2** are expected here: they mean one demo control was intentionally left "not tested," not that anything failed. See section 20.

## 20. Understand the Screen Output, Exit Status, and Result Files

- **Screen line:** number of findings, a risk score, and how many controls ran.
- **Exit code** (a number the shell records): `0` = every control ran; `2` = completed but some controls were "NotTested" or errored (normal for the demo); `1` = a fatal setup problem. `Confirmed — csaf/runner.py:44-46`.
- **Result files** are in the run subfolder printed on screen.

**Command ID:** `LNX-CMD-013`
**Purpose:** List the generated report files.
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** verified

```bash
ls out/*/
```

You will see (verified): `findings.json`, `findings.csv`, `control-results.csv`, `control-results.jsonl`, `coverage-report.json`, `coverage-report.csv`, `detection-coverage.json`, `detection-coverage.csv`, `remediation-roadmap.csv`, `technical-report.json`, `executive-summary.html`, `manifest.json`, and a `.log` and `.jsonl` log. Open `executive-summary.html` in a web browser for a readable overview; `manifest.json` lists a SHA-256 checksum of every file so you can prove the reports were not altered.

## 21. Common Novice Workflows

- **Just try it safely:** section 19 (offline demo).
- **Assess a real AWS account (read-only):** activate `.venv`, then run (statically verified):

  **Command ID:** `LNX-CMD-014` · **Run in:** bash · **Working directory:** repo folder · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** only after replacement · **Replace:** `YOUR_AWS_PROFILE` → the name of a read-only AWS profile you configured (example: `audit`) · **Side effects:** reads AWS config, writes reports · **Validation status:** statically verified

  ```bash
  python3 invoke_assessment.py --profile Assessment --regions us-east-1 --aws-profile YOUR_AWS_PROFILE --output-dir out
  ```

- **Compare against a previous run:** add `--previous-findings out/OLD_RUN/findings.json`.

## 22. Configuration, Environment Variables, and Credentials

- CSAF needs **no configuration file** for the offline demo.
- Real assessments use your existing cloud credentials: AWS named profiles (`--aws-profile`), Azure `DefaultAzureCredential`, GCP Application Default Credentials, or a kubeconfig (`--kubeconfig`).
- Environment variable `KUBECONFIG` is honored for Kubernetes. The build variable `CSAF_SOURCE_REVISION` is for maintainers only.
- Use **least-privilege, read-only** credentials. CSAF blocks mutating calls itself, but least-privilege credentials are your first line of defense.

## 23. How to Stop or Cancel Safely

To stop a run in progress, press **Ctrl + C** in the terminal. CSAF is read-only, so cancelling cannot damage your cloud. Partly written report files in the current run folder can simply be deleted (section 24). *(Statically verified — standard process interrupt.)*

## 24. Cleanup, Uninstall, and Host Restoration

**Command ID:** `LNX-CMD-015`
**Purpose:** Delete generated reports.
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** removes the `out/` folder · **Validation status:** verified

```bash
rm -rf out
```

**Command ID:** `LNX-CMD-016`
**Purpose:** Leave and delete the virtual environment.
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** removes `.venv/` · **Validation status:** statically verified

```bash
deactivate; rm -rf .venv
```

To fully remove CSAF, also delete the repository folder: `cd .. && rm -rf Cloud-Security-Assessment-Framework`. CSAF installs nothing outside the repository folder and the virtual environment, so no system files need restoring.

## 25. Update, Upgrade, Downgrade, and Rollback

**Command ID:** `LNX-CMD-017`
**Purpose:** Update to the latest code, then reinstall.
**Run in:** bash · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** yes · **Side effects:** updates files, reinstalls packages · **Validation status:** statically verified

```bash
git pull && source .venv/bin/activate && pip install --require-hashes -r requirements-lock.txt && pip install --no-deps .
```

**Rollback:** because no `v1.0.0` tag is published yet, roll back by commit:

**Command ID:** `LNX-CMD-018` · **Run in:** bash · **Working directory:** repo folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** only after replacement · **Replace:** `KNOWN_GOOD_COMMIT` → a commit you trust (example: `a5771ab`) · **Side effects:** changes checked-out code · **Validation status:** statically verified

```bash
git checkout KNOWN_GOOD_COMMIT
```

When a `v1.0.0` tag is published, `git checkout v1.0.0` will be the supported rollback.

## 26. Troubleshooting Matrix

| Symptom | Likely cause | Fix |
|---|---|---|
| `python3: command not found` | Python not installed | `LNX-CMD-003` |
| `No module named 'jsonschema'` | dependencies not installed / venv not active | activate venv (`LNX-CMD-007`), run `LNX-CMD-008` |
| `pip: command not found` | pip missing | `LNX-CMD-003` |
| Run prints `[INCOMPLETE]` / exit 2 | expected in the demo (one control NotTested) | none — this is success |
| `Fatal: Unauthorized profile` | used Validation/AdversarySimulation without a signed engagement | use `--profile Assessment` (read-only) or provide a signed engagement |
| Permission denied writing output | output folder not writable | choose a writable `--output-dir` |

## 27. Frequently Asked Questions

- **Is it safe to run against a real account?** Yes for reading; CSAF cannot change your cloud. Still use read-only credentials and written authorization.
- **Why did it say INCOMPLETE?** In the demo one control is intentionally left untested. Exit code 2 means "completed, not everything ran," not "error."
- **Do I need the internet for the demo?** No. `--self-check` is fully offline.
- **What is `authorizedSourceAddresses`?** An engagement field that, if set, this local tool cannot enforce — so it deliberately blocks active runs. Enforce source-IP restrictions in your cloud/network instead, or remove the field.

## 28. Command Quick Reference

| ID | Command | Purpose |
|---|---|---|
| LNX-CMD-001 | `python3 --version` | check Python |
| LNX-CMD-002 | `git --version` | check Git |
| LNX-CMD-003 | `sudo apt-get install ...` | install prerequisites |
| LNX-CMD-004 | `git clone YOUR_REPOSITORY_URL` | download CSAF |
| LNX-CMD-005 | `cd Cloud-Security-Assessment-Framework` | enter folder |
| LNX-CMD-006 | `python3 -m venv .venv` | create environment |
| LNX-CMD-007 | `source .venv/bin/activate` | activate environment |
| LNX-CMD-008 | `pip install --require-hashes -r requirements-lock.txt` | install dependencies |
| LNX-CMD-009 | `pip install --no-deps .` | install CSAF |
| LNX-CMD-010 | `python3 test_dependencies.py` | preflight |
| LNX-CMD-011 | `python3 invoke_assessment.py --version` | show version |
| LNX-CMD-012 | `python3 invoke_assessment.py --self-check --output-dir out` | first safe run |
| LNX-CMD-013 | `ls out/*/` | list reports |
| LNX-CMD-014 | `python3 invoke_assessment.py --profile Assessment --regions us-east-1 --aws-profile YOUR_AWS_PROFILE --output-dir out` | real AWS assessment |
| LNX-CMD-015 | `rm -rf out` | delete reports |
| LNX-CMD-016 | `deactivate; rm -rf .venv` | remove environment |
| LNX-CMD-017 | `git pull && ... pip install ...` | update |
| LNX-CMD-018 | `git checkout KNOWN_GOOD_COMMIT` | rollback |

## 29. Glossary

- **Repository:** a folder of project files tracked by Git; here, the CSAF download.
- **Terminal:** the app where you type commands.
- **Shell:** the program inside the terminal that runs commands (bash).
- **Command:** an instruction you type and run.
- **Working directory / current directory:** the folder your commands act in; change it with `cd`.
- **Absolute path / relative path:** an absolute path starts at `/` (e.g. `/home/you/…`); a relative path is from your current folder (e.g. `out/`).
- **Runtime:** the language engine that runs CSAF (Python).
- **Dependency:** another package CSAF needs (e.g. `boto3`).
- **Package manager:** installs packages (`pip` for Python, `apt` for the OS).
- **Virtual environment:** an isolated Python folder (`.venv`) for this project.
- **Container:** a packaged, isolated runtime; CSAF does not require one.
- **Environment variable:** a named value the system passes to programs (e.g. `KUBECONFIG`).
- **Configuration file:** a file of settings; not needed for the demo.
- **Administrator / root / `sudo`:** elevated rights; used here only to install system packages.
- **Standard output / standard error:** normal messages vs. error messages a program prints.
- **Exit code:** a number a command returns; 0 success, non-zero a problem or partial result.
- **Process:** a running program.
- **Service / port / listener:** background programs and the network endpoints they open; CSAF opens none.
- **Log:** a file recording what happened during a run.
- **Report / artifact:** an output file CSAF produces.
- **Clone / pull / update / upgrade / downgrade / rollback / cleanup / uninstall:** download a repo / fetch new changes / move to newer code / move to older code / undo changes / delete outputs / remove the tool.
- **Findings / controls / baseline (CSAF terms):** a *control* is one security check; a *baseline* is the set of expected values; a *finding* is a control that did not meet the baseline.

## 30. Validation Record, Known Limitations, and Support Boundaries

- **Validated on:** 2026-08-01, Ubuntu 22.04, Python 3.10.12, bash, standard user.
- **Live-verified steps:** `LNX-CMD-001/002/005/006/007/008/009/010/011/012/013/015` (install through first successful offline run and report listing).
- **Statically verified steps:** OS package install, clone, real-cloud assessment, update, rollback, cleanup of `.venv`, cancellation.
- **Known limitations:** cloud assessments require your own read-only credentials and were not exercised; `v1.0.0` is not yet tagged, so rollback uses a commit (see section 25).
- **Support boundary:** questions and issues go to the project's GitHub repository; security issues follow `SECURITY.md` (private reporting).
