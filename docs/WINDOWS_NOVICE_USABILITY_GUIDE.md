---
guide_id: windows-novice-usability
guide_schema_version: 1
platform: windows
canonical_path: docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md
project_name: Cloud Security Assessment Framework (CSAF)
target_release: "latest locally verifiable version: 1.0.0 (untagged, commit a5771ab)"
target_commit: a5771ab3a31dd660a6d0da3dd6bbc97ce63050a9
support_status: native_supported
alternative_support_paths: []
validation_status: statically_verified_only
validated_on: 2026-08-01
validated_environments: []
primary_shells: [powershell]
maintainer_source_of_truth: README.md
known_limitations:
  - "No clean Windows host was available during review; commands are statically verified against the code and the README PowerShell activation instructions, not re-run on Windows."
  - "The equivalent offline run was verified live on Linux; behavior is identical because CSAF is pure Python."
  - "Update/rollback assume a published v1.0.0 tag, which does not yet exist; commit-based rollback is provided instead."
---

# CSAF Windows Novice Usability Guide

## 1. About This Guide

This guide takes you from a fresh Windows computer to running your first CSAF security assessment safely, assuming **no prior experience** with PowerShell, Command Prompt, Git, Python, or repositories. Every technical term is defined in the **Glossary** (section 29). Every command has an ID (like `WIN-CMD-001`), tells you which application to run it in, and says what to expect.

**Validation status:** *statically verified only.* No clean Windows machine was available during the review, so Windows commands were verified against the source code and the project's documented PowerShell instructions, not re-executed on Windows. The identical offline run **was** verified live on Linux, and CSAF is pure Python, so behavior is the same.

## 2. What This Project Does

CSAF inspects the **configuration** of a cloud account (AWS, Azure, GCP, or Kubernetes) and reports where it does not meet a security baseline. It is **read-only**: it never creates, changes, or deletes anything in your cloud. It writes report files to a folder on your computer. `Confirmed — csaf/__init__.py`, `csaf/clouds/aws/session.py`.

## 3. Who Should Use It

Security assessors, auditors, cloud administrators, and students who have **written authorization** to assess a cloud account, or who want to try the safe offline demo. You do **not** need to be a programmer to run the offline demo.

## 4. Safety, Authorization, and Data Handling

- Only assess cloud accounts you are **authorized in writing** to assess.
- The offline demo (`--self-check`, section 19) uses **synthetic data** — no cloud account, no credentials, no internet. Start there.
- Report files may describe real security weaknesses; treat the output folder as **sensitive**.
- This guide never asks you to weaken Windows security. In particular, it uses a **safe, scoped** PowerShell execution-policy change for your user only (section 11) and explains why — it does not tell you to disable protection globally.

## 5. Platform Support Status

**Windows is natively supported.** CSAF is pure Python and runs on Windows 10/11 (x64) with Python 3.10 or newer, using **Windows PowerShell**. WSL and Docker are **not required** and are not covered here because native Windows works directly.

## 6. What You Will Accomplish

Install prerequisites, download CSAF, create an isolated environment, run a safe offline assessment, read the results, trigger and recover from an error, cancel safely, clean up, and learn how to update.

## 7. Before You Begin Checklist

- Windows 10 or 11 (64-bit) you can install software on.
- About 500 MB free disk space.
- Internet access for download and dependency steps (the offline demo needs no internet).
- A standard user account is enough. Installing Python/Git may show a **User Account Control** prompt; approve it. No step needs a permanently elevated Administrator shell.
- (Only for real cloud assessments) read-only cloud credentials (e.g. an AWS profile with `ReadOnlyAccess`/`SecurityAudit`).

## 8. Computer and Software Requirements

| Requirement | Needed version | How to check | Section |
|---|---|---|---|
| Python | 3.10 – 3.14 | `WIN-CMD-001` | 12 |
| Git (or a downloaded ZIP) | any recent | `WIN-CMD-002` | 12 |
| Windows PowerShell | ships with Windows | open it (section 11) | 11 |

## 9. Terms and Concepts You Need to Know

Read the **Glossary** (section 29) once before starting. Most important: *PowerShell*, *command*, *working directory*, *repository*, *virtual environment*, *dependency*, *exit code*.

## 10. Choose the Correct Installation Path

Use the **source checkout + virtual environment** path with **Windows PowerShell**. It matches the project's documented Windows instructions (`README.md`: `.venv\Scripts\Activate.ps1`). There is no separate installer or container to choose.

## 11. Open the Correct Terminal or Shell

Click **Start**, type **PowerShell**, and open **Windows PowerShell** (the blue icon). You will type commands at the prompt (it ends with `>`).

Some systems block running the environment-activation script by default. Allow it **for your user only** (this is scoped and reversible; it does not disable Windows security):

**Command ID:** `WIN-CMD-000`
**Purpose:** Permit locally created scripts (like the venv activator) to run for your user.
**Run in:** Windows PowerShell · **Working directory:** any · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** sets your user's PowerShell execution policy to `RemoteSigned` · **Validation status:** statically verified

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`RemoteSigned` still blocks unsigned scripts downloaded from the internet; it only allows local scripts. This is the standard, safe setting for Python development on Windows.

## 12. Check and Install Prerequisites

**Command ID:** `WIN-CMD-001`
**Purpose:** Confirm Python 3.10+ is installed.
**Run in:** PowerShell · **Working directory:** any · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** statically verified

```powershell
python --version
```

Expected: `Python 3.10.x` – `3.14.x`. If you see an error or the Microsoft Store opens, install Python with `WIN-CMD-003`.

**Command ID:** `WIN-CMD-002`
**Purpose:** Confirm Git is installed.
**Run in:** PowerShell · **Working directory:** any · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** statically verified

```powershell
git --version
```

Expected: `git version 2.x`. If missing, install with `WIN-CMD-003`.

**Command ID:** `WIN-CMD-003`
**Purpose:** Install Python and Git using the Windows package manager (winget, included on Windows 10/11).
**Run in:** PowerShell · **Working directory:** any · **Privilege:** standard user (approve any UAC prompt) · **Internet:** required · **Safe to copy/paste:** yes · **Side effects:** installs Python and Git · **Validation status:** statically verified

```powershell
winget install --id Python.Python.3.12 -e; winget install --id Git.Git -e
```

After installing, **close and reopen PowerShell** so the new programs are found, then re-run `WIN-CMD-001` and `WIN-CMD-002`.

## 13. Download or Clone the Repository

**Command ID:** `WIN-CMD-004`
**Purpose:** Download (clone) CSAF.
**Run in:** PowerShell · **Working directory:** your user folder (e.g. `C:\Users\You`) · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** only after replacing the placeholder · **Replace before running:** `YOUR_REPOSITORY_URL` → `https://github.com/rikterskale/Cloud-Security-Assessment-Framework.git` · **Side effects:** creates a new folder · **Validation status:** statically verified

```powershell
git clone YOUR_REPOSITORY_URL
```

## 14. Find and Enter the Repository Folder

**Command ID:** `WIN-CMD-005`
**Purpose:** Move into the downloaded folder.
**Run in:** PowerShell · **Working directory:** your user folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** statically verified

```powershell
cd Cloud-Security-Assessment-Framework
```

## 15. Create an Isolated Environment

**Command ID:** `WIN-CMD-006`
**Purpose:** Create the virtual environment folder `.venv`.
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** creates `.venv\` · **Validation status:** statically verified

```powershell
python -m venv .venv
```

**Command ID:** `WIN-CMD-007`
**Purpose:** Activate the virtual environment (prompt shows `(.venv)`).
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** changes this PowerShell session only · **Validation status:** statically verified

```powershell
.venv\Scripts\Activate.ps1
```

If this is blocked, you missed `WIN-CMD-000`; run it, then retry.

## 16. Install Project Dependencies

**Command ID:** `WIN-CMD-008`
**Purpose:** Install the exact, security-pinned dependencies.
**Run in:** PowerShell (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** yes · **Side effects:** installs packages into `.venv` only · **Validation status:** statically verified

```powershell
pip install --require-hashes -r requirements-lock.txt
```

`--require-hashes` refuses any package whose content does not match the recorded checksum. Do not remove it.

## 17. Build or Install the Project

**Command ID:** `WIN-CMD-009`
**Purpose:** Install CSAF itself.
**Run in:** PowerShell (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** installs the `csaf` package into `.venv` · **Validation status:** statically verified

```powershell
pip install --no-deps .
```

There is no compile step; CSAF is pure Python.

## 18. Verify the Installation

**Command ID:** `WIN-CMD-010`
**Purpose:** Preflight that dependencies import correctly.
**Run in:** PowerShell (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** statically verified

```powershell
python test_dependencies.py
```

**Command ID:** `WIN-CMD-011`
**Purpose:** Confirm CSAF's version.
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** statically verified (Code-Derived Output; verified live on Linux)

```powershell
python invoke_assessment.py --version
```

Expected output: `CSAF v1.0.0`

## 19. Complete the First Safe Successful Run

The offline demo uses synthetic data — no cloud, no credentials, no internet.

**Command ID:** `WIN-CMD-012`
**Purpose:** Run a complete offline assessment and write reports to `out\`.
**Run in:** PowerShell (`.venv` active) · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** creates an `out\` folder with a timestamped run subfolder · **Validation status:** statically verified (Code-Derived Output; identical run verified live on Linux)

```powershell
python invoke_assessment.py --self-check --output-dir out
```

Expected output (your run ID will differ):

```text
[INCOMPLETE] Completed. 5 findings, risk 70.0/100 (CRITICAL). Coverage 29/30 executed.
[*] Output written to out\20260801T150342Z-11592d76
```

This is **success**. `[INCOMPLETE]` and exit code **2** are expected here (one demo control is intentionally not tested). See section 20.

## 20. Understand the Screen Output, Exit Status, and Result Files

- **Screen line:** findings count, risk score, controls run.
- **Exit code:** `0` = all controls ran; `2` = completed but some NotTested/errored (normal for the demo); `1` = fatal setup problem. `Confirmed — csaf/runner.py:44-46`. In PowerShell, check the last exit code with `$LASTEXITCODE`.
- **Result files** are in the run subfolder printed on screen.

**Command ID:** `WIN-CMD-013`
**Purpose:** List the generated report files.
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** none · **Validation status:** statically verified

```powershell
Get-ChildItem out\*\
```

You will see `findings.json`, `findings.csv`, `control-results.csv`, `control-results.jsonl`, `coverage-report.json`, `coverage-report.csv`, `detection-coverage.json`, `detection-coverage.csv`, `remediation-roadmap.csv`, `technical-report.json`, `executive-summary.html`, `manifest.json`, and log files. Double-click `executive-summary.html` to open it in your browser; `manifest.json` holds a SHA-256 checksum of every file for integrity.

## 21. Common Novice Workflows

- **Just try it safely:** section 19 (offline demo).
- **Assess a real AWS account (read-only):** with `.venv` active (statically verified):

  **Command ID:** `WIN-CMD-014` · **Run in:** PowerShell · **Working directory:** repo folder · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** only after replacement · **Replace:** `YOUR_AWS_PROFILE` → your read-only AWS profile name (example: `audit`) · **Side effects:** reads AWS config, writes reports · **Validation status:** statically verified

  ```powershell
  python invoke_assessment.py --profile Assessment --regions us-east-1 --aws-profile YOUR_AWS_PROFILE --output-dir out
  ```

- **Compare against a previous run:** add `--previous-findings out\OLD_RUN\findings.json`.

## 22. Configuration, Environment Variables, and Credentials

- No configuration file is needed for the offline demo.
- Real assessments use your existing cloud credentials: AWS named profiles (`--aws-profile`), Azure `DefaultAzureCredential`, GCP Application Default Credentials, or a kubeconfig (`--kubeconfig`).
- The `KUBECONFIG` environment variable is honored for Kubernetes. Set a variable for the current session with `$env:KUBECONFIG = "C:\path\to\config"`.
- Always use **least-privilege, read-only** credentials.

## 23. How to Stop or Cancel Safely

Press **Ctrl + C** in PowerShell to stop a run. CSAF is read-only, so cancelling cannot damage your cloud. Delete any partly written report folder (section 24). *(Statically verified — standard interrupt.)*

## 24. Cleanup, Uninstall, and Host Restoration

**Command ID:** `WIN-CMD-015`
**Purpose:** Delete generated reports.
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** removes the `out\` folder · **Validation status:** statically verified

```powershell
Remove-Item -Recurse -Force out
```

**Command ID:** `WIN-CMD-016`
**Purpose:** Leave and delete the virtual environment.
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** yes · **Side effects:** removes `.venv\` · **Validation status:** statically verified

```powershell
deactivate; Remove-Item -Recurse -Force .venv
```

To fully remove CSAF, also delete the repository folder: `cd ..; Remove-Item -Recurse -Force Cloud-Security-Assessment-Framework`. CSAF installs nothing outside the repository folder and virtual environment. To undo the section 11 setting, run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Undefined`.

## 25. Update, Upgrade, Downgrade, and Rollback

**Command ID:** `WIN-CMD-017`
**Purpose:** Update to the latest code, then reinstall.
**Run in:** PowerShell · **Working directory:** the repository folder · **Privilege:** standard user · **Internet:** required · **Safe to copy/paste:** yes · **Side effects:** updates files, reinstalls packages · **Validation status:** statically verified

```powershell
git pull; .venv\Scripts\Activate.ps1; pip install --require-hashes -r requirements-lock.txt; pip install --no-deps .
```

**Rollback (by commit, since no `v1.0.0` tag is published yet):**

**Command ID:** `WIN-CMD-018` · **Run in:** PowerShell · **Working directory:** repo folder · **Privilege:** standard user · **Internet:** not required · **Safe to copy/paste:** only after replacement · **Replace:** `KNOWN_GOOD_COMMIT` → a commit you trust (example: `a5771ab`) · **Side effects:** changes checked-out code · **Validation status:** statically verified

```powershell
git checkout KNOWN_GOOD_COMMIT
```

When `v1.0.0` is tagged, `git checkout v1.0.0` becomes the supported rollback.

## 26. Troubleshooting Matrix

| Symptom | Likely cause | Fix |
|---|---|---|
| `python` opens Microsoft Store or "not recognized" | Python not installed / not on PATH | `WIN-CMD-003`, reopen PowerShell |
| `Activate.ps1 cannot be loaded ... not digitally signed` | execution policy blocks local scripts | run `WIN-CMD-000`, then `WIN-CMD-007` |
| `No module named 'jsonschema'` | dependencies not installed / venv not active | activate venv (`WIN-CMD-007`), run `WIN-CMD-008` |
| Run prints `[INCOMPLETE]` / `$LASTEXITCODE` is 2 | expected in the demo | none — this is success |
| `Fatal: Unauthorized profile` | active profile without a signed engagement | use `--profile Assessment` (read-only) |
| Reports fail to write | output folder not writable | pick a writable `--output-dir` |

## 27. Frequently Asked Questions

- **Do I need Administrator?** No. Installing Python/Git may show a UAC prompt; the tool itself runs as a standard user.
- **Why did it say INCOMPLETE?** The demo intentionally leaves one control untested; exit code 2 means "completed, not everything ran," not "error."
- **Is WSL required?** No. Native Windows PowerShell works directly.
- **Is it safe against a real account?** Yes for reading; CSAF cannot change your cloud. Still use read-only credentials and written authorization.
- **What is `authorizedSourceAddresses`?** An engagement field this local tool cannot enforce, so it deliberately blocks active runs; enforce source-IP limits in your cloud/network or remove the field.

## 28. Command Quick Reference

| ID | Command | Purpose |
|---|---|---|
| WIN-CMD-000 | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` | allow local scripts (safe) |
| WIN-CMD-001 | `python --version` | check Python |
| WIN-CMD-002 | `git --version` | check Git |
| WIN-CMD-003 | `winget install ...` | install prerequisites |
| WIN-CMD-004 | `git clone YOUR_REPOSITORY_URL` | download CSAF |
| WIN-CMD-005 | `cd Cloud-Security-Assessment-Framework` | enter folder |
| WIN-CMD-006 | `python -m venv .venv` | create environment |
| WIN-CMD-007 | `.venv\Scripts\Activate.ps1` | activate environment |
| WIN-CMD-008 | `pip install --require-hashes -r requirements-lock.txt` | install dependencies |
| WIN-CMD-009 | `pip install --no-deps .` | install CSAF |
| WIN-CMD-010 | `python test_dependencies.py` | preflight |
| WIN-CMD-011 | `python invoke_assessment.py --version` | show version |
| WIN-CMD-012 | `python invoke_assessment.py --self-check --output-dir out` | first safe run |
| WIN-CMD-013 | `Get-ChildItem out\*\` | list reports |
| WIN-CMD-014 | `python invoke_assessment.py --profile Assessment --regions us-east-1 --aws-profile YOUR_AWS_PROFILE --output-dir out` | real AWS assessment |
| WIN-CMD-015 | `Remove-Item -Recurse -Force out` | delete reports |
| WIN-CMD-016 | `deactivate; Remove-Item -Recurse -Force .venv` | remove environment |
| WIN-CMD-017 | `git pull; ... pip install ...` | update |
| WIN-CMD-018 | `git checkout KNOWN_GOOD_COMMIT` | rollback |

## 29. Glossary

- **Repository:** a folder of project files tracked by Git; here, the CSAF download.
- **PowerShell:** the Windows terminal application where you type commands.
- **Command Prompt:** an older Windows terminal; this guide uses PowerShell instead.
- **Shell:** the program that runs your commands (PowerShell).
- **Command:** an instruction you type and run.
- **Working directory / current directory:** the folder your commands act in; change it with `cd`.
- **Absolute path / relative path:** an absolute path starts at a drive (e.g. `C:\Users\You\…`); a relative path is from your current folder (e.g. `out\`).
- **Runtime:** the language engine that runs CSAF (Python).
- **Dependency:** another package CSAF needs (e.g. `boto3`).
- **Package manager:** installs packages (`pip` for Python, `winget` for Windows apps).
- **Virtual environment:** an isolated Python folder (`.venv`) for this project.
- **Container:** a packaged isolated runtime; CSAF does not require one.
- **Environment variable:** a named value the system passes to programs (e.g. `KUBECONFIG`); set with `$env:NAME = "value"`.
- **Configuration file:** a settings file; not needed for the demo.
- **Administrator / UAC:** elevated rights; the User Account Control prompt appears only when installing software.
- **Execution policy:** a PowerShell safety setting controlling which scripts may run; `RemoteSigned` is the safe development default.
- **Standard output / standard error:** normal vs. error messages a program prints.
- **Exit code:** a number a command returns (check `$LASTEXITCODE`); 0 success, non-zero a problem or partial result.
- **Process:** a running program.
- **Service / port / listener:** background programs and network endpoints; CSAF opens none.
- **Log:** a file recording what happened during a run.
- **Report / artifact:** an output file CSAF produces.
- **Clone / pull / update / upgrade / downgrade / rollback / cleanup / uninstall:** download a repo / fetch new changes / move to newer code / move to older code / undo changes / delete outputs / remove the tool.
- **Findings / controls / baseline (CSAF terms):** a *control* is one security check; a *baseline* is the expected values; a *finding* is a control that did not meet the baseline.

## 30. Validation Record, Known Limitations, and Support Boundaries

- **Validated on:** 2026-08-01. **No clean Windows host was available**, so every Windows command is *statically verified* against the source and the project's documented PowerShell instructions (`README.md`).
- **Cross-checked live on Linux:** the offline first run (`--self-check`) produced the shown output on Ubuntu 22.04 / Python 3.10.12; Windows behavior is expected to match because CSAF is pure Python.
- **Known limitations:** cloud assessments require your own read-only credentials (not exercised); `v1.0.0` is not yet tagged, so rollback uses a commit (section 25); Windows-native re-validation is recommended before relying on this guide in production (tracked as roadmap item "cross-OS CI" and finding `REV-DX-002`).
- **Support boundary:** questions and issues go to the project's GitHub repository; security issues follow `SECURITY.md` (private reporting).
