#!/usr/bin/env python3
"""One-command CSAF bootstrap: venv, locked deps, preflight, first assessment.

Usage (from a source checkout):
    python scripts/install.py
    python scripts/install.py --cloud azure --live --subscription 00000000-0000-0000-0000-000000000000

Exit 0 means the first assessment completed (the offline demo's exit 2 is mapped to 0).
This installer never calls a cloud API unless --live is passed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
REQUIRED_PYTHON = (3, 10)
SELFCHECK_INCOMPLETE = 2
PYPROJECT = ROOT / "pyproject.toml"

# Child processes must emit UTF-8. Completions and reports break on UTF-16 consoles.
_CHILD_ENV = {
    **os.environ,
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
}


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def _fail(code: str, cause: str, resource: str, fix: str) -> int:
    print(f"[{code}] {cause}")
    print(f"    Resource: {resource}")
    print(f"    Fix: {fix}")
    return 1


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("env", _CHILD_ENV)
    return subprocess.run(cmd, cwd=ROOT, check=False, **kwargs)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install CSAF and complete the first assessment.")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp", "k8s"], default="aws")
    parser.add_argument("--live", action="store_true", help="Also validate cloud credentials/API access (read-only).")
    parser.add_argument("--aws-profile", default=None)
    parser.add_argument("--subscription", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--kube-context", default=None)
    parser.add_argument("--kubeconfig", default=None)
    parser.add_argument("--output-dir", default="out")
    parser.add_argument("--skip-self-check", action="store_true")
    parser.add_argument("--python", default=sys.executable, help="Python used to create the virtualenv.")
    return parser.parse_args(argv)


def ensure_checkout() -> int:
    if not PYPROJECT.is_file():
        return _fail(
            "CSAF-E003",
            "This installer must run from a Cloud-Security-Assessment-Framework checkout.",
            str(ROOT),
            "git clone https://github.com/rikterskale/Cloud-Security-Assessment-Framework.git"
            " && cd Cloud-Security-Assessment-Framework && python scripts/install.py",
        )
    text = PYPROJECT.read_text(encoding="utf-8")
    if 'name = "cloud-saf"' not in text:
        return _fail(
            "CSAF-E003",
            "pyproject.toml is not the cloud-saf project.",
            str(PYPROJECT),
            "cd into the CSAF repository root, then: python scripts/install.py",
        )
    print(f"[PASS] repository root {ROOT}")
    return 0


def ensure_python(executable: str) -> int:
    proc = _run(
        [executable, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return _fail(
            "CSAF-E001",
            "The selected Python interpreter could not be executed.",
            executable,
            "Install Python 3.10+ from https://www.python.org/downloads/ then: "
            "py -3.12 scripts/install.py   (Windows) or python3.12 scripts/install.py",
        )
    major_s, minor_s = proc.stdout.strip().split(".")
    major, minor = int(major_s), int(minor_s)
    if (major, minor) < REQUIRED_PYTHON:
        return _fail(
            "CSAF-E001",
            f"Python {major}.{minor} is too old (need >= 3.10).",
            executable,
            "Install Python 3.10 or newer, then: py -3.12 scripts/install.py   (Windows) or python3.12 scripts/install.py",
        )
    venv_probe = _run([executable, "-c", "import venv"], capture_output=True, text=True)
    if venv_probe.returncode != 0:
        return _fail(
            "CSAF-E001",
            "The venv module is missing from this Python install.",
            executable,
            "Windows: reinstall Python 3.12 and tick pip and py launcher. "
            "Debian/Ubuntu: sudo apt-get install python3-venv python3-pip",
        )
    print(f"[PASS] Python {major}.{minor} ({executable})")
    return 0


def create_venv(executable: str) -> int:
    if not VENV.exists():
        print(f"[*] Creating virtualenv at {VENV}")
        proc = _run([executable, "-m", "venv", str(VENV)])
        if proc.returncode != 0:
            return _fail(
                "CSAF-E001",
                "Virtualenv creation failed.",
                str(VENV),
                f"{executable} -m venv .venv",
            )
    py = _venv_python()
    if not py.is_file():
        return _fail("CSAF-E001", "Virtualenv Python is missing.", str(py), f"{executable} -m venv .venv")
    print(f"[PASS] virtualenv {py}")
    return 0


def ensure_pip() -> int:
    py = str(_venv_python())
    probe = _run([py, "-m", "pip", "--version"], capture_output=True, text=True)
    if probe.returncode == 0:
        print(f"[PASS] pip ({(probe.stdout or '').strip() or 'ok'})")
        return 0
    print("[*] Bootstrapping pip with ensurepip")
    bootstrap = _run([py, "-m", "ensurepip", "--upgrade"])
    if bootstrap.returncode != 0:
        return _fail(
            "CSAF-E001",
            "pip is not available in the virtualenv and ensurepip failed.",
            py,
            f"{py} -m ensurepip --upgrade",
        )
    retry = _run([py, "-m", "pip", "--version"], capture_output=True, text=True)
    if retry.returncode != 0:
        return _fail(
            "CSAF-E001",
            "pip is still missing after ensurepip.",
            py,
            f"{py} -m ensurepip --upgrade && {py} -m pip install --upgrade pip",
        )
    print("[PASS] pip bootstrapped")
    return 0


def install_locked() -> int:
    py = str(_venv_python())
    lock = ROOT / "requirements-lock.txt"
    if not lock.is_file():
        return _fail(
            "CSAF-E003",
            "Hash-locked dependency file is missing.",
            str(lock),
            "Restore requirements-lock.txt from the repository and retry.",
        )
    steps = (
        ([py, "-m", "pip", "install", "--upgrade", "pip"], "pip", f"{py} -m pip install --upgrade pip"),
        (
            [py, "-m", "pip", "install", "--require-hashes", "-r", str(lock)],
            str(lock),
            f"{py} -m pip install --require-hashes -r requirements-lock.txt",
        ),
        ([py, "-m", "pip", "install", "--no-deps", str(ROOT)], str(ROOT), f"{py} -m pip install --no-deps ."),
    )
    for cmd, resource, fix in steps:
        print(f"[*] {' '.join(cmd)}")
        proc = _run(cmd)
        if proc.returncode != 0:
            return _fail("CSAF-E001", "Dependency installation failed.", resource, fix)
    print("[PASS] locked dependencies and cloud-saf package installed")
    return 0


def _assess_cmd() -> list[str]:
    bin_dir = _venv_python().parent
    script = bin_dir / ("csaf-assess.exe" if os.name == "nt" else "csaf-assess")
    if script.is_file():
        return [str(script)]
    return [str(_venv_python()), str(ROOT / "invoke_assessment.py")]


def verify_console_script() -> int:
    cmd = [*_assess_cmd(), "--version"]
    proc = _run(cmd, capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 or "CSAF v" not in output:
        return _fail(
            "CSAF-E001",
            "csaf-assess --version failed after install.",
            " ".join(cmd),
            f"{' '.join(_assess_cmd())} --version",
        )
    print(f"[PASS] {output.strip()}")
    return 0


def local_preflight(cloud: str, output_dir: str) -> int:
    cmd = [*_assess_cmd(), "--preflight", "--cloud", cloud, "--output-dir", output_dir, "--output-format", "text"]
    print(f"[*] {' '.join(cmd)}")
    proc = _run(cmd)
    if proc.returncode != 0:
        return _fail(
            "CSAF-E001",
            "Local preflight failed (Python, deps, catalog, or output directory).",
            "python/deps/catalog/output-dir",
            f"{' '.join(_assess_cmd())} --preflight --cloud {cloud} --output-format text",
        )
    return 0


def live_preflight(args: argparse.Namespace) -> int:
    cmd = [
        *_assess_cmd(),
        "--preflight",
        "--live",
        "--cloud",
        args.cloud,
        "--output-dir",
        args.output_dir,
        "--output-format",
        "text",
    ]
    if args.aws_profile:
        cmd.extend(["--aws-profile", args.aws_profile])
    if args.subscription:
        cmd.extend(["--subscription", args.subscription])
    if args.project:
        cmd.extend(["--project", args.project])
    if args.kube_context:
        cmd.extend(["--kube-context", args.kube_context])
    if args.kubeconfig:
        cmd.extend(["--kubeconfig", args.kubeconfig])
    print(f"[*] {' '.join(cmd)}")
    proc = _run(cmd)
    if proc.returncode != 0:
        return _fail(
            "CSAF-E002",
            "Live credential/API preflight failed.",
            args.cloud,
            f"csaf-assess --guide --cloud {args.cloud}",
        )
    return 0


def _latest_run_dir(output_dir: str) -> Path | None:
    base = ROOT / output_dir
    if not base.is_dir():
        return None
    runs = [p for p in base.iterdir() if p.is_dir()]
    return max(runs, key=lambda p: p.stat().st_mtime) if runs else None


def run_self_check(cloud: str, output_dir: str) -> int:
    cmd = [*_assess_cmd(), "--self-check", "--cloud", cloud, "--output-dir", output_dir]
    print(f"[*] {' '.join(cmd)}")
    proc = _run(cmd)
    if proc.returncode not in (0, SELFCHECK_INCOMPLETE):
        return _fail(
            "CSAF-E999",
            f"Self-check failed with exit {proc.returncode}.",
            output_dir,
            f"{' '.join(_assess_cmd())} --self-check --cloud {cloud} --output-dir {output_dir} --log-level DEBUG",
        )
    run_dir = _latest_run_dir(output_dir)
    required = ("executive-summary.html", "findings.csv", "findings.json", "manifest.json")
    missing = [name for name in required if run_dir is None or not (run_dir / name).is_file()]
    if missing:
        return _fail(
            "CSAF-E003",
            "Self-check finished but expected report files were not written.",
            ", ".join(missing),
            f"{' '.join(_assess_cmd())} --self-check --cloud {cloud} --output-dir {output_dir} --log-level DEBUG",
        )
    print(f"[PASS] first assessment written to {run_dir}")
    if proc.returncode == SELFCHECK_INCOMPLETE:
        print("[PASS] demo coverage is intentionally incomplete; exit 2 is success.")
    return 0


def main(argv: list[str] | None = None) -> int:
    started = time.monotonic()
    args = parse_args(argv)
    print("CSAF installer (no mutating cloud calls)\n")
    for step in (
        ensure_checkout,
        lambda: ensure_python(args.python),
        lambda: create_venv(args.python),
        ensure_pip,
        install_locked,
        verify_console_script,
        lambda: local_preflight(args.cloud, args.output_dir),
    ):
        code = step()
        if code:
            return code
    if args.live:
        code = live_preflight(args)
        if code:
            return code
    if not args.skip_self_check:
        code = run_self_check(args.cloud, args.output_dir)
        if code:
            return code
    activate = r".venv\Scripts\Activate.ps1" if os.name == "nt" else "source .venv/bin/activate"
    run_dir = _latest_run_dir(args.output_dir)
    html = str((run_dir / "executive-summary.html") if run_dir else Path(args.output_dir) / "*/executive-summary.html")
    elapsed = int(time.monotonic() - started)
    print("\n[PASS] First assessment complete (no manual dependency fixes).")
    print(f"What just happened: locked dependencies installed; first assessment written ({elapsed}s).")
    print(f"Next: {activate}")
    print(f"      Open {html}")
    print(f"      For a real {args.cloud} account: csaf-assess --guide --cloud {args.cloud}")
    print("      Packaged install after the GitHub Release: pipx install cloud-saf==1.1.0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
