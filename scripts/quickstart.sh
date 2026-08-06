#!/usr/bin/env sh
# Safe source-checkout bootstrap for the offline CSAF demo.
set -eu
# CDPATH= is a deliberate temporary env prefix that neutralizes CDPATH for this
# single cd; it is not a broken empty assignment (newer shellcheck flags SC1007).
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
cd "$ROOT"
"$PYTHON" -m venv .venv
# The venv activator is created at runtime and cannot be followed at lint time.
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements-lock.txt
python -m pip install --no-deps .
set +e
python invoke_assessment.py --self-check --output-dir out
status=$?
set -e
if [ "$status" -eq 2 ]; then
  echo "Self-check is intentionally INCOMPLETE (exit 2): one control is left untested. Setup succeeded."
  exit 0
fi
exit "$status"
