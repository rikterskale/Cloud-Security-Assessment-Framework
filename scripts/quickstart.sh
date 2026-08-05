#!/usr/bin/env sh
# Safe source-checkout bootstrap for the offline CSAF demo.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
cd "$ROOT"
"$PYTHON" -m venv .venv
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
