#!/usr/bin/env sh
# Delegate to the cross-platform installer.
set -eu
# CDPATH= is a deliberate temporary env prefix that neutralizes CDPATH for this
# single cd; it is not a broken empty assignment (newer shellcheck flags SC1007).
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
exec "$PYTHON" "$ROOT/scripts/install.py" "$@"
