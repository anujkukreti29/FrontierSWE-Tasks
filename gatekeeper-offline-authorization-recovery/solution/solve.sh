#!/usr/bin/env bash
set -euo pipefail
# Reference implementation for local and Harbor Oracle evaluation.
# Copies the reference package into the candidate workspace.
if [ ! -f /solution/reference/gatekeeper/engine.py ]; then
  echo 'REFERENCE_MISSING: no substantive implementation; Oracle cannot be validated' >&2
  exit 2
fi
cp -a /solution/reference/gatekeeper/. /workspace/gatekeeper/
python3 -m gatekeeper --help >/dev/null
