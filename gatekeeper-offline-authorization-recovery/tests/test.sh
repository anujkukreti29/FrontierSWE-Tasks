#!/usr/bin/env bash
set -euo pipefail

reward=/logs/verifier/reward.txt
mkdir -p /logs/verifier
rm -f "$reward"

# Only the candidate package is transferred to this verifier environment.
if [ ! -d /workspace/gatekeeper ] || [ ! -f /workspace/gatekeeper/__main__.py ]; then
  printf '0\n' > "$reward"
  echo 'MISSING_CANDIDATE_PACKAGE' >&2
  exit 0
fi

cd /tests
export GATEKEEPER_REWARD_PATH="$reward"
# Store the replay seed with trusted verifier logs, outside the candidate workspace.
export GATEKEEPER_SEED_LOG_PATH=/logs/verifier/scenario-seed.txt
if python3 /tests/scenarios.py; then
  if [ ! -s "$reward" ]; then
    printf '0\n' > "$reward"
    echo 'VERIFIER_ERROR: scenarios completed without producing a reward' >&2
    exit 2
  fi
else
  result=$?
  printf '0\n' > "$reward"
  echo "VERIFIER_ERROR: scenario suite terminated before completion (exit $result)" >&2
  exit "$result"
fi
