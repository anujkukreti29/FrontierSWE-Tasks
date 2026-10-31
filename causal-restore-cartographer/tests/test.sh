#!/bin/sh
set -eu
mkdir -p /logs/verifier
chmod 700 /logs/verifier
chmod -R a+rX /app/cartographer
# The runner is independent of candidate-produced JSON/reward files.
python /tests/verify.py > /logs/verifier/evaluation.log 2>&1 || {
  printf '0\n' > /logs/verifier/reward.txt
  exit 0
}
printf '1\n' > /logs/verifier/reward.txt
