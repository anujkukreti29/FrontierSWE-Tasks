#!/bin/sh
set -u
mkdir -p /logs/verifier
if python /tests/verify.py --app /app > /logs/verifier/test-stdout.txt 2>&1; then
    printf '1.0\n' > /logs/verifier/reward.txt
    printf '%s\n' 'Verifier: all independent checks passed.'
else
    printf '0.0\n' > /logs/verifier/reward.txt
    printf '%s\n' 'Verifier: one or more independent checks failed.'
fi
cat /logs/verifier/test-stdout.txt
