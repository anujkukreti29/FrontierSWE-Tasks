#!/bin/sh
set -eu
install -m 0644 /solution/reference/gateway.py /app/permitgate/gateway.py
install -m 0644 /solution/reference/cli.py /app/permitgate/cli.py
python -m compileall -q /app/permitgate
