#!/bin/sh
set -eu
# Reference implementation is not included in the agent's Docker build context.
cp -R /solution/reference/cartographer/. /app/cartographer/
python -m compileall -q /app/cartographer
