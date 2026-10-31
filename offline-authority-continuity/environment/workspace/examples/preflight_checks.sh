#!/bin/sh
# Public dependency and transport preflight; NOT evidence of a solved task.
set -eu
WORKSPACE_DIR="${WORKSPACE_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
cd "$WORKSPACE_DIR"
python -m compileall -q permitgate examples
python -m unittest discover -s examples -p 'test_*.py' -v
python - <<'PY2'
import tempfile
from pathlib import Path
from examples.make_sample import generate
from permitgate.canonical import canonical_json, content_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import json, hashlib
with tempfile.TemporaryDirectory() as td:
    generate(td)
    root = Path(td)
    trust = json.loads((root / 'trust.json').read_text())
    cmd = json.loads((root / 'commands.jsonl').read_text().splitlines()[0])
    b = cmd['bundle']
    signed = {k: v for k, v in b.items() if k != 'signature'}
    pk_hex = trust['sites']['north']['keys'][0]['public_key_hex']
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
    digest = hashlib.sha256(canonical_json(signed)).digest()
    pk.verify(bytes.fromhex(b['signature']), digest)
    assert content_hash(signed) == digest.hex()
    try:
        pk.verify(bytes.fromhex(b['signature']), hashlib.sha256(digest).digest())
    except InvalidSignature:
        pass
    else:
        raise AssertionError('tampered signed content was not rejected')
print('PASS: synthetic Ed25519 sign/verify and canonical hash round-trip')
PY2
printf '%s\n' 'PREFLIGHT PASS: basic workspace, parser and demo signer only'
