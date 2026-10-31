"""Public smoke test of the partial starter (not authorization engine)."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    state=root/'st'
    key=Ed25519PrivateKey.generate()
    pk=base64.b64encode(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)).decode()
    trust={'schema':2,'tenant':'north','offline_window_ticks':30,
           'genesis_root_key_id':'root-a','genesis_root_public_key':pk}
    tr=root/'trust.json';tr.write_text(json.dumps(trust))
    def run(*args,ok=True):
        r=subprocess.run([sys.executable,'-m','gatekeeper',*args],capture_output=True,text=True)
        assert (r.returncode==0)==ok,(r.returncode,r.stdout,r.stderr)
        return json.loads(r.stdout if ok else r.stderr)
    assert run('init','--state',str(state),'--trust',str(tr))=={'state':'INITIALIZED','tenant':'north'}
    assert run('init','--state',str(state),'--trust',str(tr))=={'state':'UNCHANGED','tenant':'north'}
    s=run('status','--state',str(state))
    assert s['tenant']=='north' and s['seq']==0 and s['last_digest']=='0'*64
    assert s['authenticated_grant_count']==0 and s['applied_request_count']==0
    (state/'cache').mkdir(exist_ok=True)
    (state/'cache'/'stale.json').write_text('{"seq":99}')
    assert run('status','--state',str(state))==s
    trust['tenant']='different';tr.write_text(json.dumps(trust))
    assert run('init','--state',str(state),'--trust',str(tr),ok=False)=={'error':'INIT_CONFLICT'}
    assert run('status','--state',str(state))==s
print('PASS: starter init, repeat init, conflict handling, status and stale cache isolation')
