"""Public signed checkpoint example for the gateway CLI.

Only synthetic keys and a temporary SQLite database are used.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def enc(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def digest(obj):
    return hashlib.sha256(enc(obj)).hexdigest()


def pub(priv,key_id):
    return {'key_id':key_id,
            'public_key_hex':priv.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),
            'from_seq':1,'through_seq':100}


def run(root,commands):
    inp=root/'in.jsonl';out=root/'out.jsonl'
    inp.write_bytes(b''.join(enc(x)+b'\n' for x in commands))
    subprocess.run([sys.executable,'-m','permitgate.cli','run',
                    '--trust',str(root/'trust.json'), '--state',str(root/'state.sqlite'),
                    '--input',str(inp),'--output',str(out)],check=True)
    return [json.loads(line) for line in out.read_text('utf-8').splitlines()]


def main():
    policy_key=Ed25519PrivateKey.generate()
    checkpoint_key=Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix='checkpoint-demo-') as directory:
        root=Path(directory)
        trust={'sites':{'lab':{'keys':[pub(policy_key,'policy')],
                                'checkpoint_keys':[pub(checkpoint_key,'checkpoint')],
                                'critical':[]}}}
        (root/'trust.json').write_bytes(enc(trust))
        event={'type':'grant','authority':'operations','principal':'operator',
               'asset':'fan','action':'inspect','valid_from_tick':0,'expires_at_tick':100}
        payload={'site':'lab','start_seq':1,'prev_hash':'0'*64,'key_id':'policy','events':[event]}
        bundle={**payload,'signature':policy_key.sign(hashlib.sha256(enc(payload)).digest()).hex()}
        active=[[1,'grant','operations','operator',None,None,'fan','inspect',0,100]]
        projection={'site':'lab','through_seq':1,'anchor_hash':digest(payload),
                    'max_tick':-1,'active_policy':active,'open_requests':[],
                    'effects':[],'retired':[],
                    'accepted_ids':[[1,1,hashlib.sha256(enc(bundle)).hexdigest()]]}
        body={'site':'lab','through_seq':1,'anchor_hash':digest(payload),
              'state_hash':digest(projection),'key_id':'checkpoint'}
        checkpoint={**body,'signature':checkpoint_key.sign(
            hashlib.sha256(enc({'domain':'permitgate-checkpoint-v1',**body})).digest()).hex()}
        commands=[{'kind':'ingest','bundle':bundle},
                  {'kind':'checkpoint','checkpoint':checkpoint},
                  {'kind':'checkpoint_status','site':'lab'},
                  {'kind':'ingest','bundle':bundle},
                  {'kind':'prepare','request_id':'job1','site':'lab','principal':'operator',
                   'asset':'fan','action':'inspect','tick':10},
                  {'kind':'commit','request_id':'job1','tick':11}]
        responses=run(root,commands)
        expected=[{'status':'applied','code':'applied'},
                  {'status':'checkpointed','code':'checkpointed'},
                  {'status':'ok','through_seq':1,'retained_from_seq':2,
                   'accepted_batch_identities':1,'raw_batches':0,'gap':False},
                  {'status':'duplicate','code':'duplicate'},
                  {'status':'prepared','code':'prepared'},
                  {'status':'executed','code':'executed'}]
        if responses != expected:
            raise AssertionError(f'Unexpected gateway results: {responses!r}')
        print('Checkpoint example: PASS (6/6 responses)')


if __name__=='__main__':
    main()
