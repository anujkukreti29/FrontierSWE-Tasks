"""Independent integration tests for Gatekeeper.

The verifier generates fresh synthetic authority histories and grants using a
separate signer and Merkle implementation. Candidate behavior is evaluated
through subprocess CLI calls, never by importing candidate functions.
"""
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import traceback
import random

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

CANON = lambda o: json.dumps(o, sort_keys=True, ensure_ascii=True,
                            separators=(',', ':'), allow_nan=False).encode('utf-8')
H = lambda b: hashlib.sha256(b).digest()
PAD = H(b'GATEKEEPER/V2-PAD')
EMPTY = H(b'GATEKEEPER/V2-EMPTY')
DOMAIN = b'GATEKEEPER/V2\x00'
WORKSPACE = os.environ.get('GATEKEEPER_WORKSPACE', '/workspace')

# The verifier uses a new private seed for each run unless a seed is supplied
# for replay. Record it in trusted verifier logs before executing scenarios.
_RUN_SEED = None

def verifier_seed():
    global _RUN_SEED
    if _RUN_SEED is None:
        encoded = os.getenv('GATEKEEPER_TEST_SEED')
        if encoded is None:
            _RUN_SEED = secrets.token_bytes(32)
        else:
            if len(encoded) != 64 or any(x not in '0123456789abcdefABCDEF' for x in encoded):
                raise ValueError('GATEKEEPER_TEST_SEED must contain exactly 64 hexadecimal characters')
            _RUN_SEED = bytes.fromhex(encoded)
    return _RUN_SEED

def case_seed(name):
    return H(b'Gatekeeper verifier scenario seed\x00' + verifier_seed() + name.encode('ascii'))

def random_hex(rng, size):
    return rng.getrandbits(size * 8).to_bytes(size, 'big').hex()

# Run untrusted candidate processes as a low-privilege user in the separate
# verifier. The root-owned verifier source and reward directory are never
# made readable or writable to that user inside the verifier image.
def candidate_command(argv):
    """Use a separate launcher to drop uid safely under concurrent test threads."""
    if os.name == 'posix' and os.geteuid() == 0:
        return [sys.executable, str(Path(__file__).with_name('candidate_exec.py')), *argv]
    return argv



def priv(): return Ed25519PrivateKey.generate()


def pub(key):
    return base64.b64encode(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)).decode('ascii')


def sign(kind, data, key, field='signature', exclude=None):
    exclude = set(exclude or ['signature'])
    body = {k: v for k, v in data.items() if k not in exclude}
    message = DOMAIN + kind.encode('ascii') + b'\x00' + CANON(body)
    signature = base64.b64encode(key.sign(message)).decode('ascii')
    return dict(data, **{field: signature})


def hash_record(data): return H(CANON(data)).hex()


def tree_and_proofs(records):
    if not records: return EMPTY.hex(), []
    leaves = [H(b'\x00' + CANON(o)) for o in records]
    padded = 1 << (len(leaves)-1).bit_length()
    leaves += [PAD] * (padded-len(leaves))
    levels = [leaves]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append([H(b'\x01'+row[i]+row[i+1]) for i in range(0, len(row), 2)])
    proofs = []
    for idx in range(len(records)):
        siblings = []
        i = idx
        for layer in levels[:-1]:
            siblings.append(layer[i ^ 1].hex())
            i //= 2
        proofs.append(siblings)
    return levels[-1][0].hex(), proofs


class Driver:
    def __init__(self, directory, *, signing_seed=None):
        self.directory = Path(directory)
        self.state = self.directory / 'state'
        self.seq = 0
        self.tip = '0' * 64
        self.issued_tick = 0
        if signing_seed is None:
            self.key = priv()
            self.holder_key = priv()
        else:
            self.key = Ed25519PrivateKey.from_private_bytes(H(signing_seed + b'/root-key'))
            self.holder_key = Ed25519PrivateKey.from_private_bytes(H(signing_seed + b'/holder-key'))
        self.root_id = 'root-a'
        self.root_priv = self.key
        self.files = 0
        self.history = []
        self.trust = {
            'schema': 2, 'tenant': 'north', 'offline_window_ticks': 40,
            'genesis_root_key_id': self.root_id,
            'genesis_root_public_key': pub(self.key)
        }

    def write(self, data):
        self.files += 1
        p = self.directory / f'input_{self.files:04}.json'
        p.write_bytes(CANON(data))
        return p

    def call(self, command, obj=None, tick=None, after=None, limit=None, *, ok=True):
        args = [sys.executable, '-m', 'gatekeeper', command,
                '--state', str(self.state)]
        if obj is not None:
            if command == 'init': args += ['--trust', str(self.write(obj))]
            elif command == 'ingest' or command == 'decide':
                args += ['--file', str(self.write(obj))]
        if tick is not None: args += ['--tick', str(tick)]
        if after is not None: args += ['--after', str(after)]
        if limit is not None: args += ['--limit', str(limit)]
        env = dict(os.environ, PYTHONPATH=WORKSPACE)
        try:
            r = subprocess.run(candidate_command(args), cwd=WORKSPACE, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=9)
        except subprocess.TimeoutExpired as e:
            raise AssertionError(f'{command}: timed out') from e
        if ok:
            assert r.returncode == 0, f'{command} failed: {r.stderr[:240]!r}'
            assert r.stdout.strip(), f'{command}: empty stdout'
            try: out = json.loads(r.stdout)
            except Exception as e: raise AssertionError(f'{command} non-JSON stdout: {r.stdout[:100]!r}') from e
            assert isinstance(out,dict), f'{command}: output not object'
            return out
        assert r.returncode != 0, f'{command} should reject malformed input'
        assert not r.stdout.strip(), f'{command}: invalid-input wrote to stdout'
        err=json.loads(r.stderr)
        assert err.get('error') in {'INVALID_INPUT','IO_ERROR','STATE_MISSING','STATE_CORRUPT','INIT_CONFLICT'},err
        return err

    def initialize(self):
        output = self.call('init',self.trust)
        assert output == {'state':'INITIALIZED','tenant':'north'},output

    def grant(self, grant_id='g0', *, not_before=100, expires=200,
              actions=None, prefix='/units/pump', depth=3, delegable=True,
              parent=None, holder=None, issued_seq=None, signer=None, holder_key=None):
        obj = {'kind':'grant','tenant':'north','grant_id':grant_id,
               'parent_id':parent, 'issuer_key': signer or self.root_id,
               'issued_seq': issued_seq if issued_seq is not None else self.seq+1,
               'holder': holder or 'tech:lead',
               'holder_key': pub(holder_key or self.holder_key),
               'resource_prefix': prefix, 'actions': actions or ['inspect', 'restart'],
               'not_before': not_before, 'expires':expires,
               'delegable':delegable,'remaining_depth':depth}
        return sign('grant',obj,self.key if parent is None else self.holder_key)

    def checkpoint(self, *, tick=100, grants=(), revoked=(), apply=True):
        records = sorted(grants, key=lambda r:r['grant_id'])
        root,paths = tree_and_proofs(records)
        obj = {'kind':'checkpoint','tenant':'north', 'seq':self.seq+1,
               'previous_digest':self.tip,'issued_tick':tick,
               'revoked_ids':sorted(revoked),'issuance_count':len(records),
               'issuance_root':root,'signer':self.root_id}
        cp=sign('checkpoint',obj,self.key)
        self.seq+=1;self.issued_tick=tick;self.tip=hash_record(cp)
        self.history.append(cp)
        bundles = []
        for idx,grant in enumerate(records):
            bundles.append({'kind':'issuance_bundle','grant':grant,
                            'proof':{'checkpoint_seq':self.seq,'index':idx,
                                     'count':len(records),'siblings':paths[idx]}})
        if apply:
            out=self.call('ingest',cp)
            assert out['state'] in {'APPLIED','QUARANTINED'},out
        return cp,bundles

    def rotate(self, *, tick=101, apply=True, new_id='root-b'):
        next_key=priv()
        obj={'kind':'rotate','tenant':'north','seq':self.seq+1,
             'previous_digest':self.tip,'issued_tick':tick,
             'old_signer':self.root_id,'new_signer':new_id,
             'new_root_public_key':pub(next_key)}
        base=DOMAIN + b'rotate\x00' + CANON(obj)
        rot=dict(obj,old_signature=base64.b64encode(self.key.sign(base)).decode(),
                 new_signature=base64.b64encode(next_key.sign(base)).decode())
        self.seq+=1;self.issued_tick=tick;self.tip=hash_record(rot)
        self.history.append(rot)
        self.key=next_key;self.root_id=new_id
        if apply:
            out=self.call('ingest',rot)
            assert out['state']=='APPLIED',out
        return rot

    def delegate(self, parent, child_id='g1', holder_key=None, holder='tech:field',
                 prefix='/units/pump/a', actions=None, expires=180,
                 depth=1, delegable=True):
        body={'kind':'grant','tenant':'north','grant_id':child_id,
              'parent_id':parent['grant_id'],
              'issuer_key':'holder:'+parent['grant_id'],
              'issued_seq':self.seq,'holder':holder,
              'holder_key':pub(holder_key or priv()),
              'resource_prefix':prefix, 'actions':actions or ['inspect'],
              'not_before':101,'expires':expires,
              'delegable':delegable,'remaining_depth':depth}
        return sign('grant',body,self.holder_key)

    def request(self, request_id='r0', *, holder='tech:lead', chain=None,
                resource='/units/pump/a', action='inspect', key=None):
        obj={'kind':'request','tenant':'north','request_id':request_id,
             'holder':holder,'resource':resource,'action':action,
             'chain':chain or ['g0']}
        return sign('request',obj,key or self.holder_key)

    def accept(self, bundle):
        out=self.call('ingest',bundle)
        assert out['state']=='APPLIED',out
        return out

    def decision(self,req,tick,decision,reason,applied):
        out=self.call('decide',req,tick=tick)
        assert set(out)=={'request_id','decision','reason','applied','checkpoint_seq','grant_path'},out
        assert (out['decision'],out['reason'],out['applied'])==(decision,reason,applied),out
        return out


def seeded(directory, *, initial_tick=100):
    d=Driver(directory)
    d.initialize()
    root=d.grant()
    cp,bundles=d.checkpoint(tick=initial_tick,grants=[root])
    d.accept(bundles[0])
    return d,root,bundles[0]


def s01_happy_replay(tmp):
    d,root,_=seeded(tmp)
    req=d.request('r_1')
    a=d.decision(req,110,'ALLOW','AUTHORIZED',True)
    assert a['checkpoint_seq']==1 and a['grant_path']==['g0']
    d.decision(req,111,'ALLOW','DUPLICATE',False)
    rows=d.call('effects')
    assert len(rows['effects'])==1,rows
    assert rows['effects'][0]['request_id']=='r_1'
    assert rows['effects'][0]['request_digest']==hash_record(req)
    assert rows['effects'][0]['index']==1
    d.decision(d.request('r_2'),111,'ALLOW','AUTHORIZED',True)
    page=d.call('effects',after=0,limit=1)
    assert len(page['effects'])==1 and page['next_after']==1
    page=d.call('effects',after=1,limit=10)
    assert len(page['effects'])==1 and page['next_after']==2


def s02_signature_and_liveness(tmp):
    d,root,_=seeded(tmp)
    a=d.request('auth_a')
    forged=dict(a,resource='/units/pump/forged')
    d.decision(forged,107,'DENY','BAD_SIGNATURE',False)
    d.decision(d.request('auth_b'),108,'ALLOW','AUTHORIZED',True)
    replaced=d.request('auth_b',action='restart')
    d.decision(replaced,109,'DENY','REQUEST_ID_REUSE',False)
    assert len(d.call('effects')['effects'])==1


def s03_signed_uncommitted_root(tmp):
    d,root,_=seeded(tmp)
    # Correct root signature but missing proof of issuance in authenticated batch.
    fake=d.grant(grant_id='forged_issued',issued_seq=1)
    cp_fake,bundles_fake=d.checkpoint(tick=115,grants=[],revoked=[])
    # attempt to pass fake credential as member of empty batch
    improper={'kind':'issuance_bundle','grant':fake,
              'proof':{'checkpoint_seq':1,'index':0,'count':1,'siblings':[]}}
    response=d.call('ingest',improper)
    assert response['state']=='REJECTED' and response['reason']=='BAD_PROOF',response
    d.decision(d.request('valid_still'),118,'ALLOW','AUTHORIZED',True)


def s04_delayed_issuance(tmp):
    d=Driver(tmp);d.initialize()
    root=d.grant()
    cp,bundles=d.checkpoint(tick=100,grants=[root],apply=False)
    before=d.call('ingest',bundles[0]); assert before['state']=='PENDING',before
    d.decision(d.request('pending_req'),100,'DEFER','NO_CHECKPOINT',False)
    out=d.call('ingest',cp); assert out['state']=='APPLIED',out
    d.decision(d.request('now_auth'),101,'ALLOW','AUTHORIZED',True)


def s05_delegate_scope_and_ancestry(tmp):
    d,root,_=seeded(tmp)
    leafpriv=priv()
    delegated=d.delegate(root,holder_key=leafpriv)
    d.accept(delegated)
    req=d.request('r_child',holder='tech:field',chain=['g0','g1'],key=leafpriv)
    d.decision(req,113,'ALLOW','AUTHORIZED',True)
    bad=d.request('r_cross',holder='tech:field',chain=['g0','g1'],
                  resource='/units/pumpology/a',key=leafpriv)
    d.decision(bad,114,'DENY','OUT_OF_SCOPE',False)
    over=d.delegate(root,child_id='g2',holder_key=leafpriv,
                    prefix='/units',actions=['inspect','restart'],depth=2)
    result=d.call('ingest',over)
    assert result['state'] == 'REJECTED', result
    # An invalid attenuation must not authenticate a broadened child.
    invalid=d.request('r_over',holder='tech:field',chain=['g0','g2'],key=leafpriv)
    got=d.call('decide',invalid,tick=115)
    assert got['decision']!='ALLOW', got


def s06_revoke_after_allowed(tmp):
    d,root,_=seeded(tmp)
    old_req=d.request('r_1')
    d.decision(old_req,108,'ALLOW','AUTHORIZED',True)
    d.checkpoint(tick=110,grants=[],revoked=['g0'])
    d.decision(d.request('r_new'),112,'DENY','REVOKED',False)
    d.decision(old_req,113,'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==1


def s07_no_rotation_freshness_extension(tmp):
    d,root,_=seeded(tmp)
    d.rotate(tick=130)
    d.decision(d.request('too_old'),141,'DEFER','STALE_CHECKPOINT',False)
    assert d.call('status')['last_checkpoint_tick']==100


def s08_clock_cache_and_replay(tmp):
    d,root,_=seeded(tmp)
    req=d.request('once')
    d.decision(req,106,'ALLOW','AUTHORIZED',True)
    d.decision(d.request('outscope',resource='/other'),132,'DENY','OUT_OF_SCOPE',False)
    cache=d.state/'cache';cache.mkdir(parents=True,exist_ok=True)
    (cache/'index.json').write_text('{"seq":0,"valid":true}')
    d.decision(d.request('rollback'),110,'DEFER','TIME_ROLLBACK',False)
    d.decision(req,110,'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==1
    assert d.call('status')['highest_protected_tick']==132


def s09_out_of_order_and_untrusted(tmp):
    d=Driver(tmp);d.initialize()
    root=d.grant()
    cp1,bundles=d.checkpoint(tick=100,grants=[root],apply=False)
    rot=d.rotate(tick=101,apply=False)
    cp3,_=d.checkpoint(tick=105,grants=[],apply=False)
    assert d.call('ingest',cp3)['state']=='PENDING'
    assert d.call('ingest',rot)['state']=='PENDING'
    assert d.call('ingest',cp1)['state']=='APPLIED'
    st=d.call('status'); assert st['seq']==3,st
    d.accept(bundles[0])
    d.decision(d.request('liveness'),110,'ALLOW','AUTHORIZED',True)


def s10_authenticated_fork(tmp):
    d,root,_=seeded(tmp)
    parent = d.tip
    auth=d.key
    d.checkpoint(tick=109,grants=[],revoked=[])
    sibling={'kind':'checkpoint','tenant':'north','seq':2,
             'previous_digest':parent,'issued_tick':110,
             'revoked_ids':['alternate'], 'issuance_count':0,
             'issuance_root':EMPTY.hex(),'signer':'root-a'}
    sibling=sign('checkpoint',sibling,auth)
    out=d.call('ingest',sibling)
    assert out['state']=='QUARANTINED',out
    d.decision(d.request('new'),111,'DEFER','QUARANTINED',False)


def s11_json_error_isolation(tmp):
    d,root,_=seeded(tmp)
    baseline=d.call('status')
    p=d.directory/'malformed.json';p.write_text('{"a":1,"a":2}')
    r=subprocess.run(candidate_command([sys.executable,'-m','gatekeeper','ingest','--state',str(d.state),
                      '--file',str(p)]),cwd=WORKSPACE,env=dict(os.environ,PYTHONPATH=WORKSPACE),
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=9)
    assert r.returncode!=0 and not r.stdout.strip()
    assert d.call('status')==baseline
    d.decision(d.request('survive'),107,'ALLOW','AUTHORIZED',True)


def s12_late_forgery_does_not_poison(tmp):
    d,root,_=seeded(tmp)
    malicious={'kind':'checkpoint','tenant':'north','seq':999,
       'previous_digest':'f'*64,'issued_tick':120,
       'revoked_ids':['g0'],'issuance_count':0,'issuance_root':EMPTY.hex(),
       'signer':'root-a','signature':base64.b64encode(b'X'*64).decode()}
    out=d.call('ingest',malicious)
    assert out['state'] in {'PENDING','REJECTED'},out
    d.decision(d.request('normal'),115,'ALLOW','AUTHORIZED',True)
    assert d.call('status')['quarantined'] is False


def s13_concurrent_replay(tmp):
    d,root,_=seeded(tmp)
    req=d.request('same_request')
    path=d.write(req)
    def worker(i):
        args=[sys.executable,'-m','gatekeeper','decide','--state',str(d.state),
              '--file',str(path),'--tick','110']
        p=subprocess.run(candidate_command(args),cwd=WORKSPACE,env=dict(os.environ,PYTHONPATH=WORKSPACE),
                         capture_output=True, timeout=12)
        assert p.returncode==0,(p.returncode,p.stderr)
        return json.loads(p.stdout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        answers=list(pool.map(worker,range(6)))
    assert sum(x['applied'] for x in answers)==1,answers
    assert all(x['decision']=='ALLOW' for x in answers)
    assert len(d.call('effects')['effects'])==1


def s14_retired_root_key_cannot_backdate(tmp):
    d,root,bundle=seeded(tmp)
    old_root=d.key
    d.rotate(tick=105)
    # A historical root key can sign any bytes, but a freshly signed old-key
    # credential was never in the committed checkpoint issuance batch.
    forged=dict(root,grant_id='retroactive',issuer_key='root-a',issued_seq=1)
    forged.pop('signature')
    forged=sign('grant',forged,old_root)
    fake_bundle={'kind':'issuance_bundle','grant':forged,
                 'proof':{'checkpoint_seq':1,'index':0,'count':1,'siblings':[]}}
    out=d.call('ingest',fake_bundle)
    assert out['state']=='REJECTED' and out['reason']=='BAD_PROOF',out
    # Rotation does not invalidate an otherwise valid, earlier-issued root grant.
    d.decision(d.request('historical_legitimate'),110,'ALLOW','AUTHORIZED',True)
    # A new issuance batch under the *new* root must also work.
    new=d.grant(grant_id='modern',not_before=111,expires=160)
    cp,bundles=d.checkpoint(tick=111,grants=[new])
    d.accept(bundles[0])
    d.decision(d.request('new_root_valid',chain=['modern']),112,'ALLOW','AUTHORIZED',True)


def s15_revocation_decision_overlap(tmp):
    d,root,_=seeded(tmp)
    cp,_=d.checkpoint(tick=110,grants=[],revoked=['g0'],apply=False)
    request=d.request('racing_req')
    cpfile=d.write(cp);reqfile=d.write(request)
    def process(kind,path):
        args=[sys.executable,'-m','gatekeeper',kind,'--state',str(d.state),
              '--file',str(path)]
        if kind=='decide':args+=['--tick','112']
        proc=subprocess.run(candidate_command(args),cwd=WORKSPACE,env=dict(os.environ,PYTHONPATH=WORKSPACE),
                            capture_output=True,timeout=12)
        assert proc.returncode==0,(kind,proc.stderr)
        return json.loads(proc.stdout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        result_decide=pool.submit(process,'decide',reqfile)
        result_ingest=pool.submit(process,'ingest',cpfile)
        decision=result_decide.result()
        ingested=result_ingest.result()
    assert ingested['state']=='APPLIED',ingested
    assert (decision['decision'],decision['reason']) in {
        ('ALLOW','AUTHORIZED'),('DENY','REVOKED')},decision
    observed=d.call('effects')['effects']
    assert len(observed)==(1 if decision['applied'] else 0)
    d.decision(d.request('after_commit'),113,'DENY','REVOKED',False)
    assert len(d.call('effects')['effects'])==len(observed)




def s16_multi_leaf_issuance_and_proofs(tmp):
    d=Driver(tmp);d.initialize()
    grants=[d.grant(grant_id=f'g_{i}') for i in range(5)]
    cp,bundles=d.checkpoint(tick=100,grants=grants)
    for bundle in reversed(bundles):
        d.accept(bundle)
    for grant in grants:
        req=d.request(f'use_{grant["grant_id"]}',chain=[grant['grant_id']])
        d.decision(req,109,'ALLOW','AUTHORIZED',True)
    assert len(d.call('effects')['effects'])==5
    # A valid signature with another member's proof must not authenticate.
    mismatched=dict(bundles[1]);mismatched['proof']=bundles[2]['proof']
    response=d.call('ingest',mismatched)
    assert response['state']=='REJECTED' and response['reason']=='BAD_PROOF',response


def s17_deferred_delegation_reconciles(tmp):
    d=Driver(tmp);d.initialize()
    root=d.grant()
    cp,bundles=d.checkpoint(tick=100,grants=[root],apply=False)
    leaf_key=priv()
    child=d.delegate(root,child_id='g1',holder_key=leaf_key)
    pending=d.call('ingest',child)
    assert pending['state']=='PENDING' and pending['reason']=='MISSING_GRANT_PARENT',pending
    pending=d.call('ingest',bundles[0]); assert pending['state']=='PENDING',pending
    d.call('ingest',cp)
    status=d.call('status')
    assert status['pending_grant_count']==0 and status['authenticated_grant_count']==2,status
    request=d.request('child_after_reconcile',holder='tech:field',chain=['g0','g1'],key=leaf_key)
    d.decision(request,115,'ALLOW','AUTHORIZED',True)


def s18_invalid_authenticated_fork_cannot_quarantine(tmp):
    d,root,_=seeded(tmp)
    good=d.checkpoint(tick=105,grants=[],revoked=[])[0]
    forged=dict(good,signature=base64.b64encode(b'\x01'*64).decode('ascii'))
    answer=d.call('ingest',forged)
    assert answer['state']=='REJECTED' and answer['reason']=='BAD_SIGNATURE',answer
    assert d.call('status')['quarantined'] is False
    d.decision(d.request('after_bad_fork'),110,'ALLOW','AUTHORIZED',True)


def s19_failed_decide_input_does_not_advance_clock(tmp):
    d,root,_=seeded(tmp)
    before=d.call('status')['highest_protected_tick']
    bad=d.request('broken_request')
    bad['unexpected_field']='must fail schema'
    d.call('decide',bad,tick=130,ok=False)
    assert d.call('status')['highest_protected_tick']==before
    d.decision(d.request('good_followup'),110,'ALLOW','AUTHORIZED',True)


def s20_three_level_delegation_and_middle_revocation(tmp):
    # A valid signature on the leaf is insufficient: every intermediate grant
    # must attenuate the permission and survive the cumulative revocation set.
    d, root, _ = seeded(tmp)
    middle_key, leaf_key = priv(), priv()
    middle = d.delegate(root, child_id='middle', holder_key=middle_key,
                        holder='tech:middle', depth=2, expires=175)
    d.accept(middle)
    leaf_unverified = d.delegate(middle, child_id='leaf', holder_key=leaf_key,
                                 holder='tech:leaf', prefix='/units/pump/a',
                                 depth=1, expires=160)
    leaf = sign('grant', {k:v for k,v in leaf_unverified.items() if k!='signature'}, middle_key)
    d.accept(leaf)
    chain = ['g0', 'middle', 'leaf']
    good = d.request('deep_ok', holder='tech:leaf', chain=chain,
                     resource='/units/pump/a/valve', key=leaf_key)
    d.decision(good, 108, 'ALLOW', 'AUTHORIZED', True)
    # The middle holder is a real signer but cannot widen its own scope.
    wide = dict(leaf, grant_id='widened', resource_prefix='/units', signature=None)
    wide.pop('signature')
    wide = sign('grant', wide, middle_key)
    result = d.call('ingest', wide)
    assert result['state']=='REJECTED',result
    d.decision(d.request('segment_escape', holder='tech:leaf', chain=chain,
                         resource='/units/pump/ab', key=leaf_key),
               109, 'DENY','OUT_OF_SCOPE',False)
    d.checkpoint(tick=112, grants=[], revoked=['middle'])
    d.decision(d.request('revoked_middle', holder='tech:leaf', chain=chain,
                         resource='/units/pump/a/valve', key=leaf_key),
               115, 'DENY','REVOKED',False)
    d.decision(good, 116, 'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==1


def s21_historical_rotations_and_old_fork(tmp):
    # Historical signer verification must not accidentally use the current
    # root key when a delayed, valid conflict is delivered much later.
    d=Driver(tmp);d.initialize()
    g0=d.grant('epoch_0', not_before=100)
    cp1,b1=d.checkpoint(tick=100, grants=[g0], apply=False)
    original_key=d.key
    rot2=d.rotate(tick=101, apply=False, new_id='root-b')
    g1=d.grant('epoch_1', not_before=103)
    cp3,b3=d.checkpoint(tick=103, grants=[g1], apply=False)
    rot4=d.rotate(tick=105, apply=False, new_id='root-c')
    g2=d.grant('epoch_2', not_before=107)
    cp5,b5=d.checkpoint(tick=107, grants=[g2], apply=False)
    rot6=d.rotate(tick=109, apply=False, new_id='root-d')
    g3=d.grant('epoch_3', not_before=111)
    cp7,b7=d.checkpoint(tick=111, grants=[g3], apply=False)
    for record in (cp7, rot6, cp5, rot4, cp3, rot2):
        assert d.call('ingest',record)['state']=='PENDING'
    assert d.call('status')['seq']==0
    assert d.call('ingest',cp1)['state']=='APPLIED'
    assert d.call('status')['seq']==7
    for bundle in (b7[0], b5[0], b3[0], b1[0]):d.accept(bundle)
    for i in range(4):
        d.decision(d.request(f'epoch_request_{i}', chain=[f'epoch_{i}']),
                   114, 'ALLOW','AUTHORIZED',True)
    assert d.call('status')['last_checkpoint_tick']==111
    # A second root-a-signed child of checkpoint 1 is a true historical fork.
    alternate_key=priv()
    fork_body={'kind':'rotate','tenant':'north','seq':2,
        'previous_digest':hash_record(cp1),'issued_tick':102,
        'old_signer':'root-a','new_signer':'root-x',
        'new_root_public_key':pub(alternate_key)}
    message=DOMAIN+b'rotate\x00'+CANON(fork_body)
    fork=dict(fork_body,
        old_signature=base64.b64encode(original_key.sign(message)).decode('ascii'),
        new_signature=base64.b64encode(alternate_key.sign(message)).decode('ascii'))
    assert d.call('ingest',fork)['state']=='QUARANTINED'
    d.decision(d.request('new_after_old_fork', chain=['epoch_3']),
               115, 'DEFER','QUARANTINED',False)
    d.decision(d.request('epoch_request_3', chain=['epoch_3']),
               116, 'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==4


def s22_authenticated_collision_and_forged_nonpoisoning(tmp):
    d,root,_=seeded(tmp)
    # An unauthenticated collision must never disable the original grant.
    malformed=dict(root,signature=base64.b64encode(b'X'*64).decode('ascii'))
    forged={'kind':'issuance_bundle','grant':malformed,
            'proof':{'checkpoint_seq':1,'count':1,'index':0,'siblings':[]}}
    assert d.call('ingest',forged)['state']=='REJECTED'
    d.decision(d.request('after_forged_id'),108,'ALLOW','AUTHORIZED',True)
    # A genuinely committed second grant with the same ID is a conflict.
    collision=d.grant('g0',not_before=110, expires=180,actions=['inspect'])
    cp2,bundles=d.checkpoint(tick=110,grants=[collision])
    verdict=d.call('ingest',bundles[0])
    assert verdict['state']=='REJECTED' and verdict['reason']=='CONFLICT',verdict
    d.decision(d.request('after_authenticated_collision'),113,
               'DENY','INVALID_CHAIN',False)
    d.decision(d.request('after_forged_id'),114,'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==1


def s23_process_termination_receipt_recovery(tmp):
    # No candidate-specific crash hook. Kill ordinary CLI processes at
    # different points; accept either outcome for commands without stdout.
    d,root,_=seeded(tmp)
    requests=[d.request(f'kill_test_{i:02}') for i in range(12)]
    files=[d.write(r) for r in requests]
    processes=[]
    env=dict(os.environ,PYTHONPATH=WORKSPACE)
    for i,path in enumerate(files):
        proc=subprocess.Popen(candidate_command([sys.executable,'-m','gatekeeper','decide',
            '--state',str(d.state),'--file',str(path),'--tick','110']),
            cwd=WORKSPACE,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            )
        processes.append(proc)
    import time
    time.sleep(0.08)
    for idx in (0,3,6,9):
        if processes[idx].poll() is None: processes[idx].kill()
    for proc in processes:
        out,err=proc.communicate(timeout=20)
        if proc.returncode==0:
            answer=json.loads(out)
            assert answer['decision']=='ALLOW',answer
        else:
            assert proc.returncode in (-9,137), (proc.returncode,err[:300])
    # Regardless of whether a killed call committed, retry must not
    # introduce a second effect or lose a previously committed receipt.
    for i,record in enumerate(requests):
        result=d.call('decide',record,tick=110)
        assert result['decision']=='ALLOW' and result['reason'] in ('DUPLICATE','AUTHORIZED'),result
    effects=d.call('effects',after=0,limit=1000)['effects']
    assert len(effects)==len(requests), effects
    assert [row['index'] for row in effects]==list(range(1,13)),effects
    assert len({row['request_id'] for row in effects})==12
    for row in effects:
        index=int(row['request_id'].rsplit('_',1)[-1])
        assert row['request_digest']==hash_record(requests[index]), row
    assert d.call('status')['applied_request_count']==12
    # Read after complete restart with a malicious disposable cache snapshot.
    cache=d.state/'cache';cache.mkdir(exist_ok=True)
    (cache/'index.json').write_text('{"seq":0,"applied_request_count":0}')
    assert len(d.call('effects',after=4,limit=1000)['effects'])==8


def s24_permuted_authority_histories_equivalent(tmp):
    import random
    rng=random.Random(721904)
    left=Path(tmp)/'forward';right=Path(tmp)/'reversed'
    left.mkdir(mode=0o777);right.mkdir(mode=0o777)
    os.chmod(left,0o777);os.chmod(right,0o777)
    a=Driver(left);a.initialize()
    produced=[];grants=[]
    for k in range(9):
        tick=100+k
        if k in (3,6):
            produced.append(a.rotate(tick=tick,apply=False,new_id=f'root-{k}'))
        else:
            g=a.grant(f'varied_{k}',not_before=tick,expires=180)
            cp,bundles=a.checkpoint(tick=tick,grants=[g],apply=False)
            produced.append(cp);produced.extend(bundles)
            grants.append(g)
    b=Driver(right)
    b.trust=dict(a.trust)
    b.initialize()
    # Two distinct ingestion schedules for identical signed evidence.
    for rec in produced:a.call('ingest',rec)
    reordered=list(produced);rng.shuffle(reordered)
    for rec in reordered:b.call('ingest',rec)
    sa=a.call('status');sb=b.call('status')
    for key in ('seq','last_digest','last_checkpoint_tick',
                'authenticated_grant_count','pending_authority_count','pending_grant_count'):
        assert sa[key]==sb[key],(key,sa,sb)
    assert sa['seq']==9 and sa['authenticated_grant_count']==7,sa
    for i,g in enumerate(grants):
        req=a.request(f'varied_request_{i}',chain=[g['grant_id']])
        va=a.call('decide',req,tick=112)
        vb=b.call('decide',req,tick=112)
        assert va==vb,(va,vb)
        assert va['decision']=='ALLOW' and va['applied'],va
    assert a.call('effects')==b.call('effects')


def s25_heterogeneous_history_from_reversed_delivery(tmp):
    """Authenticated history is independent of delivery order across root epochs."""
    d=Driver(tmp);d.initialize()
    history=[]; bundles=[]; ids=[]
    for k in range(18):
        tick=100+k
        if k in (4,9,14):
            history.append(d.rotate(tick=tick,apply=False,new_id=f'root-epoch-{k}'))
        else:
            root=d.grant(f'hist_{k}',not_before=tick,expires=230,
                         prefix=f'/units/zone_{k}',actions=['inspect'])
            cp,b=d.checkpoint(tick=tick,grants=[root],apply=False)
            history.append(cp);bundles.extend(b);ids.append((k,root))
    # The records with the highest sequence arrive first and cannot confer trust.
    for record in reversed(history[1:]):
        assert d.call('ingest',record)['state']=='PENDING'
    before=d.call('status')
    assert before['seq']==0 and before['last_checkpoint_tick'] is None,before
    # An authenticated-looking outsider does not advance the verified tip.
    forged=dict(history[0],signature=base64.b64encode(b'F'*64).decode())
    assert d.call('ingest',forged)['state'] in ('PENDING','REJECTED')
    assert d.call('status')['seq']==0
    assert d.call('ingest',history[0])['state']=='APPLIED'
    final=d.call('status')
    assert final['seq']==18 and final['quarantined'] is False,final
    for bundle in reversed(bundles):d.accept(bundle)
    assert d.call('status')['authenticated_grant_count']==len(ids)
    for k,root in ids[::3]:
        d.decision(d.request(f'history_recover_{k}',chain=[root['grant_id']],
                             resource=f'/units/zone_{k}/instrument'),
                   125,'ALLOW','AUTHORIZED',True)
    assert len(d.call('effects')['effects'])==len(ids[::3])


def s26_delegated_id_collision_does_not_restore_authority(tmp):
    """Two valid parent signatures for one child ID disable the entire chain."""
    d,root,_=seeded(tmp)
    field_key=priv()
    child=d.delegate(root,child_id='field',holder_key=field_key,
                     holder='tech:field',prefix='/units/pump/a',depth=1)
    d.accept(child)
    original=d.request('before_collision',chain=['g0','field'],
                       holder='tech:field',key=field_key)
    d.decision(original,110,'ALLOW','AUTHORIZED',True)
    conflicting=d.delegate(root,child_id='field',holder_key=priv(),
                           holder='tech:field',prefix='/units/pump/b',depth=1)
    result=d.call('ingest',conflicting)
    assert result['state']=='REJECTED' and result['reason']=='CONFLICT',result
    d.decision(d.request('after_collision',chain=['g0','field'],
                         holder='tech:field',key=field_key),
               111,'DENY','INVALID_CHAIN',False)
    d.decision(original,112,'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==1


def s27_init_trust_validation_and_idempotence(tmp):
    """Invalid trust roots must be rejected before any persistent state exists."""
    d=Driver(tmp)
    cases=[
        dict(d.trust, schema=True),
        dict(d.trust, offline_window_ticks=0),
        dict(d.trust, offline_window_ticks=2**63),
        dict(d.trust, tenant='bad tenant'),
        dict(d.trust, genesis_root_key_id='invalid/root'),
        dict(d.trust, genesis_root_public_key='AAAA'),
    ]
    for invalid in cases:
        assert d.call('init',invalid,ok=False)['error']=='INVALID_INPUT'
    assert not (d.state/'protected'/'authority.sqlite3').exists()
    d.initialize()
    assert d.call('init',d.trust)=={'state':'UNCHANGED','tenant':'north'}
    invalid=dict(d.trust,offline_window_ticks=15)
    assert d.call('init',invalid,ok=False)['error']=='INIT_CONFLICT'
    assert d.call('status')['seq']==0


def s28_request_effects_and_priority_boundaries(tmp):
    """Receipts, tick monotonicity, pagination and revocation interact."""
    d,root,_=seeded(tmp)
    for i in range(9):
        d.decision(d.request(f'page_{i}'),111+i,'ALLOW','AUTHORIZED',True)
    page=d.call('effects',after=0,limit=3)
    seen=[]
    while page['effects']:
        seen.extend(page['effects'])
        page=d.call('effects',after=page['next_after'],limit=3)
    assert [x['index'] for x in seen]==list(range(1,10)),seen
    # An invalid signature cannot authorize or append an effect.
    forged=dict(d.request('untrusted'),signature=base64.b64encode(b'B'*64).decode())
    d.decision(forged,121,'DENY','BAD_SIGNATURE',False)
    assert d.call('status')['highest_protected_tick']==121
    d.decision(d.request('out_of_order'),120,'DEFER','TIME_ROLLBACK',False)
    # A successful old receipt is still acknowledged below protected time.
    d.decision(d.request('page_0'),118,'ALLOW','DUPLICATE',False)
    d.checkpoint(tick=122,grants=[],revoked=['g0'])
    d.decision(d.request('after_revocation'),123,'DENY','REVOKED',False)
    d.decision(d.request('page_0'),124,'ALLOW','DUPLICATE',False)
    assert d.call('status')['applied_request_count']==9


def s29_pending_forgery_and_causal_grant_recovery(tmp):
    """Fake pending envelopes cannot prevent a legitimate issuance and delegation."""
    d=Driver(tmp);d.initialize()
    root=d.grant('legitimate')
    cp,bundles=d.checkpoint(tick=100,grants=[root],apply=False)
    valid=bundles[0]
    poisoned=json.loads(json.dumps(valid))
    poisoned['grant']['signature']=base64.b64encode(b'Z'*64).decode()
    assert d.call('ingest',poisoned)['state']=='PENDING'
    assert d.call('ingest',valid)['state']=='PENDING'
    middle_key=priv()
    child=d.delegate(root,child_id='deferred',holder_key=middle_key,
                     holder='tech:middle',depth=1)
    assert d.call('ingest',child)['state']=='PENDING'
    assert d.call('ingest',cp)['state']=='APPLIED'
    state=d.call('status')
    assert state['authenticated_grant_count']==2 and not state['quarantined'],state
    d.decision(d.request('legit_after_poison',chain=['legitimate']),108,'ALLOW','AUTHORIZED',True)
    d.decision(d.request('delegated_after_poison',chain=['legitimate','deferred'],
                         holder='tech:middle',key=middle_key),
               109,'ALLOW','AUTHORIZED',True)


def s30_disposable_cache_and_boundary_freshness(tmp):
    """A stale cache and subsequent signing rotation must not renew freshness."""
    d,root,_=seeded(tmp)
    window=d.trust['offline_window_ticks']
    first=d.request('cached_authorization')
    d.decision(first,100+window,'ALLOW','AUTHORIZED',True)
    d.rotate(tick=100+window+1,new_id='root-after-window')
    cache=d.state/'cache';cache.mkdir(exist_ok=True)
    (cache/'authority_index.json').write_text('{"seq":0,"checkpoint":2000000}')
    d.decision(d.request('freshness_expired'),100+window+1,'DEFER','STALE_CHECKPOINT',False)
    d.decision(first,100+window+2,'ALLOW','DUPLICATE',False)
    assert len(d.call('effects')['effects'])==1



def s31_fresh_randomized_issuance_and_effect_model(tmp):
    """An unpredictable signed batch must authorize according to its own scopes."""
    import random
    seed = case_seed('s31')
    d=Driver(tmp, signing_seed=seed);d.initialize()
    rng=random.Random(int.from_bytes(H(seed + b'/sample'), 'big'))
    specs=[]
    for i in range(6):
        grant_id='rand_'+random_hex(rng, 7)
        prefix='/units/r_'+random_hex(rng, 5)
        actions=['inspect'] if i%2==0 else ['inspect','restart']
        grant=d.grant(grant_id,not_before=100,expires=180,depth=1,
                      actions=actions,prefix=prefix)
        specs.append((grant, prefix, actions))
    cp,bundles=d.checkpoint(tick=100,grants=[g for g,_,_ in specs])
    rng.shuffle(bundles)
    for bundle in bundles:d.accept(bundle)
    recorded=[]
    for grant,prefix,actions in specs:
        request_id='action_'+random_hex(rng, 8)
        req=d.request(request_id,chain=[grant['grant_id']],resource=prefix+'/asset',action='inspect')
        d.decision(req,110,'ALLOW','AUTHORIZED',True)
        recorded.append((req,grant,prefix,actions))
        if 'restart' not in actions:
            bad=d.request('wrong_'+random_hex(rng, 8),chain=[grant['grant_id']],
                          resource=prefix+'/asset',action='restart')
            d.decision(bad,110,'DENY','OUT_OF_SCOPE',False)
    effects=d.call('effects',after=0,limit=1000)['effects']
    assert len(effects)==6 and [e['index'] for e in effects]==list(range(1,7))
    assert {e['request_digest'] for e in effects}=={hash_record(r) for r,_,_,_ in recorded}
    revoke=recorded[rng.randrange(6)]
    d.checkpoint(tick=111,grants=[],revoked=[revoke[1]['grant_id']])
    d.decision(d.request('revoked_'+random_hex(rng, 8),chain=[revoke[1]['grant_id']],
                         resource=revoke[2]+'/asset'),112,'DENY','REVOKED',False)
    d.decision(revoke[0],112,'ALLOW','DUPLICATE',False)
    assert d.call('status')['applied_request_count']==6



def s32_randomized_authorization_state_model(tmp):
    """A signed batch, denied variants, revocation and old receipts share one ledger."""
    import random
    seed = case_seed('s32')
    rng=random.Random(int.from_bytes(H(seed + b'/sample'), 'big'))
    d=Driver(tmp, signing_seed=seed);d.initialize()
    specs=[]
    for i in range(5):
        gid='property_'+random_hex(rng, 6)
        prefix='/units/set_'+random_hex(rng, 4)
        actions=['inspect'] if i%2 else ['inspect','restart']
        g=d.grant(gid,prefix=prefix,actions=actions,expires=200,depth=2)
        specs.append((g,prefix,actions))
    _,bundles=d.checkpoint(tick=100,grants=[g for g,_,_ in specs])
    rng.shuffle(bundles)
    for bundle in bundles:d.accept(bundle)
    accepted={}
    for i,(g,prefix,actions) in enumerate(specs):
        req=d.request('accepted_'+random_hex(rng, 6),chain=[g['grant_id']],resource=prefix+'/member')
        allowed=d.decision(req,111+i,'ALLOW','AUTHORIZED',True)
        assert allowed['grant_path']==[g['grant_id']]
        accepted[g['grant_id']]=req
        outside=d.request('outside_'+random_hex(rng, 6),chain=[g['grant_id']],resource=prefix+'2/member')
        d.decision(outside,111+i,'DENY','OUT_OF_SCOPE',False)
        if 'restart' not in actions:
            wrong=d.request('action_'+random_hex(rng, 6),chain=[g['grant_id']],resource=prefix+'/member',action='restart')
            d.decision(wrong,111+i,'DENY','OUT_OF_SCOPE',False)
    selected=rng.choice(specs)[0]['grant_id']
    d.checkpoint(tick=120,grants=[],revoked=[selected])
    for i,(g,prefix,_) in enumerate(specs):
        new=d.request('after_'+random_hex(rng, 6),chain=[g['grant_id']],resource=prefix+'/member')
        if g['grant_id']==selected:
            d.decision(new,121+i,'DENY','REVOKED',False)
        else:
            d.decision(new,121+i,'ALLOW','AUTHORIZED',True)
        d.decision(accepted[g['grant_id']],121+i,'ALLOW','DUPLICATE',False)
    expected_count=2*len(specs)-1
    effects=d.call('effects',limit=1000)['effects']
    assert len(effects)==expected_count,effects
    assert [x['index'] for x in effects]==list(range(1,expected_count+1))
    assert len({x['request_id'] for x in effects})==expected_count
    assert d.call('status')['applied_request_count']==expected_count


def s33_independent_concurrent_requests_and_replay(tmp):
    """Different requests and duplicate retries race without losing or repeating effects."""
    d,_,_=seeded(tmp)
    requests=[d.request('parallel_'+secrets.token_hex(8)) for _ in range(9)]
    paths=[d.write(req) for req in requests]
    launched=[(i,path) for i,path in enumerate(paths) for _ in range(2)]
    import random
    random.Random(81438).shuffle(launched)
    def run(item):
        idx,path=item
        cmd=[sys.executable,'-m','gatekeeper','decide','--state',str(d.state),
             '--file',str(path),'--tick','110']
        out=subprocess.run(candidate_command(cmd),cwd=WORKSPACE,env=dict(os.environ,PYTHONPATH=WORKSPACE),
                           capture_output=True,timeout=15)
        assert out.returncode==0,(out.returncode,out.stderr[:150])
        return idx,json.loads(out.stdout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        answers=list(executor.map(run,launched))
    for i in range(len(requests)):
        rows=[x for k,x in answers if k==i]
        assert len(rows)==2
        assert sorted((r['reason'],r['applied']) for r in rows)==[('AUTHORIZED',True),('DUPLICATE',False)],rows
    ledger=d.call('effects',limit=1000)['effects']
    assert len(ledger)==len(requests),ledger
    assert [r['index'] for r in ledger]==list(range(1,len(requests)+1))
    assert {r['request_digest'] for r in ledger}=={hash_record(r) for r in requests}
    cache=d.state/'cache';cache.mkdir(exist_ok=True)
    (cache/'replay.json').write_text('{"applied_request_count": 0}')
    for req in requests:d.decision(req,111,'ALLOW','DUPLICATE',False)
    assert d.call('status')['applied_request_count']==len(requests)


def s34_overflow_safe_freshness_and_protected_clock(tmp):
    """Large protocol-valid timestamps must not overflow the freshness calculation."""
    d=Driver(tmp)
    upper=2**63-1
    d.trust['offline_window_ticks']=upper
    d.initialize()
    g=d.grant('time_upper_bound',expires=upper)
    _,bundles=d.checkpoint(tick=100,grants=[g])
    d.accept(bundles[0])
    successful=d.request('near_max',chain=['time_upper_bound'])
    d.decision(successful,upper-1,'ALLOW','AUTHORIZED',True)
    d.decision(d.request('expired_at_max',chain=['time_upper_bound']),upper,'DENY','EXPIRED',False)
    d.decision(d.request('clock_reverted',chain=['time_upper_bound']),upper-1,'DEFER','TIME_ROLLBACK',False)
    d.decision(successful,upper,'ALLOW','DUPLICATE',False)
    assert d.call('status')['highest_protected_tick']==upper
    assert len(d.call('effects')['effects'])==1

def s35_concurrent_revocation_effect_snapshot(tmp):
    """Every successful effect must precede its racing revocation in the authority history."""
    d, _, _ = seeded(tmp)
    revocation, _ = d.checkpoint(tick=110, grants=[], revoked=['g0'], apply=False)
    inputs = [(f'contender_{i}', d.write(d.request(f'contender_{i}'))) for i in range(7)]
    cp_path = d.write(revocation)

    def process(job):
        kind, file_path = job
        cmd = [sys.executable, '-m', 'gatekeeper', kind,
               '--state', str(d.state), '--file', str(file_path)]
        if kind == 'decide':
            cmd += ['--tick', '112']
        completed = subprocess.run(candidate_command(cmd), cwd=WORKSPACE,
                                   env=dict(os.environ, PYTHONPATH=WORKSPACE),
                                   capture_output=True, timeout=20)
        assert completed.returncode == 0, (kind, completed.stderr[:250])
        return kind, json.loads(completed.stdout)

    jobs = [('decide', item[1]) for item in inputs]
    jobs.insert(3, ('ingest', cp_path))
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(process, jobs))
    ingests = [result for kind, result in results if kind == 'ingest']
    assert len(ingests) == 1 and ingests[0]['state'] == 'APPLIED', ingests
    decisions = [result for kind, result in results if kind == 'decide']
    applied = [result for result in decisions if result['applied']]
    assert all((r['decision'], r['reason'], r['applied']) in
               {('ALLOW', 'AUTHORIZED', True), ('DENY', 'REVOKED', False)}
               for r in decisions), decisions
    ledger = d.call('effects', limit=1000)['effects']
    assert len(ledger) == len(applied), (ledger, applied)
    assert [row['index'] for row in ledger] == list(range(1, len(ledger) + 1))
    assert all(row['authority_seq'] == 1 and row['checkpoint_seq'] == 1
               for row in ledger), ledger
    assert {row['request_id'] for row in ledger} == \
           {result['request_id'] for result in applied}
    for rid, path in inputs:
        if rid in {result['request_id'] for result in applied}:
            d.decision(json.loads(path.read_text()), 113, 'ALLOW', 'DUPLICATE', False)
        else:
            d.decision(json.loads(path.read_text()), 113, 'DENY', 'REVOKED', False)
    d.decision(d.request('new_after_revocation'), 114, 'DENY', 'REVOKED', False)
    assert len(d.call('effects')['effects']) == len(ledger)


def s36_corrupt_protected_state_fails_closed(tmp):
    """Damaged authoritative storage must not be silently reinitialized."""
    d, _, _ = seeded(tmp)
    prior = d.request('durable_pre_damage')
    d.decision(prior, 111, 'ALLOW', 'AUTHORIZED', True)
    protected = d.state / 'protected'
    database = protected / 'authority.sqlite3'
    assert database.is_file()
    database.write_bytes(b'not a SQLite database - intentionally corrupted\n')
    for command in ('status', 'effects'):
        err = d.call(command, ok=False)
        assert err['error'] == 'STATE_CORRUPT', (command, err)
    err = d.call('decide', d.request('must_not_reapply'), tick=112, ok=False)
    assert err['error'] == 'STATE_CORRUPT', err
    assert database.read_bytes().startswith(b'not a SQLite')


def s37_cross_tenant_isolation_and_clock(tmp):
    """Foreign signed evidence must not alter authority; a valid denied request advances time."""
    d, _, _ = seeded(tmp)
    before = d.call('status')
    foreign_cp = {'kind': 'checkpoint', 'tenant': 'other-tenant', 'seq': 2,
                  'previous_digest': d.tip, 'issued_tick': 108,
                  'revoked_ids': ['g0'], 'issuance_count': 0,
                  'issuance_root': EMPTY.hex(), 'signer': d.root_id}
    foreign_cp = sign('checkpoint', foreign_cp, d.key)
    ingested = d.call('ingest', foreign_cp)
    assert (ingested['state'], ingested['reason']) == ('REJECTED', 'WRONG_TENANT'), ingested
    status = d.call('status')
    assert (status['seq'], status['last_digest'], status['authenticated_grant_count']) == \
           (before['seq'], before['last_digest'], before['authenticated_grant_count']), status
    foreign_req = d.request('foreign_request')
    foreign_req['tenant'] = 'other-tenant'
    foreign_req = sign('request', {k: v for k, v in foreign_req.items() if k != 'signature'}, d.holder_key)
    d.decision(foreign_req, 120, 'DENY', 'CROSS_TENANT', False)
    assert d.call('status')['highest_protected_tick'] == 120
    d.decision(d.request('rolled_back_after_foreign'), 119, 'DEFER', 'TIME_ROLLBACK', False)
    d.decision(d.request('legitimate_after_foreign'), 121, 'ALLOW', 'AUTHORIZED', True)
    assert d.call('status')['applied_request_count'] == 1


SCENARIOS=[
    ('valid issuance, replay receipts and effect pagination',s01_happy_replay),
    ('signature forgery and request-ID reuse',s02_signature_and_liveness),
    ('historical root grant requires checkpoint proof',s03_signed_uncommitted_root),
    ('late issuance bundle and pending parent',s04_delayed_issuance),
    ('delegation attenuation and path boundaries',s05_delegate_scope_and_ancestry),
    ('monotonic revocation and old receipt',s06_revoke_after_allowed),
    ('rotation does not renew offline freshness',s07_no_rotation_freshness_extension),
    ('clock, cache rollback, durable effect',s08_clock_cache_and_replay),
    ('reorder across rotation and checkpoint',s09_out_of_order_and_untrusted),
    ('genuinely signed fork quarantine',s10_authenticated_fork),
    ('strict malformed document without side effect',s11_json_error_isolation),
    ('untrusted far-future authority does not poison',s12_late_forgery_does_not_poison),
    ('multi-process duplicate decision concurrency',s13_concurrent_replay),
    ('retired root key backdating and modern reissuance',s14_retired_root_key_cannot_backdate),
    ('concurrent decision and revocation legal outcomes',s15_revocation_decision_overlap),
    ('five-way issuance and independent Merkle paths',s16_multi_leaf_issuance_and_proofs),
    ('causal child delegation and late issuance reconciliation',s17_deferred_delegation_reconciles),
    ('forged authenticated-sibling claim cannot quarantine',s18_invalid_authenticated_fork_cannot_quarantine),
    ('malformed decision cannot advance persistent clock',s19_failed_decide_input_does_not_advance_clock),
    ('three-level attenuation and intermediate revocation',s20_three_level_delegation_and_middle_revocation),
    ('out-of-order multi-root epochs and historical authenticated fork',s21_historical_rotations_and_old_fork),
    ('unauthenticated versus authenticated grant-ID collision',s22_authenticated_collision_and_forged_nonpoisoning),
    ('process termination and durable replay receipts',s23_process_termination_receipt_recovery),
    ('permuted authenticated histories yield equivalent results',s24_permuted_authority_histories_equivalent),
    ('reversed delivery across 18 signing-history transitions',s25_heterogeneous_history_from_reversed_delivery),
    ('authenticated delegated-ID conflict and prior receipt',s26_delegated_id_collision_does_not_restore_authority),
    ('trust-anchor validation and idempotent initialization',s27_init_trust_validation_and_idempotence),
    ('receipt, clock, pagination and revocation consistency',s28_request_effects_and_priority_boundaries),
    ('forged pending grant nonpoisoning with delegated recovery',s29_pending_forgery_and_causal_grant_recovery),
    ('stale cache and exact freshness boundaries after rotation',s30_disposable_cache_and_boundary_freshness),
    ('fresh randomized multi-grant commitments and effect-model invariants',s31_fresh_randomized_issuance_and_effect_model),
    ('randomized independent authorization and revocation model',s32_randomized_authorization_state_model),
    ('concurrent distinct commands and duplicate receipts',s33_independent_concurrent_requests_and_replay),
    ('integer-limit freshness and monotonic protected time',s34_overflow_safe_freshness_and_protected_clock),
    ('concurrent revocation and effect-history linearization',s35_concurrent_revocation_effect_snapshot),
    ('irrecoverable protected-store corruption fails closed',s36_corrupt_protected_state_fails_closed),
    ('foreign-tenant evidence isolation and protected time',s37_cross_tenant_isolation_and_clock),
]


def main():
    seed = verifier_seed()
    print(f'VERIFIER_REPLAY_SEED={seed.hex()}', flush=True)
    seed_path = os.environ.get('GATEKEEPER_SEED_LOG_PATH')
    if seed_path:
        Path(seed_path).parent.mkdir(parents=True, exist_ok=True)
        Path(seed_path).write_text(seed.hex() + '\n')
    successes=[]
    for label,func in SCENARIOS:
        with tempfile.TemporaryDirectory(prefix='gatekeeper-verify-') as directory:
            os.chmod(directory, 0o777)
            try:
                func(directory)
                successes.append(label)
                print('PASS:',label,flush=True)
            except Exception as e:
                print('FAIL:',label,repr(e),flush=True)
                if os.getenv('VERIFIER_VERBOSE')=='1': traceback.print_exc()
    # Partial credit requires at least one authentic end-to-end authorization
    # and durable-effect scenario; genesis-only behavior is not the task.
    core_labels={SCENARIOS[i][0] for i in (0, 5, 12, 27, 30)}
    core_demonstrated=bool(core_labels.intersection(successes))
    score=(len(successes)/len(SCENARIOS)) if core_demonstrated else 0.0
    print(f'INTEGRATION SCENARIOS: {len(successes)}/{len(SCENARIOS)}, core demonstrated={core_demonstrated}, provisional reward {score:.6f}')
    reward=Path(os.environ.get('GATEKEEPER_REWARD_PATH', '/logs/verifier/reward.txt'))
    reward.parent.mkdir(parents=True,exist_ok=True)
    reward.write_text(f'{score:.6f}\n')
    return 0


if __name__=='__main__':sys.exit(main())
