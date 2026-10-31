"""Independent behavioral checks for offline authorization.

All policy keys are generated in the verifier process. The tested workspace
never receives private keys, expected responses, or this verifier source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import random
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def enc(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(enc(value)).hexdigest()


def full(status, code=None):
    return {'status':status,'code':code or status}


def evt(kind, authority, principal, asset='cooler', action='open', low=10, high=100):
    item = dict(type=kind,authority=authority,principal=principal,asset=asset,action=action)
    if kind == 'grant':
        item.update(valid_from_tick=low,expires_at_tick=high)
    return item


def edge(kind, authority, a, b, asset='cooler', action='open', low=10, high=100):
    item = dict(type=kind,authority=authority,delegator=a,delegatee=b,asset=asset,action=action)
    if kind == 'delegate':
        item.update(valid_from_tick=low,expires_at_tick=high)
    return item


def p(rid,t,site='alpha',principal='tech',asset='cooler',action='open'):
    return dict(kind='prepare',request_id=rid,site=site,principal=principal,asset=asset,action=action,tick=t)


def c(rid,t):
    return dict(kind='commit',request_id=rid,tick=t)


def ingest(b):
    return dict(kind='ingest',bundle=b)


class World:
    def __init__(self):
        self.keys = {name:Ed25519PrivateKey.generate() for name in ('alpha-1','alpha-2','beta-1','alpha-cp','beta-cp')}
        self.trust = {'sites':{
          'alpha':{'keys':[self.pub('alpha-1'),self.pub('alpha-2')],
                   'critical':[{'asset':'cooler','action':'open'}], 'checkpoint_keys':[self.pub('alpha-cp')]},
          'beta':{'keys':[self.pub('beta-1')], 'critical':[], 'checkpoint_keys':[self.pub('beta-cp')]}}}

    def pub(self,kid):
        public = self.keys[kid].public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        return dict(key_id=kid,public_key_hex=public,from_seq=1,through_seq=10000)

    def b(self,site,start,prev,kid,events):
        payload = dict(site=site,start_seq=start,prev_hash=prev,key_id=kid,events=events)
        return {**payload,'signature':self.keys[kid].sign(hashlib.sha256(enc(payload)).digest()).hex()}

    def hash(self,b):
        return digest({k:v for k,v in b.items() if k!='signature'})

    def cp(self, site, through, anchor, state_hash, kid=None):
        kid=kid or (site+'-cp')
        obj=dict(site=site,through_seq=through,anchor_hash=anchor,
                 state_hash=state_hash,key_id=kid)
        payload={'domain':'permitgate-checkpoint-v1',**obj}
        return {**obj,'signature':self.keys[kid].sign(hashlib.sha256(enc(payload)).digest()).hex()}


class Runner:
    def __init__(self,app,folder):
        self.app = app
        self.root = Path(folder)
        self.root.chmod(0o1777)
        self.state = self.root/'state.sqlite'
        self.n = 0
        self.trust = self.root/'trust.json'

    def write_trust(self,config):
        self.trust.write_bytes(enc(config))
        self.trust.chmod(0o644)

    def _spawn(self,command,timeout=35):
        env = os.environ.copy()
        env['PYTHONPATH'] = str(self.app)
        def drop():
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
        result = subprocess.run(command,cwd=str(self.app),env=env,stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                text=True,timeout=timeout,preexec_fn=drop if os.name=='posix' else None)
        if result.returncode:
            raise AssertionError(f'Candidate failed ({result.returncode}): {result.stderr[:600]}')

    def run(self, commands, expected=None, raws=None):
        self.n+=1
        token = secrets.token_hex(5)
        inp = self.root/f'input-{self.n}-{token}.jsonl'
        out = self.root/f'output-{self.n}-{token}.jsonl'
        if raws is None:
            inp.write_bytes(b''.join(enc(cmd)+b'\n' for cmd in commands))
        else:
            inp.write_bytes(b''.join(raw+b'\n' for raw in raws))
        inp.chmod(0o644)
        self._spawn([sys.executable,'-m','permitgate.cli','run','--trust',str(self.trust),
                     '--state',str(self.state),'--input',str(inp),'--output',str(out)])
        responses=[json.loads(line) for line in out.read_text('utf-8').splitlines()]
        if expected is not None:
            assert responses == expected, f'First mismatch: {next(((i, a, b) for i,(a,b) in enumerate(zip(expected,responses)) if a!=b), None)}; lengths {len(expected)} {len(responses)}'
        return responses

    def audit(self):
        self.n+=1
        out = self.root/f'audit-{self.n}.jsonl'
        self._spawn([sys.executable,'-m','permitgate.cli','audit','--state',str(self.state),
                     '--output',str(out)])
        return [json.loads(line) for line in out.read_text('utf-8').splitlines()]


def checkpoint_projection(site, batches, policies, tick=-1, retired=(), requests=(), effects=()):
    """Independent state summary; constructed from scenario events, not candidate SQL tables."""
    ids=sorted([[b['start_seq'],b['start_seq']+len(b['events'])-1,
                 hashlib.sha256(enc(b)).hexdigest()] for b in batches])
    last=batches[-1]
    state={'site':site,'through_seq':last['start_seq']+len(last['events'])-1,
           'anchor_hash':digest({k:v for k,v in last.items() if k!='signature'}),
           'max_tick':tick,'active_policy':policies,
           'open_requests':list(requests),'effects':list(effects),
           'retired':list(sorted(retired)),'accepted_ids':ids}
    return digest(state)


def checkpoint_cmd(cp):
    return dict(kind='checkpoint',checkpoint=cp)


def checkpoint_status(site='alpha'):
    return dict(kind='checkpoint_status',site=site)


def case_checkpoint_compaction_and_replay(r,w):
    grant=evt('grant','operations','tech')
    b1=w.b('alpha',1,'0'*64,'alpha-1',[grant])
    active=[[1,'grant','operations','tech',None,None,'cooler','open',10,100]]
    sh=checkpoint_projection('alpha',[b1],active)
    cp=w.cp('alpha',1,w.hash(b1),sh)
    other=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','other')])
    b2=w.b('alpha',2,w.hash(b1),'alpha-1',[evt('grant','operations','else')])
    assert r.run([ingest(b1),checkpoint_status(),checkpoint_cmd(cp),checkpoint_status(),
                  checkpoint_cmd(cp),ingest(b1),ingest(other),ingest(b2)],
                 [full('applied'),{'status':'ok','through_seq':0,'retained_from_seq':1,
                                   'accepted_batch_identities':1,'raw_batches':1,'gap':False},
                  full('checkpointed'),{'status':'ok','through_seq':1,'retained_from_seq':2,
                                       'accepted_batch_identities':1,'raw_batches':0,'gap':False},
                  full('duplicate'),full('duplicate'),full('rejected','overlap'),full('applied')])
    # A prior authenticated checkpoint cannot rewind the newer accepted head.
    old=w.cp('alpha',1,w.hash(b1),sh)
    assert r.run([checkpoint_cmd(old)])==[full('rejected','stale_checkpoint')]


def case_checkpoint_authentication_and_gap(r,w):
    one=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','tech')])
    active=[[1,'grant','operations','tech',None,None,'cooler','open',10,100]]
    sh=checkpoint_projection('alpha',[one],active)
    cp=w.cp('alpha',1,w.hash(one),sh)
    bad=dict(cp,signature='0'*128)
    tampered=dict(cp,state_hash='f'*64)
    mismatch=w.cp('alpha',1,w.hash(one),'f'*64)
    wrong=dict(cp,key_id='alpha-1')
    future=w.b('alpha',3,'0'*64,'alpha-2',[evt('grant','operations','pending')])
    assert r.run([ingest(one),checkpoint_cmd(bad),checkpoint_cmd(tampered),
                  checkpoint_cmd(mismatch),checkpoint_cmd(wrong),
                  ingest(future),checkpoint_status(),checkpoint_cmd(cp)],
                 [full('applied'),full('rejected','bad_signature'),
                  full('rejected','bad_signature'),full('rejected','state_mismatch'),
                  full('rejected','unknown_key'),full('buffered'),
                  {'status':'ok','through_seq':0,'retained_from_seq':1,
                   'accepted_batch_identities':1,'raw_batches':1,'gap':True},
                  full('rejected','gap')])
    # Invalid signatures and failed checkpoint installations did not truncate the journal.
    assert r.run([ingest(one)])==[full('duplicate')]


def case_checkpoint_preserves_prepare_evidence(r,w):
    events=[evt('grant','operations','op'),evt('grant','safety','safety'),
            edge('delegate','operations','op','tech'),edge('delegate','safety','safety','tech')]
    b1=w.b('alpha',1,'0'*64,'alpha-1',events)
    policy=[[1,'grant','operations','op',None,None,'cooler','open',10,100],
            [2,'grant','safety','safety',None,None,'cooler','open',10,100],
            [3,'delegate','operations',None,'op','tech','cooler','open',10,100],
            [4,'delegate','safety',None,'safety','tech','cooler','open',10,100]]
    req=[['hold','tech','cooler','open',[1,2,3,4],digest({'seqs':[1,2,3,4]})]]
    sh=checkpoint_projection('alpha',[b1],policy,tick=20,requests=req)
    cp=w.cp('alpha',4,w.hash(b1),sh)
    b2=w.b('alpha',5,w.hash(b1),'alpha-2',[evt('revoke','operations','op')])
    b3=w.b('alpha',6,w.hash(b2),'alpha-2',[evt('grant','operations','op')])
    assert r.run([ingest(b1),p('hold',20),checkpoint_cmd(cp),checkpoint_status(),
                  ingest(b2),c('hold',21),ingest(b3),c('hold',22),p('new',23),c('new',24)],
                 [full('applied'),full('prepared'),full('checkpointed'),
                  {'status':'ok','through_seq':4,'retained_from_seq':5,
                   'accepted_batch_identities':1,'raw_batches':0,'gap':False},
                  full('applied'),full('denied','authority_changed'),full('applied'),
                  full('denied','authority_changed'),full('prepared'),full('executed')])
    effects=r.audit()
    assert [row['request_id'] for row in effects]==['new']


def case_checkpoint_window_and_status_validation(r,w):
    # A correctly signed checkpoint outside its trusted sequence window is rejected.
    w.trust['sites']['alpha']['checkpoint_keys'][0]['from_seq']=3
    r.write_trust(w.trust)
    b=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','tech')])
    active=[[1,'grant','operations','tech',None,None,'cooler','open',10,100]]
    cp=w.cp('alpha',1,w.hash(b),checkpoint_projection('alpha',[b],active))
    responses=r.run([checkpoint_status('ghost'),
                     {'kind':'checkpoint_status','site':'alpha','extra':1},
                     ingest(b),checkpoint_cmd(cp),checkpoint_status()])
    assert responses==[full('denied','unknown_site'),full('denied','malformed'),
                       full('applied'),full('rejected','key_range'),
                       {'status':'ok','through_seq':0,'retained_from_seq':1,
                        'accepted_batch_identities':1,'raw_batches':1,'gap':False}]


def case_checkpoint_rejects_invalid_bootstrap(r,w):
    # A policy signer is not a checkpoint root; an overlapping key ID must fail startup.
    invalid=json.loads(json.dumps(w.trust))
    invalid['sites']['alpha']['checkpoint_keys'][0]['key_id']='alpha-1'
    r.write_trust(invalid)
    try:
        r.run([checkpoint_status()])
    except AssertionError:
        pass
    else:
        raise AssertionError('The gateway accepted a duplicated policy/checkpoint key ID')


def case_checkpoint_commit_race(r,w):
    import concurrent.futures
    events=[evt('grant','operations','op'),evt('grant','safety','safety'),
            edge('delegate','operations','op','tech'),edge('delegate','safety','safety','tech')]
    initial=w.b('alpha',1,'0'*64,'alpha-1',events)
    r.run([ingest(initial),p('race',20)], [full('applied'),full('prepared')])
    policy=[[1,'grant','operations','op',None,None,'cooler','open',10,100],
            [2,'grant','safety','safety',None,None,'cooler','open',10,100],
            [3,'delegate','operations',None,'op','tech','cooler','open',10,100],
            [4,'delegate','safety',None,'safety','tech','cooler','open',10,100]]
    req=[['race','tech','cooler','open',[1,2,3,4],digest({'seqs':[1,2,3,4]})]]
    state=checkpoint_projection('alpha',[initial],policy,tick=20,requests=req)
    cp=w.cp('alpha',4,w.hash(initial),state)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs=[pool.submit(r.run,[checkpoint_cmd(cp)]),pool.submit(r.run,[c('race',21)])]
        a=jobs[0].result()[0];b=jobs[1].result()[0]
    assert b==full('executed'),(a,b)
    assert a in (full('checkpointed'),full('rejected','state_mismatch')),(a,b)
    assert [e['request_id'] for e in r.audit()]==['race']
    assert r.run([c('race',21)])[0]==full('already_executed')


def case_authenticated_before_buffering(r,w):
    first=w.b('beta',1,'0'*64,'beta-1',[evt('grant','operations','chief','valve','inspect')])
    rejected=[]
    for idx in range(66):
        future=w.b('beta',idx+3,'0'*64,'beta-1',[evt('grant','operations',f'fake-{idx}','valve','inspect')])
        future['signature']='0'*128
        rejected.append(ingest(future))
    actual_future=w.b('beta',3,'1'*64,'beta-1',[evt('grant','operations','future','valve','inspect')])
    # Invalid future signatures must not consume a pending slot or block a different site.
    assert r.run(rejected+[ingest(actual_future),ingest(first),
                           p('known',20,'beta','chief','valve','inspect')]) == (
          [full('rejected','bad_signature')]*66+[full('buffered'),full('applied'),full('denied','gap')])


def case_repeat_prepare_evidence_is_fixed(r,w):
    events=[evt('grant','operations','op'),evt('grant','safety','safe'),
            edge('delegate','operations','op','tech'),edge('delegate','safety','safe','tech')]
    b1=w.b('alpha',1,'0'*64,'alpha-1',events)
    b2=w.b('alpha',5,w.hash(b1),'alpha-2',[evt('grant','operations','other'),
            edge('delegate','operations','other','tech')])
    b3=w.b('alpha',7,w.hash(b2),'alpha-2',[evt('revoke','operations','op')])
    r.run([ingest(b1),p('fixed',20),ingest(b2),p('fixed',21),ingest(b3),
           c('fixed',22),p('new',23),c('new',24)],
          [full('applied'),full('prepared'),full('applied'),full('prepared'),
           full('applied'),full('denied','authority_changed'),full('prepared'),full('executed')])
    assert [x['request_id'] for x in r.audit()] == ['new']



def case_repeat_prepare_returns_invalidated(r, w):
    """An old request cannot borrow a replacement grant after a revocation."""
    initial = [evt('grant', 'operations', 'operator'),
               evt('grant', 'safety', 'inspector'),
               edge('delegate', 'operations', 'operator', 'tech'),
               edge('delegate', 'safety', 'inspector', 'tech')]
    first = w.b('alpha', 1, '0' * 64, 'alpha-1', initial)
    revoked = w.b('alpha', 5, w.hash(first), 'alpha-2',
                  [evt('revoke', 'operations', 'operator')])
    restored = w.b('alpha', 6, w.hash(revoked), 'alpha-2',
                   [evt('grant', 'operations', 'operator')])
    commands = [ingest(first), p('original', 20), ingest(revoked),
                p('original', 21), ingest(restored), p('original', 22),
                c('original', 23), p('replacement', 24), c('replacement', 25),
                p('original', 26)]
    expected = [full('applied'), full('prepared'), full('applied'),
                full('denied', 'invalidated'), full('applied'),
                full('denied', 'invalidated'), full('denied', 'authority_changed'),
                full('prepared'), full('executed'), full('denied', 'invalidated')]
    r.run(commands, expected)
    effects = r.audit()
    assert [row['request_id'] for row in effects] == ['replacement'], effects
    assert effects[0]['prepare_hash'] == digest({'seqs': [2, 3, 4, 6]}), effects


def case_repeat_prepare_invalidated_on_expiry(r, w):
    """The original preparation cannot outlive an authorization window."""
    initial = [evt('grant', 'operations', 'operator', high=22),
               evt('grant', 'safety', 'inspector'),
               edge('delegate', 'operations', 'operator', 'tech'),
               edge('delegate', 'safety', 'inspector', 'tech')]
    batch = w.b('alpha', 1, '0' * 64, 'alpha-1', initial)
    r.run([ingest(batch), p('expiring', 20), p('expiring', 21),
           p('expiring', 22), c('expiring', 23)],
          [full('applied'), full('prepared'), full('prepared'),
           full('denied', 'invalidated'), full('denied', 'authority_changed')])
    assert r.audit() == []


def case_invalid_commands_do_not_advance_clock(r,w):
    b=w.b('beta',1,'0'*64,'beta-1',[evt('grant','operations','tech','valve','inspect')])
    commands=[ingest(b),p('r',20,'beta','tech','valve','inspect'),
              dict(kind='prepare',request_id='x',site='beta',principal='tech',asset='valve',
                   action='inspect',tick=True),
              dict(kind='prepare',request_id='x',site='beta',principal='tech',asset='valve',
                   action='inspect',tick=1<<63),
              dict(kind='prepare',request_id='x',site='unknown',principal='tech',asset='valve',
                   action='inspect',tick=999999),
              p('r2',21,'beta','tech','valve','inspect'),c('r',22)]
    assert r.run(commands)==[full('applied'),full('prepared'),full('denied','malformed'),
                             full('denied','malformed'),full('denied','unknown_site'),
                             full('prepared'),full('executed')]


def case_dual_and_regrant(r,w):
    initial=[evt('grant','operations','op'),evt('grant','safety','safety'),
             edge('delegate','operations','op','tech'),edge('delegate','safety','safety','tech')]
    first=w.b('alpha',1,'0'*64,'alpha-1',initial)
    revoke=w.b('alpha',5,w.hash(first),'alpha-2',[evt('revoke','operations','op')])
    regrant=w.b('alpha',6,w.hash(revoke),'alpha-2',[evt('grant','operations','op')])
    responses=r.run([ingest(first),p('a',20),p('b',20),c('a',21),ingest(revoke),c('b',22),
                     ingest(regrant),c('b',23),p('new',24),c('new',25),c('new',25)],
       [full('applied'),full('prepared'),full('prepared'),full('executed'),full('applied'),
        full('denied','authority_changed'),full('applied'),full('denied','authority_changed'),
        full('prepared'),full('executed'),full('already_executed')])
    rows=r.audit()
    assert [i['request_id'] for i in rows] == ['a','new'], rows
    assert rows[0]['prepare_hash']==digest({'seqs':[1,2,3,4]}),rows
    assert rows[0]['commit_tick']==21 and rows[1]['commit_tick']==25


def case_gap_and_retirement(r,w):
    first=w.b('beta',1,'0'*64,'beta-1',[evt('grant','operations','beta-op','valve','inspect')])
    b1=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','op')])
    b2=w.b('alpha',2,w.hash(b1),'alpha-1',[{'type':'retire_key','key_id':'alpha-1'}])
    b3=w.b('alpha',3,w.hash(b2),'alpha-1',[evt('grant','safety','bad')])
    b3good=w.b('alpha',3,w.hash(b2),'alpha-2',[evt('grant','safety','good')])
    b4=w.b('alpha',4,w.hash(b3good),'alpha-2',[evt('grant','operations','new')])
    assert r.run([ingest(first),ingest(b4),ingest(b4),
                  p('beta-req',20,'beta','beta-op','valve','inspect'),c('beta-req',21),
                  p('gap-req',20),ingest(b1),ingest(b2),ingest(b3),ingest(b3good),
                  ingest(b1),ingest(b4)],
       [full('applied'),full('buffered'),full('duplicate'),full('prepared'),full('executed'),
        full('denied','gap'),full('applied'),full('applied'),full('rejected','retired_key'),
        full('applied'),full('duplicate'),full('duplicate')])
    assert [e['request_id'] for e in r.audit()] == ['beta-req']


def case_alternative_graph(r,w):
    a=[evt('grant','operations','op1'),evt('grant','operations','op2'),
       evt('grant','safety','safe'),edge('delegate','operations','op1','node'),
       edge('delegate','operations','op2','node'),edge('delegate','operations','node','tech'),
       edge('delegate','safety','safe','tech'),edge('delegate','operations','node','op1')]
    b1=w.b('alpha',1,'0'*64,'alpha-1',a)
    b2=w.b('alpha',9,w.hash(b1),'alpha-1',[edge('undelegate','operations','op1','node')])
    b3=w.b('alpha',10,w.hash(b2),'alpha-2',[edge('undelegate','operations','op2','node')])
    b4=w.b('alpha',11,w.hash(b3),'alpha-2',[evt('grant','operations','op3'),edge('delegate','operations','op3','node')])
    r.run([ingest(b1),p('x',20),p('y',20),ingest(b2),c('x',21),ingest(b3),c('y',22),
           ingest(b4),c('y',23),p('z',24),c('z',25),p('z',26)],
        [full('applied'),full('prepared'),full('prepared'),full('applied'),full('executed'),
         full('applied'),full('denied','authority_changed'),full('applied'),
         full('denied','authority_changed'),full('prepared'),full('executed'),
         full('denied','already_executed')])
    rows=r.audit()
    assert [x['request_id'] for x in rows] == ['x','z'],rows
    assert rows[0]['prepare_hash'] == digest({'seqs':list(range(1,9))})


def case_conflicts_and_clock(r,w):
    b1=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','op'),
              evt('grant','safety','op'),edge('delegate','operations','op','tech'),
              edge('delegate','safety','op','tech')])
    b2=w.b('alpha',5,w.hash(b1),'alpha-1',[evt('grant','operations','other')])
    fork=w.b('alpha',5,'1'*64,'alpha-1',[evt('grant','operations','other')])
    bad=w.b('alpha',6,w.hash(b2),'alpha-1',[evt('grant','operations','new')])
    bad['signature']='0'*128
    r.run([ingest(b1),p('n',20),p('no',18),p('n',20,'alpha','outsider'),
           p('n',21),ingest(fork),ingest(b2),ingest(bad),
           p('m',19),c('missing',22)],
          [full('applied'),full('denied','unauthorized'),full('denied','stale_tick'),
           full('denied','unauthorized'),
           full('denied','unauthorized'),full('rejected','fork'),full('applied'),
           full('rejected','bad_signature'),full('denied','stale_tick'),
           full('denied','unknown_request')])
    # A denied preparation does not reserve an identifier.
    assert not r.audit()


def case_validation(r,w):
    raws = [b'{"kind":"commit","request_id":"x","tick":NaN}',
            b'{"kind":"commit","request_id":"x","tick":1,"tick":1}',
            b'\xff\xfe', b'{"kind":"commit","request_id":"no","tick":8}',
            b'[]',b'{"kind":"prepare","tick":1}',b'{"kind":"ingest","bundle":{}}']
    r.run([],raws=raws,expected=[full('denied','malformed'),full('denied','malformed'),
             full('denied','malformed'),full('denied','unknown_request'),
             full('denied','malformed'),full('denied','malformed'),full('rejected','malformed')])


def case_concurrent(r,w):
    b1=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','op'),
          evt('grant','safety','safe'),edge('delegate','operations','op','tech'),
          edge('delegate','safety','safe','tech')])
    r.run([ingest(b1),p('race',20)],[full('applied'),full('prepared')])
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _: r.run([c('race',21)])[0],range(2)))
    assert sorted(reply['status'] for reply in results)==['already_executed','executed'],results
    assert [row['request_id'] for row in r.audit()]==['race']
    # New process, older trusted tick is denied even though the request committed.
    r.run([c('race',19),c('race',22)], [full('denied','stale_tick'),full('already_executed')])


def case_large_graph(r,w):
    # A cyclic chain of delegation edges with a late path to the target.
    # Tests stateful evaluation rather than searching for a fixture principal.
    n = 450
    events=[evt('grant','operations','root-a','valve','inspect')]
    for i in range(n):
        events.append(edge('delegate','operations',f'node-{i}',f'node-{i+1}','valve','inspect'))
    events.append(edge('delegate','operations','root-a','node-0','valve','inspect'))
    events.append(edge('delegate','operations',f'node-{n}',f'node-{n-200}','valve','inspect'))
    b1=w.b('beta',1,'0'*64,'beta-1',events)
    r.run([ingest(b1),p('deep',20,'beta',f'node-{n}','valve','inspect'),
           c('deep',21),p('outside',22,'beta','absent','valve','inspect')],
          [full('applied'),full('prepared'),full('executed'),full('denied','unauthorized')])
    assert [row['request_id'] for row in r.audit()]==['deep']



def case_key_retirement_while_buffered(r,w):
    first=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','op'),
                 evt('grant','safety','safe'),edge('delegate','operations','op','tech'),
                 edge('delegate','safety','safe','tech')])
    retire=w.b('alpha',5,w.hash(first),'alpha-1',[{'type':'retire_key','key_id':'alpha-1'}])
    late=w.b('alpha',6,w.hash(retire),'alpha-1',[evt('grant','operations','ghost')])
    correct=w.b('alpha',6,w.hash(retire),'alpha-2',[evt('grant','operations','second')])
    r.run([ingest(late),p('pending',20),ingest(first),ingest(retire),
           p('ok',20),c('ok',21),ingest(late),ingest(correct)],
          [full('buffered'),full('denied','gap'),full('applied'),full('applied'),
           full('prepared'),full('executed'),full('rejected','retired_key'),
           full('applied')])
    assert [row['request_id'] for row in r.audit()] == ['ok']


def case_root_separation_and_windows(r,w):
    # Two authority labels on a single root do not meet dual-control.
    b1=w.b('alpha',1,'0'*64,'alpha-1',[
        evt('grant','operations','shared'),evt('grant','safety','shared'),
        edge('delegate','operations','shared','tech'),
        edge('delegate','safety','shared','tech')])
    b2=w.b('alpha',5,w.hash(b1),'alpha-2',[
        evt('grant','safety','independent','cooler','open',10,23),
        edge('delegate','safety','independent','tech','cooler','open',10,23)])
    b3=w.b('alpha',7,w.hash(b2),'alpha-2',[
        evt('grant','safety','independent','cooler','open',24,40),
        edge('delegate','safety','independent','tech','cooler','open',24,40)])
    r.run([ingest(b1),p('same',20),ingest(b2),p('expires',21),c('expires',23),
           ingest(b3),p('fresh',24),c('fresh',25)],
          [full('applied'),full('denied','unauthorized'),full('applied'),
           full('prepared'),full('denied','authority_changed'),full('applied'),
           full('prepared'),full('executed')])


def case_pending_limit(r,w):
    # A duplicate future bundle does not consume a pending slot.
    bundles=[w.b('alpha',i,'0'*64,'alpha-2',
                 [evt('grant','operations',f'user-{i}')]) for i in range(2,68)]
    cmds=[ingest(bundle) for bundle in bundles[:64]]
    cmds.extend([ingest(bundles[0]),ingest(bundles[64])])
    r.run(cmds,[full('buffered')]*64 + [full('duplicate'),full('rejected','pending_limit')])
    r.run([p('blocked',20)],[full('denied','gap')])


def case_many_requests(r,w):
    # A sustained mixed workload exercises durable indexing and graph walks.
    events=[evt('grant','operations','operator','valve','inspect'),
            edge('delegate','operations','operator','technician','valve','inspect')]
    for i in range(850):
        events.append(edge('delegate','operations',f'dummy-{i}',f'dummy-{i+1}',
                           'valve','inspect'))
    first=w.b('beta',1,'0'*64,'beta-1',events)
    commands=[ingest(first)]
    results=[full('applied')]
    for i in range(120):
        commands.extend([p(f'r-{i:04d}',50,'beta','technician','valve','inspect'),
                         c(f'r-{i:04d}',50)])
        results.extend([full('prepared'),full('executed')])
    r.run(commands,results)
    assert len(r.audit()) == 120


def case_randomized_policy(r,w):
    # Values are different on each run, so fixed output tables cannot pass.
    asset='asset-'+secrets.token_hex(6)
    action='action-'+secrets.token_hex(4)
    root='root-'+secrets.token_hex(6)
    mid='mid-'+secrets.token_hex(6)
    target='target-'+secrets.token_hex(6)
    b1=w.b('beta',1,'0'*64,'beta-1',[
        evt('grant','operations',root,asset,action,12,80),
        edge('delegate','operations',root,mid,asset,action,12,80),
        edge('delegate','operations',mid,target,asset,action,12,80),
        edge('delegate','operations',target,mid,asset,action,12,80)])
    b2=w.b('beta',5,w.hash(b1),'beta-1',[
        edge('undelegate','operations',root,mid,asset,action)])
    b3=w.b('beta',6,w.hash(b2),'beta-1',[
        edge('delegate','operations',root,mid,asset,action,25,40)])
    r.run([ingest(b1),p('perm-'+target,20,'beta',target,asset,action),
           ingest(b2),c('perm-'+target,21),ingest(b3),
           p('new-'+target,24,'beta',target,asset,action),
           p('late-'+target,25,'beta',target,asset,action),
           c('late-'+target,26)],
          [full('applied'),full('prepared'),full('applied'),
           full('denied','authority_changed'),full('applied'),
           full('denied','unauthorized'),full('prepared'),full('executed')])
    assert [row['request_id'] for row in r.audit()] == ['late-'+target]


def case_revoke_commit_race(r,w):
    import concurrent.futures
    first=w.b('alpha',1,'0'*64,'alpha-1',[
        evt('grant','operations','op'),evt('grant','safety','safety'),
        edge('delegate','operations','op','tech'),
        edge('delegate','safety','safety','tech')])
    revoke=w.b('alpha',5,w.hash(first),'alpha-2',[
        evt('revoke','operations','op')])
    r.run([ingest(first),p('contest',20)],[full('applied'),full('prepared')])
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1=pool.submit(r.run,[ingest(revoke)])
        f2=pool.submit(r.run,[c('contest',21)])
        a,b=f1.result()[0],f2.result()[0]
    assert a == full('applied'),a
    assert b in [full('executed'),full('denied','authority_changed')],b
    audit=r.audit()
    assert len(audit) == (1 if b['status']=='executed' else 0),audit
    assert r.run([c('contest',22)])[0] == (
        full('already_executed') if audit else full('denied','authority_changed'))


def case_signing_boundaries(r,w):
    empty='0'*64
    known=w.b('alpha',1,empty,'alpha-1',[evt('grant','operations','op')])
    modified=dict(known)
    modified['signature']='0'*128
    unknown=dict(known)
    unknown['key_id']='not-in-trust'
    future=w.b('alpha',10001,empty,'alpha-1',[
        evt('grant','operations','op')])
    invalid=w.b('alpha',1,empty,'alpha-1',[
        evt('grant','operations','op','cooler','open',20,20)])
    r.run([ingest(modified),ingest(unknown),ingest(future),ingest(invalid),ingest(known)],
          [full('rejected','bad_signature'),full('rejected','unknown_key'),
           full('rejected','key_range'),full('rejected','malformed'),full('applied')])


def case_bootstrap_fingerprint(r,w):
    r.run([])
    changed=json.loads(enc(w.trust))
    changed['sites']['alpha']['critical'].append({'asset':'unused','action':'run'})
    r.write_trust(changed)
    failed=False
    try:
        r.run([p('unexpected',20)])
    except AssertionError:
        failed=True
    assert failed, 'Existing persisted state accepted a different trusted bootstrap'


def case_request_binding(r,w):
    first=w.b('alpha',1,'0'*64,'alpha-1',[
        evt('grant','operations','op'),evt('grant','safety','safe'),
        edge('delegate','operations','op','tech'),
        edge('delegate','safety','safe','tech')])
    r.run([ingest(first),p('bound',20),p('bound',21,asset='other'),
           p('bound',21),c('bound',22),c('bound',22),p('bound',22),
           p('bound',20,'beta','tech','cooler','open')],
          [full('applied'),full('prepared'),full('denied','request_conflict'),
           full('prepared'),full('executed'),full('already_executed'),
           full('denied','already_executed'),full('denied','request_conflict')])
    assert len(r.audit())==1


def case_discard_bad_pending_link(r,w):
    first=w.b('alpha',1,'0'*64,'alpha-1',[evt('grant','operations','op')])
    wrong=w.b('alpha',2,'0'*64,'alpha-2',[evt('grant','safety','wrong')])
    right=w.b('alpha',2,w.hash(first),'alpha-2',[evt('grant','safety','right')])
    r.run([ingest(wrong),ingest(first),ingest(right),ingest(right)],
          [full('buffered'),full('applied'),full('applied'),full('duplicate')])
    assert not r.audit()

def case_randomized_delegation_model(r, w):
    """Check independently modeled authorization, saved evidence, and regrant fences.

    A logged seed makes the graph shape reproducible. Signing keys and file
    paths are generated independently for each run.
    """
    seed_text = os.environ.get('PG_VERIFY_SEED')
    seed = int(seed_text, 0) if seed_text is not None else secrets.randbits(64)
    print(f'MODEL_SEED={seed} (replay: PG_VERIFY_SEED={seed})', flush=True)
    rng = random.Random(seed)
    asset = 'machine-' + secrets.token_hex(4)
    action = 'activate-' + secrets.token_hex(4)
    w.trust['sites']['alpha']['critical'].append({'asset':asset, 'action':action})
    r.write_trust(w.trust)
    roots = [f'root-{i}' for i in range(5)]
    delegates = [f'd-{i}' for i in range(16)]
    people = roots + delegates
    # Keep a model of only the latest active version of each policy key.
    active = {}
    next_seq = 1

    def key(event):
        if event['type'] in ('grant', 'revoke'):
            return (event['authority'], 'grant', event['principal'], event['asset'], event['action'])
        return (event['authority'], 'delegate', event['delegator'], event['delegatee'],
                event['asset'], event['action'])

    def apply(events):
        nonlocal next_seq
        for e in events:
            k = key(e)
            active.pop(k, None)
            if e['type'] in ('grant', 'delegate'):
                active[k] = (next_seq, e)
            next_seq += 1

    def authorized(principal, tick, evidence=None):
        valid = [(seq, e) for seq,e in active.values()
                 if e['valid_from_tick'] <= tick < e['expires_at_tick']
                 and (evidence is None or seq in evidence)]
        def reach(label):
            roots_here = {e['principal'] for _,e in valid
                          if e['authority'] == label and e['type'] == 'grant'}
            backwards = {}
            for _,e in valid:
                if e['type'] == 'delegate' and e['authority'] == label:
                    backwards.setdefault(e['delegatee'], set()).add(e['delegator'])
            seen, stack, found = set(), [principal], set()
            while stack:
                person = stack.pop()
                if person in seen:
                    continue
                seen.add(person)
                if person in roots_here:
                    found.add(person)
                stack.extend(backwards.get(person, ()))
            return found
        op, safe = reach('operations'), reach('safety')
        return bool(op and safe and len(op | safe) >= 2)

    initial = []
    for label in ('operations', 'safety'):
        for root in roots[:3]:
            if rng.random() < .75:
                initial.append(evt('grant', label, root, asset, action, 10, 100))
        for _ in range(38):
            a, b = rng.sample(people, 2)
            initial.append(edge('delegate', label, a, b, asset, action, 10, 100))
    first = w.b('alpha',1,'0'*64,'alpha-1',initial)
    apply(initial)
    start_valid = sorted(seq for seq,e in active.values()
                         if e['valid_from_tick'] <= 20 < e['expires_at_tick'])
    fence = set(start_valid)
    old_hash = digest({'seqs': start_valid})
    target_people = people[:]
    rng.shuffle(target_people)
    expected = [full('applied')]
    cmds = [ingest(first)]
    prepared = {}
    for i, principal in enumerate(target_people):
        rid = f'model-{i}-{secrets.token_hex(2)}'
        yes = authorized(principal, 20)
        prepared[rid] = (principal, yes)
        cmds.append(p(rid, 20, 'alpha', principal, asset, action))
        expected.append(full('prepared') if yes else full('denied','unauthorized'))
    r.run(cmds, expected)

    # Revoke some edges, replace other paths and grant new roots. A replacement
    # cannot retroactively become evidence for a previously prepared request.
    changes = []
    available = list(active.values())
    rng.shuffle(available)
    for _, e in available[:11]:
        if e['type'] == 'grant':
            changes.append(evt('revoke',e['authority'],e['principal'],asset,action))
        else:
            changes.append(edge('undelegate',e['authority'],e['delegator'],
                                e['delegatee'],asset,action))
    for _ in range(12):
        label = rng.choice(('operations','safety'))
        if rng.random() < .3:
            changes.append(evt('grant',label,rng.choice(roots),asset,action,10,100))
        else:
            a,b = rng.sample(people,2)
            changes.append(edge('delegate',label,a,b,asset,action,10,100))
    second = w.b('alpha',len(initial)+1,w.hash(first),'alpha-2',changes)
    apply(changes)
    cmds, expected = [ingest(second)], [full('applied')]
    committed = set()
    for rid,(principal,was_prepared) in prepared.items():
        if not was_prepared:
            continue
        yes = authorized(principal, 30, fence)
        cmds.append(c(rid,30))
        expected.append(full('executed') if yes else full('denied','authority_changed'))
        if yes:
            committed.add(rid)
    r.run(cmds,expected)
    rows = r.audit()
    assert {row['request_id'] for row in rows} == committed, rows
    for row in rows:
        assert row['prepare_hash'] == old_hash and row['commit_tick'] == 30, row
        assert row['principal'] == prepared[row['request_id']][0], row
    # Fresh prepares see the new policy. Old requests cannot borrow its edges.
    cmds, expected = [], []
    for i,principal in enumerate(target_people):
        rid=f'after-{i}-{secrets.token_hex(2)}'
        cmds.append(p(rid,31,'alpha',principal,asset,action))
        expected.append(full('prepared') if authorized(principal,31)
                        else full('denied','unauthorized'))
    r.run(cmds, expected)


def case_multisite_gap_isolation(r,w):
    """A pending gap at one site must not block unaffected sites."""
    a = w.b('alpha',1,'0'*64,'alpha-1',[
        evt('grant','operations','op'),evt('grant','safety','safety'),
        edge('delegate','operations','op','tech'),
        edge('delegate','safety','safety','tech')])
    b = w.b('beta',1,'0'*64,'beta-1',[
        evt('grant','operations','betaop','valve','inspect')])
    future = w.b('alpha',6,'0'*64,'alpha-2',[
        evt('grant','operations','future')])
    r.run([ingest(a),ingest(b),p('alpha1',20),p('beta1',20,'beta','betaop','valve','inspect'),
           ingest(future),c('alpha1',21),c('beta1',21)],
          [full('applied'),full('applied'),full('prepared'),full('prepared'),
           full('buffered'),full('denied','gap'),full('executed')])
    assert [item['request_id'] for item in r.audit()] == ['beta1']


def case_policy_churn_at_scale(r, w):
    """Prepared evidence cannot be rescued by an identical replacement at scale."""
    events = [evt('grant','operations','root-op'),
              evt('grant','safety','root-safe'),
              edge('delegate','operations','root-op','tech'),
              edge('delegate','safety','root-safe','tech')]
    # Unrelated active records are part of the evidence snapshot, even when
    # they cannot reach the principal. This catches winning-path-only proofs.
    for i in range(24):
        label = 'operations' if i % 2 else 'safety'
        events.append(edge('delegate', label, f'isolated-{i}',
                           f'isolated-{i+1}'))
    first=w.b('alpha',1,'0'*64,'alpha-1',events)
    n=12
    prepares=[p(f'queued-{i:03d}',20) for i in range(n)]
    r.run([ingest(first)]+prepares,[full('applied')]+[full('prepared')]*n)
    original_hash=digest({'seqs':list(range(1,len(events)+1))})
    revoke=w.b('alpha',len(events)+1,w.hash(first),'alpha-2',[
        edge('undelegate','operations','root-op','tech')])
    replaced=w.b('alpha',len(events)+2,w.hash(revoke),'alpha-2',[
        edge('delegate','operations','root-op','tech')])
    actions=[ingest(revoke),ingest(replaced)]
    actions.extend(c(f'queued-{i:03d}',21) for i in range(n))
    expected=[full('applied'),full('applied')]+[full('denied','authority_changed')]*n
    r.run(actions,expected)
    new_requests=[p(f'current-{i:03d}',22) for i in range(n)]
    commits=[c(f'current-{i:03d}',23) for i in range(n)]
    r.run(new_requests+commits,[full('prepared')]*n+[full('executed')]*n)
    rows=r.audit()
    assert len(rows)==n, len(rows)
    assert all(x['request_id'].startswith('current-') for x in rows)
    assert all(x['prepare_hash']!=original_hash for x in rows)


def case_concurrent_independent_commits(r, w):
    """Distinct prepared effects must all commit without losing or duplicating rows."""
    first=w.b('alpha',1,'0'*64,'alpha-1',[
        evt('grant','operations','operator'),evt('grant','safety','inspector'),
        edge('delegate','operations','operator','tech'),
        edge('delegate','safety','inspector','tech')])
    ids=[f'parallel-{i}-{secrets.token_hex(3)}' for i in range(10)]
    r.run([ingest(first)]+[p(x,20) for x in ids],
          [full('applied')]+[full('prepared')]*len(ids))
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results=list(pool.map(lambda x:r.run([c(x,21)])[0], ids))
    assert results == [full('executed')]*len(ids), results
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        retries=list(pool.map(lambda x:r.run([c(x,22)])[0], ids))
    assert retries == [full('already_executed')]*len(ids), retries
    effects=r.audit()
    assert {row['request_id'] for row in effects}==set(ids), effects
    assert len(effects)==len(ids),effects


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--app',type=Path,default=Path('/app'))
    args=ap.parse_args()
    assert (args.app/'permitgate'/'cli.py').is_file(), 'Collected candidate missing'
    cases=[case_dual_and_regrant,case_gap_and_retirement,case_alternative_graph,
           case_conflicts_and_clock,case_validation,case_concurrent,case_large_graph,
           case_key_retirement_while_buffered,case_root_separation_and_windows,
           case_pending_limit,case_many_requests,case_randomized_policy,
           case_revoke_commit_race,case_signing_boundaries,case_bootstrap_fingerprint,
           case_request_binding,case_discard_bad_pending_link,
           case_randomized_delegation_model,case_multisite_gap_isolation,
           case_policy_churn_at_scale,case_concurrent_independent_commits,
           case_checkpoint_compaction_and_replay,case_checkpoint_authentication_and_gap,
           case_checkpoint_preserves_prepare_evidence,case_checkpoint_rejects_invalid_bootstrap,
           case_authenticated_before_buffering,case_repeat_prepare_evidence_is_fixed,
           case_repeat_prepare_returns_invalidated,case_repeat_prepare_invalidated_on_expiry,
           case_invalid_commands_do_not_advance_clock,case_checkpoint_commit_race,
           case_checkpoint_window_and_status_validation]
    from verify_depth import DEPTH_CASES
    cases.extend(DEPTH_CASES)
    failed=[]
    for case in cases:
        with tempfile.TemporaryDirectory(prefix='pg-eval-') as d:
            w=World()
            r=Runner(args.app,d)
            r.write_trust(w.trust)
            try:
                case(r,w)
                print('PASS',case.__name__,flush=True)
            except Exception as exc:
                failed.append(case.__name__)
                print('FAIL',case.__name__,type(exc).__name__,str(exc)[:1200],flush=True)
    print(f'{len(cases)-len(failed)}/{len(cases)} independent checks passed',flush=True)
    return 1 if failed else 0

if __name__=='__main__':
    raise SystemExit(main())
