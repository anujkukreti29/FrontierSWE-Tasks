"""Independent tests for divergent-replica recovery.

Expected results come from constructed histories and separately enumerated
small cases, not from candidate-generated recovery plans or logs.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import pathlib
import random
import resource
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import defaultdict

APP=pathlib.Path(os.environ.get('CARTOGRAPHER_TEST_APP', '/app'))
SRC=APP/'cartographer'
ZERO='0'*64

# The verifier privately varies generated inputs between evaluations. Record a
# seed in the evaluation log for exact replay of any failure. The override is
# verifier-owned and must never be forwarded to candidate subprocesses.
try:
    VERIFIER_SEED = int(os.environ.get('CARTOGRAPHER_VERIFY_SEED',
                                       str(int.from_bytes(os.urandom(8), 'big'))), 0)
except ValueError as exc:
    raise RuntimeError('CARTOGRAPHER_VERIFY_SEED must be an integer') from exc

def vary(seed):
    material = f'{VERIFIER_SEED}:{seed}'.encode('ascii')
    return seed ^ int.from_bytes(hashlib.sha256(material).digest()[:4], 'big')

def jbytes(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
def digest(x):return hashlib.sha256(x).hexdigest()
def wr(path,b):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(b)

def add_event(stream,seq,prev,kind,key,val,req,nonce,fmt=2):
    op={'kind':kind,'key':key}
    if kind=='put':op['value']=val
    if fmt==1:
        op={'kind':'set' if kind=='put' else 'remove','name':key}
        if kind=='put':op['payload']=val
    base={'stream':stream,'seq':seq,'nonce':format(nonce,'032x'),'format':fmt,'operation':op}
    event_id=digest(jbytes(base))
    r={**base,'event_id':event_id,'requires':sorted(req,key=lambda x:(x['stream'],x['seq'],x['event_id'])),'prev':prev}
    r['digest']=digest(jbytes(r))
    return r

def ref(r):return {'stream':r['stream'],'seq':r['seq'],'event_id':r['event_id']}

def snapshot(stream,sid,seq,tip,state,requires,witnesses):
    return {'id':sid,'stream':stream,'seq':seq,'tip':tip,'state_format':2,
            'state':state,'requires':sorted(requires,key=lambda x:(x['stream'],x['seq'],x['event_id'])),
            'witnesses':{str(k):v for k,v in witnesses.items()}}

def create_case(root,seed,mode='normal'):
    """Generate distinct synthetic branch and checkpoint choices from scratch."""
    rng=random.Random(seed)
    names=['audit','inventory','orders']
    stem=str(seed)+'/λ'
    # Full record chain generated independently of the candidate.
    i1=add_event('inventory',1,ZERO,'put','sku/'+stem,{'branch':'shared','n':seed},[],rng.getrandbits(128),fmt=1)
    ia2=add_event('inventory',2,i1['digest'],'put','sku/'+stem,{'branch':'A','seq':2},[],rng.getrandbits(128))
    ia3=add_event('inventory',3,ia2['digest'],'put','sku/'+stem,{'branch':'A','seq':3},[],rng.getrandbits(128))
    ib2=add_event('inventory',2,i1['digest'],'put','sku/'+stem,{'branch':'B','seq':2},[],rng.getrandbits(128))
    ib3=add_event('inventory',3,ib2['digest'],'put','sku/'+stem,{'branch':'B','seq':3},[],rng.getrandbits(128))
    ib4=add_event('inventory',4,ib3['digest'],'put','sku/'+stem,{'branch':'B','seq':4},[],rng.getrandbits(128))
    ib5=add_event('inventory',5,ib4['digest'],'put','sku/'+stem,{'branch':'B','seq':5},[],rng.getrandbits(128))
    ib6=add_event('inventory',6,ib5['digest'],'put','sku/'+stem,{'branch':'B','seq':6},[],rng.getrandbits(128))
    ib7=add_event('inventory',7,ib6['digest'],'put','sku/'+stem,{'branch':'B','seq':7},[],rng.getrandbits(128))
    o1=add_event('orders',1,ZERO,'put','order/'+stem,{'status':'new'},[ref(i1)],rng.getrandbits(128))
    o2=add_event('orders',2,o1['digest'],'put','order/'+stem,{'status':'packed'},[ref(ia2)],rng.getrandbits(128),fmt=1)
    o3=add_event('orders',3,o2['digest'],'put','order/'+stem,{'status':'shipped'},[ref(ia3)],rng.getrandbits(128))
    a1=add_event('audit',1,ZERO,'put','log/'+stem,{'state':'shipped'},[ref(o3)],rng.getrandbits(128))
    snapshots={
        'inventory':[
            snapshot('inventory','z0',0,ZERO,{},[],{}),
            snapshot('inventory','a2',2,ia2['digest'],{'sku/'+stem:{'branch':'A','seq':2}},[],{1:i1['event_id'],2:ia2['event_id']}),
            snapshot('inventory','b2',2,ib2['digest'],{'sku/'+stem:{'branch':'B','seq':2}},[],{1:i1['event_id'],2:ib2['event_id']})],
        'orders':[
            snapshot('orders','z0',0,ZERO,{},[],{}),
            snapshot('orders','a1',1,o1['digest'],{'order/'+stem:{'status':'new'}},[ref(i1)],{1:o1['event_id']})],
        'audit':[snapshot('audit','z0',0,ZERO,{},[],{})]
    }
    b_extra = [ib5,ib6] if mode=='score_tie' else ([ib5,ib6,ib7] if mode=='prefer_b' else [])
    archives={
        'inventory':[('north',[[i1,b'{garbled data',ia3]]),('east',[[ia2,ib2,ib3,ib4]+b_extra]),('south',[[i1,b'\xff']])],
        'orders':[('north',[[o1,o2],[o3]])],
        'audit':[('north',[[a1]])]
    }
    expect={'cut':{'inventory':3,'orders':3,'audit':1},
            'snapshots':{'inventory':'a2','orders':'a1','audit':'z0'},
            'objective':7,
            'values':{('inventory','sku/'+stem):{'branch':'A','seq':3},
                      ('orders','order/'+stem):{'status':'shipped'},
                      ('audit','log/'+stem):{'state':'shipped'}},
            'replay':{'inventory':[ia3['digest']],'orders':[o2['digest'],o3['digest']],'audit':[a1['digest']]}}
    if mode=='prefer_b':
        expect={'cut':{'inventory':7,'orders':1,'audit':0},
                'snapshots':{'inventory':'b2','orders':'a1','audit':'z0'},
                'objective':8,
                'values':{('inventory','sku/'+stem):{'branch':'B','seq':7},('orders','order/'+stem):{'status':'new'}},
                'replay':{'inventory':[x['digest'] for x in (ib3,ib4,ib5,ib6,ib7)],'orders':[],'audit':[]}}
    if mode=='conflict':
        # Same event ID, different hash-valid record, excludes BOTH variants.
        evil=dict(ia2);evil['requires']=[ref(o1)];evil['digest']=digest(jbytes({k:v for k,v in evil.items() if k!='digest'}))
        archives['inventory'].append(('spoof',[[evil]]))
        # ia2 can no longer anchor a history continuation from a2? A trusted
        # checkpoint already compacted ia2, so a2 remains usable; result is
        # still 7. To test actual equivocation, remove a2 checkpoint.
        snapshots['inventory']=[x for x in snapshots['inventory'] if x['id']!='a2']
        # Choice B reaches 4, orders can reach 1; audit stays 0.
        expect={'cut':{'inventory':4,'orders':1,'audit':0},
                'snapshots':{'inventory':'b2','orders':'a1','audit':'z0'},
                'objective':5,
                'values':{('inventory','sku/'+stem):{'branch':'B','seq':4},('orders','order/'+stem):{'status':'new'}},
                'replay':{'inventory':[ib3['digest'],ib4['digest']],'orders':[],'audit':[]}}
    if mode=='unwitnessed':
        # A2 checkpoint cannot authenticate the historical inventory event i1.
        # Remove its witness for i1, and require it through orders' checkpoint.
        for snap in snapshots['inventory']:
            if snap['id']=='a2':snap['witnesses'].pop('1')
        # The best recovery can still use the base z0 and replay 1-2-3.
        expect['snapshots']['inventory']='z0'
        expect['replay']['inventory']=[i1['digest'],ia2['digest'],ia3['digest']]
    if mode=='impossible':
        snapshots['inventory']=[snapshot('inventory','fixed2',2,ia2['digest'],{'sku/'+stem:{'branch':'A','seq':2}},[],{2:ia2['event_id']})]
        snapshots['orders']=[snapshot('orders','fixed1',1,o1['digest'],{'order/'+stem:{'status':'new'}},[ref(i1)],{1:o1['event_id']})]
        expect={'error':'NO_CONSISTENT_RECOVERY'}
    if mode=='no_snap':
        snapshots['audit']=[]
        expect={'error':'NO_USABLE_SNAPSHOT'}
    mani={'protocol':2,'streams':names,'snapshots':{},'archives':{},'integrity':{}}
    for stream in names:
        mani['snapshots'][stream]=[]
        for snap in snapshots[stream]:
            rel='snapshots/'+stream+'/'+snap['id']+'.json'
            content=jbytes(snap)
            wr(root/rel,content)
            mani['snapshots'][stream].append(rel)
            mani['integrity'][rel]=digest(content)
        mani['archives'][stream]=[]
        for replica,frags in archives[stream]:
            paths=[]
            for i,fragment in enumerate(frags):
                rel='wal/'+stream+'/'+replica+'-'+str(i)+'.jsonl'
                rows=[jbytes(r) if isinstance(r,dict) else r for r in fragment]
                wr(root/rel,b'\n'.join(rows)+b'\n')
                paths.append(rel)
            mani['archives'][stream].append({'replica':replica,'fragments':paths})
    wr(root/'case.json',jbytes(mani))
    return expect

def run(case,out,timeout=90,extra_env=None):
    env=os.environ.copy();env['PYTHONPATH']=str(APP)+os.pathsep+env.get('PYTHONPATH','')
    env.pop('CARTOGRAPHER_VERIFY_SEED', None)  # verifier-only case-selection secret
    if extra_env:
        env.update(extra_env)
    # Drop privileges before importing *any* candidate code. The input fixtures
    # are root-owned and test code is unreadable to the candidate user.
    def restrict():
        if os.geteuid()==0:
            os.setgroups([])
            os.setgid(10001)
            os.setuid(10001)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024*1024,128*1024*1024))
    if extra_env and 'CARTOGRAPHER_TEST_HOOK' in extra_env:
        # Run the exact same module entry point after installing a verifier-only
        # fault hook. This also works on hosts with a preinstalled sitecustomize.
        launcher=('import os,runpy,sys;'
                  'exec(compile(open(os.environ["CARTOGRAPHER_TEST_HOOK"]).read(),'
                  '"fault-hook","exec"));'
                  'sys.argv=["cartographer"]+sys.argv[1:];'
                  'runpy.run_module("cartographer",run_name="__main__")')
        command=[sys.executable,'-c',launcher,'recover','--input',str(case),'--output',str(out)]
    else:
        command=[sys.executable,'-m','cartographer','recover','--input',str(case),'--output',str(out)]
    return subprocess.run(command,env=env,cwd=str(APP),capture_output=True,text=True,timeout=timeout,preexec_fn=restrict)

def validate(case,out,expect):
    ptr=out/'CURRENT'
    if not ptr.is_file() or ptr.is_symlink():raise AssertionError('Missing/unsafe CURRENT')
    contents=ptr.read_text(encoding='utf-8')
    assert contents.startswith('generations/') and contents.endswith('\n') and len(contents.split('/')[1].strip())==64
    path=out/contents.strip()
    assert path.resolve().is_relative_to(out.resolve()) and path.is_dir() and not path.is_symlink()
    def readcanonical(p):
        b=p.read_bytes();x=json.loads(b)
        assert b==jbytes(x),p
        return x
    plan=readcanonical(path/'plan.json')
    evidence=readcanonical(path/'evidence.json')
    assert set(plan)=={'protocol','cut','snapshots','heads','objective','replay'}
    assert plan['protocol']==2
    for key in ('cut','snapshots','objective','replay'):
        assert plan[key]==expect[key],(key,plan[key],expect[key])
    assert set(evidence)=={'protocol','cut','snapshots','heads','input_sha256','provenance','recovery_status','generation_id'}
    assert evidence['protocol']==2 and evidence['recovery_status']=='complete'
    for key in ('cut','snapshots','heads'): assert evidence[key]==plan[key]
    mani=json.loads((case/'case.json').read_bytes())
    declared=['case.json']+[s for files in mani['snapshots'].values() for s in files]
    declared.extend(p for archs in mani['archives'].values() for a in archs for p in a['fragments'])
    input_hashes={p:digest((case/p).read_bytes()) for p in declared}
    assert evidence['input_sha256']==input_hashes
    gen=digest(jbytes({'protocol':2,'plan':plan,'input_sha256':input_hashes}))
    assert evidence['generation_id']==gen and contents=='generations/'+gen+'\n'
    # Derive the physical provenance independently, examining every admitted
    # archive. Neither the candidate's provenance nor its replay ledger is the
    # source of ground truth for these comparisons.
    selected={d for digests in plan['replay'].values() for d in digests}
    loc_for_digest={}
    event_for_digest={}
    for stream in mani['streams']:
        for arch in mani['archives'][stream]:
            for file in arch['fragments']:
                for number,line in enumerate((case/file).read_bytes().splitlines(),1):
                    try:rec=json.loads(line)
                    except (ValueError,UnicodeDecodeError):continue
                    if type(rec) is not dict or rec.get('digest') not in selected:continue
                    if rec.get('stream')!=stream:continue
                    dgst=rec['digest']
                    loc=(arch['replica'],file,number)
                    if dgst not in loc_for_digest or loc<loc_for_digest[dgst]:
                        loc_for_digest[dgst]=loc
                        event_for_digest[dgst]=rec
    for stream in mani['streams']:
        assert len(evidence['provenance'][stream])==len(plan['replay'][stream])
        for pos,item in enumerate(evidence['provenance'][stream]):
            assert set(item)=={'digest','replica','path','line'}
            dgst=plan['replay'][stream][pos]
            assert item=={'digest':dgst,'replica':loc_for_digest[dgst][0],
                          'path':loc_for_digest[dgst][1],'line':loc_for_digest[dgst][2]}
    # Independently reconstruct the claimed selected history, including the
    # checkpoint anchor and exact cross-stream event identities. A candidate
    # must not pass by returning the expected cut with fabricated final heads.
    base_snapshots={}
    selected_ids={}
    for stream in mani['streams']:
        candidates=[]
        for rel in mani['snapshots'][stream]:
            b=(case/rel).read_bytes()
            if digest(b)!=mani['integrity'][rel]:continue
            snap=json.loads(b)
            if snap.get('id')==plan['snapshots'][stream]:
                candidates.append(snap)
        assert len(candidates)==1,('checkpoint authentication',stream)
        snap=candidates[0]
        base_snapshots[stream]=snap
        local={int(k):v for k,v in snap['witnesses'].items()}
        last=snap['tip']
        current_seq=snap['seq']
        for d in plan['replay'][stream]:
            r=event_for_digest[d]
            assert r['stream']==stream and r['seq']==current_seq+1
            assert r['prev']==last and r['digest']==d
            payload={key:r[key] for key in ('stream','seq','nonce','format','operation')}
            assert digest(jbytes(payload))==r['event_id']
            assert digest(jbytes({k:v for k,v in r.items() if k!='digest'}))==d
            last=d
            current_seq=r['seq']
            local[current_seq]=r['event_id']
        assert plan['cut'][stream]==current_seq,('sequence cut',stream)
        assert plan['heads'][stream]==last,('final head',stream)
        selected_ids[stream]=local

    assert plan['objective']==sum(plan['cut'].values())
    for stream in mani['streams']:
        snap=base_snapshots[stream]
        deps=list(snap['requires'])
        for d in plan['replay'][stream]:
            deps.extend(event_for_digest[d]['requires'])
        for require in deps:
            target=require['stream']
            assert require['seq']<=plan['cut'][target]
            assert selected_ids[target].get(require['seq'])==require['event_id'],(stream,require)
    db=sqlite3.connect(path/'restored.sqlite')
    try:
        rows=db.execute('SELECT stream,key,value_json FROM kv').fetchall()
        for _,_,value_json in rows:
            assert value_json==jbytes(json.loads(value_json)).decode('utf-8')
        actual={ (s,k):json.loads(v) for s,k,v in rows }
        assert actual==expect['values'],(actual,expect['values'])
        applied=db.execute('SELECT stream,seq,event_id,digest FROM applied ORDER BY stream,seq').fetchall()
        required=[]
        for stream in sorted(mani['streams']):
            for dgst in plan['replay'][stream]:
                rec=event_for_digest[dgst]
                required.append((stream,rec['seq'],rec['event_id'],rec['digest']))
        assert applied==required,(applied[:5],required[:5])
        checkpoints=db.execute('SELECT stream,snapshot_id,base_seq,final_seq,final_digest FROM checkpoint').fetchall()
        assert set(x[0] for x in checkpoints)==set(mani['streams'])
        for s,sid,base,final,head in checkpoints:
            assert sid==plan['snapshots'][s] and final==plan['cut'][s] and head==plan['heads'][s]
            snap=json.loads((case/next(p for p in mani['snapshots'][s] if json.loads((case/p).read_bytes())['id']==sid)).read_bytes())
            assert base==snap['seq']
    finally:db.close()
    return gen


def create_cycle_case(root,seed):
    rng=random.Random(seed)
    # Stable IDs exist before record digests. A1 and B1 may legitimately depend
    # on each other in one atomic group.
    a1=add_event('a',1,ZERO,'put','unit',{'v':1},[],rng.getrandbits(128))
    b1=add_event('b',1,ZERO,'put','unit',{'v':1},[],rng.getrandbits(128),fmt=1)
    a1['requires']=[ref(b1)]
    a1['digest']=digest(jbytes({k:v for k,v in a1.items() if k!='digest'}))
    b1['requires']=[ref(a1)]
    b1['digest']=digest(jbytes({k:v for k,v in b1.items() if k!='digest'}))
    a2=add_event('a',2,a1['digest'],'put','unit',{'v':2},[ref(b1)],rng.getrandbits(128))
    b2=add_event('b',2,b1['digest'],'put','unit',{'v':2},[ref(a1)],rng.getrandbits(128))
    mani={'protocol':2,'streams':['a','b'],'snapshots':{},'archives':{},'integrity':{}}
    for s,chain in (('a',[a1,a2]),('b',[b1,b2])):
        snap=snapshot(s,'z0',0,ZERO,{},[],{})
        p=f'snapshots/{s}/z0.json'
        data=jbytes(snap);wr(root/p,data);mani['integrity'][p]=digest(data)
        mani['snapshots'][s]=[p]
        p=f'wal/{s}/north.jsonl'
        wr(root/p,b'\n'.join(jbytes(r) for r in chain)+b'\n')
        mani['archives'][s]=[{'replica':'north','fragments':[p]}]
    wr(root/'case.json',jbytes(mani))
    return {'cut':{'a':2,'b':2},'snapshots':{'a':'z0','b':'z0'},'objective':4,
            'values':{('a','unit'):{'v':2},('b','unit'):{'v':2}},
            'replay':{'a':[a1['digest'],a2['digest']],'b':[b1['digest'],b2['digest']]}}

def create_large_case(root,seed,n=6000):
    """Large, low-branch constructive upper-bound case with cross-stream edges.

    Total optimum upper bound = number of streams * n; a feasible state hitting
    this bound proves global optimality without trusting a heuristic solver.
    """
    streams=['alpha','beta','delta','gamma']
    mani={'protocol':2,'streams':streams,'snapshots':{},'archives':{},'integrity':{}}
    expect={'cut':{},'snapshots':{},'objective':n*len(streams),'replay':{},'values':{}}
    prev_history={}
    for j,s in enumerate(streams):
        snap=snapshot(s,'z0',0,ZERO,{},[],{})
        p=f'snapshots/{s}/z0.json'
        raw=jbytes(snap);wr(root/p,raw);mani['integrity'][p]=digest(raw)
        mani['snapshots'][s]=[p]
        primary=[];mirror=[];chain=[];prev=ZERO
        for i in range(1,n+1):
            deps=[]
            if j>0 and i>1 and i%29==0:
                deps=[ref(prev_history[streams[j-1]][i-2])]
            r=add_event(s,i,prev,'put','last',{'seq':i,'seed':seed},deps,(seed*10000000+j*n+i)%(2**128),fmt=1 if i%2 else 2)
            prev=r['digest'];chain.append(r)
            (mirror if i%97==0 else primary).append(jbytes(r))
        paths=[]
        for label,rows in (('primary',primary),('mirror',mirror)):
            p=f'wal/{s}/{label}.jsonl'
            wr(root/p,b'\n'.join(rows)+b'\n')
            paths.append((label,p))
        mani['archives'][s]=[{'replica':label,'fragments':[path]} for label,path in paths]
        expect['cut'][s]=n
        expect['snapshots'][s]='z0'
        expect['replay'][s]=[r['digest'] for r in chain]
        expect['values'][(s,'last')]={'seq':n,'seed':seed}
        prev_history[s]=chain
    wr(root/'case.json',jbytes(mani))
    return expect


def create_cascade_case(root,seed,nstreams=8):
    """Branch decisions form a downstream causal dependency cascade.

    The locally longest first history is globally inferior. An independent
    analytic bound proves selecting all A branches is best in this construction.
    """
    streams=[f'svc{i}' for i in range(nstreams)]
    mani={'protocol':2,'streams':streams,'snapshots':{},'archives':{},'integrity':{}}
    expect={'cut':{},'snapshots':{},'objective':6*nstreams,'replay':{},'values':{}}
    earlier_a2=None
    for j,s in enumerate(streams):
        z=snapshot(s,'z0',0,ZERO,{},[],{})
        rel=f'snapshots/{s}/z0.json';b=jbytes(z);wr(root/rel,b)
        mani['integrity'][rel]=digest(b);mani['snapshots'][s]=[rel]
        a_chain=[]; b_chain=[]
        first=add_event(s,1,ZERO,'put','counter',{'branch':'shared','seq':1},[],seed*10000+j*50+1)
        a_chain.append(first)
        a2=add_event(s,2,first['digest'],'put','counter',{'branch':'A','seq':2},[ref(earlier_a2)] if earlier_a2 is not None else [],seed*10000+j*50+2)
        a_chain.append(a2)
        for k in range(3,7):
            prev=a_chain[-1]['digest']
            a_chain.append(add_event(s,k,prev,'put','counter',{'branch':'A','seq':k},[],seed*10000+j*50+k))
        b2=add_event(s,2,first['digest'],'put','counter',{'branch':'B','seq':2},[],seed*10000+j*50+22)
        b_chain=[b2]
        if j==0:
            for k in range(3,10):
                b_chain.append(add_event(s,k,b_chain[-1]['digest'],'put','counter',{'branch':'B','seq':k},[],seed*10000+j*50+k+20))
        fragments=[('main',a_chain[::2]),('mirror',a_chain[1::2]+b_chain)]
        mani['archives'][s]=[]
        for replica,recs in fragments:
            p=f'wal/{s}/{replica}.jsonl'
            wr(root/p,b'\n'.join(jbytes(r) for r in recs)+b'\n')
            mani['archives'][s].append({'replica':replica,'fragments':[p]})
        earlier_a2=a2
        expect['cut'][s]=6
        expect['snapshots'][s]='z0'
        expect['replay'][s]=[r['digest'] for r in a_chain]
        expect['values'][(s,'counter')]={'branch':'A','seq':6}
    wr(root/'case.json',jbytes(mani))
    return expect

def create_branch_matrix_case(root, seed, nstreams=8, branches=12):
    """A coupled, high-branch recovery with an independently proven optimum.

    A history advances to sequence 12 in all services; its seq-2 record
    witnesses the prior service's A history. Eleven alternatives reach 11,
    except that service zero has a locally tempting alternative reaching 13.
    Only choosing all A histories achieves the global upper bound 8 * 12.
    With both rooted/checkpointed A options and the eleven other branches,
    full Cartesian enumeration considers at least 13**8 alternatives.
    """
    assert nstreams == 8 and branches == 12
    streams = [f'svc{i}' for i in range(nstreams)]
    mani = {'protocol':2,'streams':streams,'snapshots':{},'archives':{},'integrity':{}}
    expected = {'cut': {}, 'snapshots': {}, 'objective':12*nstreams,
                'replay':{}, 'values':{}}
    previous_a2 = None
    for stream_index, stream in enumerate(streams):
        r1=add_event(stream,1,ZERO,'put','last',{'branch':'base','seq':1},[],
                     seed*100000+stream_index*10000+1)
        chains = []
        a2 = None
        for branch in range(branches):
            name='A' if branch==0 else f'B{branch:02d}'
            last=12 if branch==0 else (13 if stream_index==0 and branch==11 else 11)
            deps=[ref(previous_a2)] if branch==0 and previous_a2 is not None else []
            r2=add_event(stream,2,r1['digest'],'put','last',
                         {'branch':name,'seq':2},deps,
                         seed*100000+stream_index*10000+2+branch*100)
            chain=[r1,r2]
            for seq in range(3,last+1):
                prev=chain[-1]['digest']
                chain.append(add_event(stream,seq,prev,'put','last',
                              {'branch':name,'seq':seq},[],
                              seed*100000+stream_index*10000+branch*100+seq,
                              fmt=1 if seq%3==0 else 2))
            chains.append(chain)
            if branch==0:
                a2=r2
                expected['cut'][stream]=12
                expected['snapshots'][stream]='a2'
                expected['replay'][stream]=[r['digest'] for r in chain[2:]]
                expected['values'][(stream,'last')]={'branch':'A','seq':12}
        previous_a2=a2
        z=snapshot(stream,'z0',0,ZERO,{},[],{})
        check_a=snapshot(stream,'a2',2,a2['digest'],
                         {'last':{'branch':'A','seq':2}},
                         chains[0][1]['requires'],
                         {1:r1['event_id'],2:a2['event_id']})
        # The checkpoint explicitly retains the foreign dependency of its
        # compacted event. This prevents checkpoint selection from bypassing it.
        for snap in (z,check_a):
            rel=f'snapshots/{stream}/{snap["id"]}.json'
            raw=jbytes(snap); wr(root/rel,raw)
            mani['integrity'][rel]=digest(raw)
            mani['snapshots'].setdefault(stream,[]).append(rel)
        # Both interleaved WAL fragments and a bogus line exercise physical
        # reconstruction independently of graph optimization.
        pieces=[[],[],[]]
        for branch, chain in enumerate(chains):
            for record in chain:
                if branch == 0 and record['seq'] in (6,9):
                    pieces[2].append(jbytes(record))
                else:
                    pieces[branch%2].append(jbytes(record))
        pieces[1].insert(3,b'{broken archive line')
        mani['archives'][stream]=[]
        for idx,rows in enumerate(pieces):
            replica=f'replica{idx}'
            rel=f'wal/{stream}/{replica}.jsonl'
            wr(root/rel,b'\n'.join(rows)+b'\n')
            mani['archives'][stream].append({'replica':replica,'fragments':[rel]})
    wr(root/'case.json',jbytes(mani))
    return expected


def create_cyclic_branch_matrix_case(root, seed, nstreams=8, branches=8):
    """Cross-service cyclic branch choices with an exact constructed optimum.

    All A events at sequence 2 form one atomic dependency component. Every
    service must select its A history to preserve any of those A events. Each
    service also has independent B branches; a tempting longer local B history
    cannot beat the full all-A restoration. Stable event IDs are computed
    before dependencies, so a dependency cycle does not create circular hashes.
    """
    streams = [f'svc{i}' for i in range(nstreams)]
    mani = {'protocol':2,'streams':streams,'snapshots':{},'archives':{},'integrity':{}}
    expected = {'cut':{},'snapshots':{},'objective':12*nstreams,
                'replay':{},'values':{}}
    heads={}
    provisional_a={}
    for j,s in enumerate(streams):
        common=add_event(s,1,ZERO,'put','counter',{'branch':'start','seq':1},[],seed*100000+j*10000+1)
        # Draft A event computes its stable ID without cross-stream deps.
        a_draft=add_event(s,2,common['digest'],'put','counter',
                          {'branch':'A','seq':2},[],seed*100000+j*10000+2)
        heads[s]=common
        provisional_a[s]=a_draft
    for j,s in enumerate(streams):
        common=heads[s]
        required=sorted((ref(provisional_a[streams[(j-1)%nstreams]]),
                         ref(provisional_a[streams[(j+3)%nstreams]])),
                        key=lambda r:(r['stream'],r['seq'],r['event_id']))
        chains=[]
        final_a=None
        for branch in range(branches):
            name='A' if branch==0 else f'B{branch:02d}'
            maxseq=12 if branch==0 else (13 if j==0 and branch==branches-1 else 11)
            second=add_event(s,2,common['digest'],'put','counter',
                             {'branch':name,'seq':2},required if branch==0 else [],
                             seed*100000+j*10000+2+branch*100)
            if branch==0:
                assert second['event_id']==provisional_a[s]['event_id']
                final_a=second
            chain=[common,second]
            for seq in range(3,maxseq+1):
                chain.append(add_event(s,seq,chain[-1]['digest'],'put','counter',
                                       {'branch':name,'seq':seq},[],
                                       seed*100000+j*10000+seq+branch*100,
                                       fmt=1 if seq%3==0 else 2))
            chains.append(chain)
            if branch==0:
                expected['cut'][s]=12
                expected['snapshots'][s]='a2'
                expected['replay'][s]=[r['digest'] for r in chain[2:]]
                expected['values'][(s,'counter')]={'branch':'A','seq':12}
        snapshots=(snapshot(s,'z0',0,ZERO,{},[],{}),
                   snapshot(s,'a2',2,final_a['digest'],
                            {'counter':{'branch':'A','seq':2}},required,
                            {1:common['event_id'],2:final_a['event_id']}))
        mani['snapshots'][s]=[]
        for snap in snapshots:
            rel=f'snapshots/{s}/{snap["id"]}.json'
            data=jbytes(snap);wr(root/rel,data)
            mani['integrity'][rel]=digest(data)
            mani['snapshots'][s].append(rel)
        files=[[],[],[]]
        for branch,chain in enumerate(chains):
            for record in chain:
                files[(branch+record['seq'])%3].append(jbytes(record))
        files[2].insert(1,b'not a valid record')
        mani['archives'][s]=[]
        for i,lines in enumerate(files):
            rep=f'replica{i}'
            rel=f'wal/{s}/{rep}.jsonl'
            wr(root/rel,b'\n'.join(lines)+b'\n')
            mani['archives'][s].append({'replica':rep,'fragments':[rel]})
    wr(root/'case.json',jbytes(mani))
    return expected





def create_mixed_branch_cascade(root, seed, nstreams=8, branches=5):
    """The optimal branch alternates by service, despite a longer local fork."""
    streams=[f'svc{i}' for i in range(nstreams)]
    mani={'protocol':2,'streams':streams,'snapshots':{},'archives':{},'integrity':{}}
    result={'cut':{},'snapshots':{},'objective':nstreams*12,'replay':{},'values':{}}
    previous_second=None
    for idx,name in enumerate(streams):
        best_branch=idx%2
        root_event=add_event(name,1,ZERO,'put','last',{'base':seed},[],seed*100000+idx*10000+1)
        histories=[]
        chosen=None
        for b in range(branches):
            end=12 if b==best_branch else (13 if idx==0 and b==1 else 11)
            needed=[ref(previous_second)] if b==best_branch and previous_second is not None else []
            second=add_event(name,2,root_event['digest'],'put','last',
                             {'branch':b,'seq':2},needed,seed*100000+idx*10000+b*100+2)
            chain=[root_event,second]
            for seq in range(3,end+1):
                chain.append(add_event(name,seq,chain[-1]['digest'],'put','last',
                                       {'branch':b,'seq':seq},[],
                                       seed*100000+idx*10000+b*100+seq))
            histories.append(chain)
            if b==best_branch:
                chosen=chain
                previous_second=second
        zero=snapshot(name,'z0',0,ZERO,{},[],{})
        cached=snapshot(name,'c2',2,chosen[1]['digest'],
                        {'last':{'branch':best_branch,'seq':2}},
                        chosen[1]['requires'],
                        {1:chosen[0]['event_id'],2:chosen[1]['event_id']})
        snapshots=[zero,cached]
        mani['snapshots'][name]=[]
        for snap in snapshots:
            rel=f'snapshots/{name}/{snap["id"]}.json'
            content=jbytes(snap);wr(root/rel,content)
            mani['integrity'][rel]=digest(content)
            mani['snapshots'][name].append(rel)
        fragments=[[],[],[]]
        for branch, chain in enumerate(histories):
            for event in chain:
                fragments[(branch+event['seq'])%3].append(jbytes(event))
        fragments[0].insert(0,b'irrecoverable line')
        mani['archives'][name]=[]
        for i,rows in enumerate(fragments):
            rel=f'wal/{name}/replica{i}.jsonl'
            wr(root/rel,b'\n'.join(rows)+b'\n')
            mani['archives'][name].append({'replica':f'r{i}','fragments':[rel]})
        result['cut'][name]=12
        result['snapshots'][name]='c2'
        result['replay'][name]=[event['digest'] for event in chosen[2:]]
        result['values'][(name,'last')]={'branch':best_branch,'seq':12}
    wr(root/'case.json',jbytes(mani))
    return result

def create_mixed_replay_case(root, seed):
    """Compacted checkpoint, cross-stream dependencies and mixed-version deletes."""
    inv='inventory'
    orders='orders'
    streams=[inv, orders]
    key='café/λ/📦'
    initial={'to_delete': {'stale': True}, key: {'nested': [1, {'zero': 0}]}}
    r1=add_event(inv,1,ZERO,'put',key,{'nested':[1, {'zero':0}]},[],seed*100+1,fmt=1)
    r2=add_event(inv,2,r1['digest'],'put','to_delete',{'stale':True},[],seed*100+2)
    r3=add_event(inv,3,r2['digest'],'delete','to_delete',None,[],seed*100+3,fmt=1)
    r4=add_event(inv,4,r3['digest'],'put',key,{'nested':[2, {'é':'not normalized'}]},[],seed*100+4)
    r5=add_event(inv,5,r4['digest'],'delete','absent',None,[],seed*100+5)
    o1=add_event(orders,1,ZERO,'put','order/λ',{'stage':'created'},[ref(r4)],seed*100+6)
    o2=add_event(orders,2,o1['digest'],'put','order/λ',{'stage':'paid'},[],seed*100+7,fmt=1)
    o3=add_event(orders,3,o2['digest'],'delete','order/λ',None,[],seed*100+8,fmt=1)
    snap_inv=snapshot(inv,'base2',2,r2['digest'],initial,[],{1:r1['event_id'],2:r2['event_id']})
    snap_orders=snapshot(orders,'base0',0,ZERO,{},[],{})
    mani={'protocol':2,'streams':streams,'snapshots':{},'archives':{},'integrity':{}}
    for name, snap in [(inv,snap_inv),(orders,snap_orders)]:
        rel=f'snapshots/{name}/{snap["id"]}.json'
        content=jbytes(snap)
        wr(root/rel,content)
        mani['snapshots'][name]=[rel]
        mani['integrity'][rel]=digest(content)
    for name, entries in [(inv, [[r3,r5],[r4,r3]]),(orders, [[o1,o3],[o2]])]:
        mani['archives'][name]=[]
        for replica, records in enumerate(entries):
            rel=f'wal/{name}/replica{replica}.jsonl'
            wr(root/rel,b'\n'.join(jbytes(rec) for rec in records)+b'\n')
            mani['archives'][name].append({'replica':f'replica{replica}','fragments':[rel]})
    wr(root/'case.json',jbytes(mani))
    return {'cut':{inv:5,orders:3},'snapshots':{inv:'base2',orders:'base0'},
            'objective':8,
            'replay':{inv:[r3['digest'],r4['digest'],r5['digest']],
                      orders:[o1['digest'],o2['digest'],o3['digest']]},
            'values':{(inv,key):{'nested':[2, {'é':'not normalized'}]}}}

def create_exhaustive_small_case(root, seed, nstreams=3):
    """Construct competing histories and compute the answer by independent enumeration.

    The fixture builder does not call the candidate or reference planner. Exhaustive
    enumeration covers every checkpoint, lineage and *prefix*, including empty cuts.
    """
    rng = random.Random(seed)
    streams = [f'svc{i}' for i in range(nstreams)]
    manifest = {'protocol': 2, 'streams': streams,
                'snapshots': {}, 'archives': {}, 'integrity': {}}
    shared = {}
    provisional = {}
    branches = {}
    for idx, name in enumerate(streams):
        shared[name] = add_event(name, 1, ZERO, 'put', 'last',
                                 {'common': seed}, [], rng.getrandbits(128), fmt=1)
        provisional[name] = []
        for branch in range(3):
            provisional[name].append(add_event(name, 2, shared[name]['digest'],
                              'put', 'last', {'branch': branch, 'seq': 2}, [],
                              rng.getrandbits(128)))
    for idx, name in enumerate(streams):
        choices = []
        for branch in range(3):
            other = streams[(idx+1) % len(streams)]
            # Different branches can require a matching or a nonmatching
            # history on another stream; cyclic constraints are possible.
            target = (branch + rng.randrange(2)) % 3
            deps = [ref(provisional[other][target])] if rng.randrange(5) != 0 else []
            old = provisional[name][branch]
            second = add_event(name, 2, shared[name]['digest'], 'put', 'last',
                               {'branch': branch, 'seq': 2}, deps,
                               int(old['nonce'], 16))
            assert second['event_id'] == old['event_id']
            chain = [shared[name], second]
            for seq in range(3, 4 + (branch == idx % 3)):
                extra_deps = []
                if seq == 3 and rng.randrange(3) == 0:
                    target2 = streams[(idx+2) % len(streams)]
                    extra_deps = [ref(provisional[target2][rng.randrange(3)])]
                chain.append(add_event(name, seq, chain[-1]['digest'], 'put',
                                       'last', {'branch': branch, 'seq': seq},
                                       extra_deps, rng.getrandbits(128),
                                       fmt=1 if seq % 2 else 2))
            choices.append(chain)
        branches[name] = choices
        basic = snapshot(name, 'z0', 0, ZERO, {}, [], {})
        compact = choices[0][1]
        witnessed = snapshot(name, 'c2', 2, compact['digest'],
                             {'last': {'branch': 0, 'seq': 2}},
                             compact['requires'],
                             {1: choices[0][0]['event_id'], 2: compact['event_id']})
        # Another checkpoint option on only one stream exercises cross-stream
        # choices where base ancestry differs from replayed ancestry.
        snaps = [basic, compact and witnessed] if idx != 2 else [basic]
        manifest['snapshots'][name] = []
        for snap in snaps:
            path = f'snapshots/{name}/{snap["id"]}.json'
            raw = jbytes(snap)
            wr(root/path, raw)
            manifest['snapshots'][name].append(path)
            manifest['integrity'][path] = digest(raw)
        # Scramble physical archive order; mix valid data with torn lines.
        fragments = [[], [], []]
        for branch, chain in enumerate(choices):
            for i, event in enumerate(chain):
                fragments[(branch+i) % 3].append(jbytes(event))
        fragments[1].insert(1, b'{truncated-log')
        fragments[2].append(b'\xffbroken')
        manifest['archives'][name] = []
        for replica, rows in enumerate(fragments):
            rel = f'wal/{name}/replica{replica}.jsonl'
            wr(root/rel, b'\n'.join(rows) + b'\n')
            manifest['archives'][name].append(
                {'replica': f'r{replica}', 'fragments': [rel]})

    # Enumerate every legal stream-local (checkpoint, branch, prefix) choice.
    # Unlike the reference optimizer, this does not use causal propagation,
    # branch-and-bound, rollback or an optimistic upper bound.
    domains = {}
    for name in streams:
        possibilities = []
        for branch, full_history in enumerate(branches[name]):
            for checkpoint_id in ('z0', 'c2'):
                if checkpoint_id == 'c2' and (branch != 0 or name == 'svc2'):
                    continue
                base = 2 if checkpoint_id == 'c2' else 0
                for end in range(base, len(full_history)+1):
                    replay = full_history[base:end]
                    witnesses = ({1: full_history[0]['event_id'],
                                  2: full_history[1]['event_id']}
                                 if base == 2 else {})
                    ancestry = {**witnesses, **{r['seq']: r['event_id'] for r in replay}}
                    requirements = (full_history[1]['requires'] if base == 2 else []) + [
                        req for event in replay for req in event['requires']]
                    possibilities.append({'snap': checkpoint_id, 'base': base,
                        'end': end, 'head': full_history[end-1]['digest'] if end else ZERO,
                        'replay': replay, 'anc': ancestry, 'req': requirements,
                        'branch': branch})
        domains[name] = possibilities

    best_rank = None
    best = None
    for choice in itertools.product(*(domains[name] for name in streams)):
        selected = dict(zip(streams, choice))
        if any(selected[req['stream']]['anc'].get(req['seq']) != req['event_id']
               for option in choice for req in option['req']):
            continue
        cuts = tuple(option['end'] for option in choice)
        rank = (-sum(cuts), tuple(-n for n in cuts),
                tuple(option['snap'] for option in choice),
                tuple(option['head'] for option in choice))
        if best_rank is None or rank < best_rank:
            best_rank, best = rank, selected
    assert best is not None
    expected = {'cut': {}, 'snapshots': {}, 'objective': -best_rank[0],
                'replay': {}, 'values': {}}
    for name, option in best.items():
        expected['cut'][name] = option['end']
        expected['snapshots'][name] = option['snap']
        expected['replay'][name] = [event['digest'] for event in option['replay']]
        if option['end'] == 1:
            expected['values'][(name,'last')] = {'common': seed}
        elif option['end'] >= 2:
            expected['values'][(name,'last')] = {
                'branch': option['branch'], 'seq': option['end']}
    wr(root/'case.json', jbytes(manifest))
    return expected


def check_publication_interruptions(root):
    """Kill the process at real publication syscall boundaries, then retry.

    A verifier-only startup hook intercepts Python's rename and sync operations.
    It is loaded before candidate code and exits the process instead of raising
    an exception, so no application-level cleanup or exception handler can run.
    The hook has no access to private fixture data or grading expectations.
    """
    injector = root / 'injection'
    injector.mkdir()
    # Load the fault hook before the candidate module through the verifier's
    # Python launcher; do not install it in the agent environment.
    hook = r'''import os
from pathlib import Path
_mode=os.environ.get('CARTOGRAPHER_TEST_KILL','')
_old_rename=os.rename
_old_replace=os.replace
_old_fsync=os.fsync

# These faults affect file/directory durability, not the atomic rename calls.
# Killing after the write but before the sync must not publish partial state.
def guarded_fsync(fd):
    try: path=os.readlink('/proc/self/fd/'+str(fd))
    except OSError: path=''
    database=path.endswith('/restored.sqlite')
    generation_directory=path.endswith('/generations')
    if database and _mode=='before_database_sync': os._exit(79)
    if generation_directory and _mode=='before_generation_directory_sync': os._exit(79)
    result=_old_fsync(fd)
    if database and _mode=='after_database_sync': os._exit(79)
    return result

os.fsync=guarded_fsync

def _guarded(src,dst,func,*args,**kwargs):
    target=Path(dst)
    generation=(target.parent.name=='generations' and len(target.name)==64)
    current=(target.name=='CURRENT')
    if generation and _mode=='before_generation': os._exit(79)
    if current and _mode=='before_current': os._exit(79)
    result=func(src,dst,*args,**kwargs)
    if generation and _mode=='after_generation': os._exit(79)
    if current and _mode=='after_current': os._exit(79)
    return result

def guarded_rename(src,dst,*args,**kwargs):
    return _guarded(src,dst,_old_rename,*args,**kwargs)

def guarded_replace(src,dst,*args,**kwargs):
    return _guarded(src,dst,_old_replace,*args,**kwargs)

os.rename=guarded_rename
os.replace=guarded_replace
'''
    wr(injector/'sitecustomize.py',hook.encode('utf-8'))
    (injector/'sitecustomize.py').chmod(0o644)
    case=root/'interrupt_input'
    case.mkdir()
    expected=create_case(case,vary(551),'normal')
    # Changing the bytes of a non-selected fragment must yield a different
    # generation ID even when the recovered application state is unchanged.
    for phase in ('before_generation','after_generation',
                  'before_current','after_current',
                  'before_database_sync','after_database_sync',
                  'before_generation_directory_sync'):
        output=root/('interrupt_out_'+phase)
        baseline=run(case,output)
        assert baseline.returncode==0,(phase,baseline.stderr)
        old_id=validate(case,output,expected)
        pointer_before=(output/'CURRENT').read_bytes()
        old_path=output/'generations'/old_id
        old_bytes={name:(old_path/name).read_bytes()
                   for name in ('plan.json','restored.sqlite','evidence.json')}
        # Use a new input byte map and leave the case itself intact between
        # independent fault trials.
        change=case/'wal/inventory/south-0.jsonl'
        original=change.read_bytes()
        try:
            change.write_bytes(original+b'non-json fragment after crash test\n')
            env={'CARTOGRAPHER_TEST_KILL':phase,
                 'CARTOGRAPHER_TEST_HOOK':str(injector/'sitecustomize.py')}
            failed=run(case,output,timeout=90,extra_env=env)
            assert failed.returncode==79,(phase,failed.returncode,failed.stderr)
            # Before the pointer rename the old complete generation remains
            # authoritative. Immediately afterward either complete version is
            # acceptable; an incomplete published target is never acceptable.
            current=(output/'CURRENT').read_bytes()
            if phase!='after_current':
                assert current==pointer_before,(phase,'premature pointer switch')
            else:
                if current!=pointer_before:
                    validate(case,output,expected)
            assert old_bytes=={name:(old_path/name).read_bytes()
                       for name in old_bytes},(phase,'old generation mutated')
            retried=run(case,output,timeout=90)
            assert retried.returncode==0,(phase,retried.stderr)
            new_id=validate(case,output,expected)
            assert new_id!=old_id,(phase,'changed input reused generation')
            assert old_bytes=={name:(old_path/name).read_bytes()
                       for name in old_bytes},(phase,'old generation mutated on retry')
        finally:
            change.write_bytes(original)


def main():
    print(f'Case variation seed (replay using CARTOGRAPHER_VERIFY_SEED): {VERIFIER_SEED}',flush=True)
    if not (SRC/'recover.py').is_file():raise AssertionError('No candidate recovery source')
    results=[]
    with tempfile.TemporaryDirectory(prefix='cartographer-verify-') as wd:
        wd=pathlib.Path(wd)
        # Root-owned sticky parent lets unprivileged candidate create outputs,
        # without granting deletion/rename access to root-owned input folders.
        os.chmod(wd,0o1777)
        # A replayed run must not rely on the example fixture source tree.
        for index,(seed,mode) in enumerate([(317,'normal'),(509,'normal'),(822,'normal'),(121,'conflict'),(99,'unwitnessed'),(752,'score_tie'),(651,'prefer_b'),(672,'impossible'),(723,'no_snap')]):
            case=wd/('case'+str(index));case.mkdir()
            expected=create_case(case,vary(seed),mode)
            out=wd/('out'+str(index))
            proc=run(case,out)
            if 'error' in expected:
                assert proc.returncode!=0,(mode,proc.stdout,proc.stderr)
                x=json.loads((out/'error.json').read_bytes())
                assert x=={'protocol':2,'code':expected['error']},(x,expected)
            else:
                assert proc.returncode==0,(mode,proc.stdout,proc.stderr)
                gen=validate(case,out,expected)
                # Idempotent re-run: same full generation identifier and state.
                if index==0:
                    assert run(case,out).returncode==0
                    assert validate(case,out,expected)==gen
                    # Unselected fragment changed, selection preserved but generation must change.
                    unused=case/'wal/inventory/south-0.jsonl'
                    with unused.open('ab') as f:f.write(b'{unusable-injected-line\n')
                    assert run(case,out).returncode==0
                    other=validate(case,out,expected)
                    assert other!=gen
            results.append((mode,'PASS'))
        # The archive inventory is unordered, and identical records may be
        # present in several replicas. Provenance must use the earliest physical
        # source, not whichever copy the recovery parser encountered first.
        shuffled=wd/'shuffled_archives';shuffled.mkdir()
        expected=create_case(shuffled,vary(1931),'normal')
        manifest=json.loads((shuffled/'case.json').read_bytes())
        inventory_archives=manifest['archives']['inventory']
        north_fragment=shuffled/'wal/inventory/north-0.jsonl'
        selected_record=next(json.loads(line) for line in north_fragment.read_bytes().splitlines()
                             if line.startswith(b'{') and b'"seq":3' in line)
        # A damaged preceding line and a complete, unterminated last line are
        # both explicitly covered by the protocol's line-recovery rules.
        duplicate='wal/inventory/aaa-0.jsonl'
        wr(shuffled/duplicate,b'\xff\x00garbled\n'+jbytes(selected_record))
        inventory_archives.insert(0,{'replica':'aaa','fragments':[duplicate]})
        for stream,archives in manifest['archives'].items():
            for archive in archives:
                archive['fragments'].reverse()
            archives.reverse()
        wr(shuffled/'case.json',jbytes(manifest))
        out=wd/'shuffled_out'
        proc=run(shuffled,out,timeout=30)
        assert proc.returncode==0,('shuffled archive',proc.stderr)
        validate(shuffled,out,expected)
        pointer=(out/'CURRENT').read_text(encoding='utf-8').strip()
        evidence=json.loads((out/pointer/'evidence.json').read_bytes())
        assert evidence['provenance']['inventory'][0]['replica']=='aaa'
        results.append(('archive-order-canonical-provenance-and-torn-lines','PASS'))
        print('PASS archive-order-canonical-provenance-and-torn-lines',flush=True)

        # Complete checkpoints remain recoverable even when no WAL archives
        # are declared. The snapshot choice and its foreign witnesses still
        # participate in the global optimization and tie-breaking rules.
        compacted=wd/'checkpoint_only';compacted.mkdir()
        compacted_seed=vary(1933)
        create_case(compacted,compacted_seed,'normal')
        manifest=json.loads((compacted/'case.json').read_bytes())
        for stream in manifest['streams']:
            manifest['archives'][stream]=[]
        wr(compacted/'case.json',jbytes(manifest))
        state_key='sku/'+str(compacted_seed)+'/λ'
        order_key='order/'+str(compacted_seed)+'/λ'
        expected={'cut':{'audit':0,'inventory':2,'orders':1},
                  'snapshots':{'audit':'z0','inventory':'a2','orders':'a1'},
                  'objective':3,'replay':{'audit':[],'inventory':[],'orders':[]},
                  'values':{('inventory',state_key):{'branch':'A','seq':2},
                            ('orders',order_key):{'status':'new'}}}
        out=wd/'checkpoint_only_out'
        proc=run(compacted,out,timeout=30)
        assert proc.returncode==0,('checkpoint only',proc.stderr)
        validate(compacted,out,expected)
        results.append(('checkpoint-only-causal-witness-and-tiebreak','PASS'))
        print('PASS checkpoint-only-causal-witness-and-tiebreak',flush=True)

        # Reciprocal cross-stream dependencies must be accepted atomically.
        cycle=wd/'cycle';cycle.mkdir()
        expected=create_cycle_case(cycle,89)
        cyc_out=wd/'cycle_out'
        proc=run(cycle,cyc_out)
        assert proc.returncode==0,(proc.stderr,proc.stdout)
        validate(cycle,cyc_out,expected)
        results.append(('reciprocal-atomic-group','PASS')); print('PASS reciprocal-atomic-group',flush=True)
        cascade=wd/'cascade';cascade.mkdir()
        expected=create_cascade_case(cascade,77)
        cascade_out=wd/'cascade_out'
        proc=run(cascade,cascade_out,timeout=90)
        assert proc.returncode==0,(proc.stderr,proc.stdout)
        validate(cascade,cascade_out,expected)
        results.append(('eight-stream-branch-cascade-optimum','PASS')); print('PASS eight-stream-branch-cascade-optimum',flush=True)
        # High branching cannot be handled by naively multiplying independent
        # checkpoint and replica-lineage alternatives. The all-A construction
        # attains a known tight upper bound, so its optimum is externally proven.
        branching=wd/'branch_matrix'; branching.mkdir()
        expected=create_branch_matrix_case(branching,315)
        branching_out=wd/'branch_matrix_out'
        proc=run(branching,branching_out,timeout=120)
        assert proc.returncode==0,('high-branch',proc.stderr,proc.stdout)
        validate(branching,branching_out,expected)
        results.append(('eight-stream-high-branch-global-optimum','PASS')); print('PASS eight-stream-high-branch-global-optimum',flush=True)
        # Additional identities with the same demanding branch topology
        # prevent passing only the fixed high-branch event/digest collection.
        variant=wd/'branch_matrix_variant';variant.mkdir()
        expected=create_branch_matrix_case(variant,vary(1937))
        variant_out=wd/'branch_matrix_variant_out'
        proc=run(variant,variant_out,timeout=120)
        assert proc.returncode==0,('high-branch variant',proc.stderr)
        validate(variant,variant_out,expected)
        results.append(('eight-stream-variable-high-branch-optimum','PASS'))
        print('PASS eight-stream-variable-high-branch-optimum',flush=True)
        # The A histories form a cyclic cross-service dependency component.
        # Treating cycles as inconsistent or choosing each local maximum fails.
        cyclic=wd/'cyclic_matrix';cyclic.mkdir()
        expected=create_cyclic_branch_matrix_case(cyclic,619)
        cyclic_out=wd/'cyclic_matrix_out'
        proc=run(cyclic,cyclic_out,timeout=120)
        assert proc.returncode==0,('cyclic-branch',proc.stdout,proc.stderr)
        validate(cyclic,cyclic_out,expected)
        results.append(('eight-stream-cyclic-branch-optimum','PASS')); print('PASS eight-stream-cyclic-branch-optimum',flush=True)
        # Unlike all-A fixtures, the winning history alternates across
        # services. A locally longer first-service alternative loses globally.
        mixed=wd/'mixed_branches'; mixed.mkdir()
        expected=create_mixed_branch_cascade(mixed,1729)
        mixed_out=wd/'mixed_branches_out'
        proc=run(mixed,mixed_out,timeout=120)
        assert proc.returncode==0,('mixed branch',proc.stdout,proc.stderr)
        validate(mixed,mixed_out,expected)
        results.append(('eight-stream-mixed-optimal-histories','PASS')); print('PASS eight-stream-mixed-optimal-histories',flush=True)
        # A known globally tight upper bound, with cross-stream causality and
        # physical missing-range repair, probes long replay performance.
        large=wd/'large';large.mkdir()
        expected=create_large_case(large,4001)
        large_out=wd/'large_out'
        proc=run(large,large_out,timeout=180)
        assert proc.returncode==0,(proc.stderr,proc.stdout)
        validate(large,large_out,expected)
        results.append(('large-anchored-cross-stream-replay','PASS')); print('PASS large-anchored-cross-stream-replay',flush=True)
        # Independent, exhaustive optimality oracle for small, varied inputs.
        # Unlike fixed constructed optima, each expected result is calculated
        # from all feasible checkpoint, branch and cut combinations.
        for seed in (11, 23, 37, 53, 71, 89, 101, 127):
            small=wd/f'exhaustive_{seed}';small.mkdir()
            expected=create_exhaustive_small_case(small,seed)
            target=wd/f'exhaustive_out_{seed}'
            proc=run(small,target,timeout=30)
            assert proc.returncode==0,('small exhaustive',seed,proc.stderr)
            validate(small,target,expected)
        results.append(('independent-randomized-exhaustive-optimality','PASS')); print('PASS independent-randomized-exhaustive-optimality',flush=True)
        # A fourth service multiplies checkpoint/branch/prefix interactions.
        # These optima are derived by brute force over independent fixture
        # histories, not by the candidate's pruning algorithm.
        for seed in (13, 29, 43, 97):
            small4=wd/f'four_stream_exhaustive_{seed}';small4.mkdir()
            expected=create_exhaustive_small_case(small4,seed,nstreams=4)
            target=wd/f'four_stream_out_{seed}'
            proc=run(small4,target,timeout=30)
            assert proc.returncode==0,('four-stream exhaustive',seed,proc.stderr)
            validate(small4,target,expected)
        results.append(('four-stream-independent-exhaustive-optimality','PASS')); print('PASS four-stream-independent-exhaustive-optimality',flush=True)
        # Crash-restart residue: staging and orphaned, uncommitted generations
        # must not displace a previously committed CURRENT generation.
        recovery_case=wd/'case0'
        recovery_out=wd/'out0'
        previous=(recovery_out/'CURRENT').read_bytes()
        leftover=recovery_out/'.staging-abandoned'
        leftover.mkdir()
        (leftover/'partial').write_bytes(b'incomplete')
        orphan=recovery_out/'generations'/('f'*64)
        orphan.mkdir()
        (orphan/'plan.json').write_bytes(b'partial')
        proc=run(recovery_case,recovery_out)
        assert proc.returncode==0,('orphan replay',proc.stderr)
        assert (recovery_out/'CURRENT').read_bytes()==previous
        results.append(('orphan-generation-and-staging-restart','PASS')); print('PASS orphan-generation-and-staging-restart',flush=True)
        # Reconstruct plausible crash residue without relying on interception
        # of Python or on the candidate's implementation language. These are
        # intentionally uncommitted and must never be followed as CURRENT.
        for tag in ('after-database-write','after-evidence-write',
                    'before-pointer-rename'):
            stage=recovery_out/('.staging-'+tag)
            stage.mkdir()
            (stage/'plan.json').write_bytes(b'{}')
            if tag!='after-database-write':
                (stage/'restored.sqlite').write_bytes(b'SQLite format 3\x00partial')
            if tag=='before-pointer-rename':
                (recovery_out/'.current-orphan').write_bytes(b'generations/' + b'0'*64 + b'\n')
            proc=run(recovery_case,recovery_out,timeout=45)
            assert proc.returncode==0,(tag,proc.stderr)
            assert (recovery_out/'CURRENT').read_bytes()==previous,tag
        results.append(('language-independent-partial-publication-restart','PASS')); print('PASS language-independent-partial-publication-restart',flush=True)
        check_publication_interruptions(wd)
        results.append(('process-interruptions-at-publication-boundaries','PASS')); print('PASS process-interruptions-at-publication-boundaries',flush=True)
        # A compacted checkpoint is not a replay ledger. Verify that the
        # candidate applies both operation formats and retains no deleted keys.
        replay_case=wd/'mixed_replay';replay_case.mkdir()
        expected=create_mixed_replay_case(replay_case,vary(887))
        replay_out=wd/'mixed_replay_out'
        proc=run(replay_case,replay_out,timeout=30)
        assert proc.returncode==0,('mixed replay',proc.stdout,proc.stderr)
        validate(replay_case,replay_out,expected)
        results.append(('compacted-mixed-version-replay-and-deletes','PASS')); print('PASS compacted-mixed-version-replay-and-deletes',flush=True)
        # Case-level invalid input takes priority over unusable checkpoints.
        precedence=wd/'invalid_precedence';precedence.mkdir()
        create_case(precedence,vary(199),'no_snap')
        mani=json.loads((precedence/'case.json').read_bytes())
        mani['archives']['orders'][0]['fragments'].append('missing/fragment.jsonl')
        wr(precedence/'case.json',jbytes(mani))
        error_out=wd/'invalid_precedence_out'
        proc=run(precedence,error_out,timeout=20)
        assert proc.returncode!=0
        assert json.loads((error_out/'error.json').read_bytes())=={
            'protocol':2,'code':'INVALID_INPUT'}
        results.append(('case-validation-error-precedence','PASS')); print('PASS case-validation-error-precedence',flush=True)
        # Case inventory validation precedes checkpoint interpretation.
        # Reject ambiguous JSON keys and symlinks, not only missing files.
        dup=wd/'duplicate_manifest_key';dup.mkdir()
        create_case(dup,vary(227),'normal')
        manifest_bytes=(dup/'case.json').read_bytes()
        assert manifest_bytes.endswith(b'}')
        (dup/'case.json').write_bytes(manifest_bytes[:-1]+b',"protocol":2}')
        bad=run(dup,wd/'duplicate_manifest_key_out',timeout=20)
        assert bad.returncode!=0
        assert json.loads((wd/'duplicate_manifest_key_out'/'error.json').read_bytes())=={
            'protocol':2,'code':'INVALID_INPUT'}
        linked=wd/'symlink_archive';linked.mkdir()
        create_case(linked,vary(241),'normal')
        manifest=json.loads((linked/'case.json').read_bytes())
        relative=manifest['archives']['orders'][0]['fragments'][0]
        victim=linked/relative
        other=victim.with_name('safe-real.jsonl')
        victim.rename(other)
        victim.symlink_to(other.name)
        unsafe=run(linked,wd/'symlink_archive_out',timeout=20)
        assert unsafe.returncode!=0
        assert json.loads((wd/'symlink_archive_out'/'error.json').read_bytes())=={
            'protocol':2,'code':'INVALID_INPUT'}
        results.append(('duplicate-manifest-keys-and-symlink-safety','PASS')); print('PASS duplicate-manifest-keys-and-symlink-safety',flush=True)
        # Error precedence and preservation of previously committed generation.
        case=wd/'case0';out=wd/'out0'
        prior=(out/'CURRENT').read_bytes()
        (case/'wal/inventory/north-0.jsonl').unlink()
        proc=run(case,out)
        assert proc.returncode!=0
        assert json.loads((out/'error.json').read_bytes())['code']=='INVALID_INPUT'
        assert (out/'CURRENT').read_bytes()==prior
        results.append(('invalid-input-pointer-preservation','PASS')); print('PASS invalid-input-pointer-preservation',flush=True)
        # Public golden fixture must match its own observed contract.
        # The /tests tree is root-only in the separate verifier image. Copy the
        # public fixture into the candidate-readable scratch area before using
        # it as input for the unprivileged recovery process.
        public_source=pathlib.Path(__file__).parent/'public_case'
        if public_source.exists():
            public=wd/'public_case'
            shutil.copytree(public_source,public)
            for item in public.rglob('*'):
                item.chmod(0o755 if item.is_dir() else 0o644)
            public.chmod(0o755)
            target=wd/'publicoutput'
            proc=run(public,target)
            assert proc.returncode==0,('public-golden',proc.stdout,proc.stderr)
            plan=json.loads((target/(target/'CURRENT').read_text().strip()/'plan.json').read_text())
            assert plan['cut']=={'inventory':3,'orders':2} and plan['objective']==5
            results.append(('independent-public-golden','PASS')); print('PASS independent-public-golden',flush=True)
    for label,result in results:print(label,result)

if __name__=='__main__':
    main()
