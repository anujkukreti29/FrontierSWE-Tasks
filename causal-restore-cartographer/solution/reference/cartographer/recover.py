"""Reference implementation of the protocol 2 recovery engine.

The implementation reconstructs replica histories and searches for a globally
consistent recovery, then materializes and publishes the selected state.
"""
from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import defaultdict
from pathlib import Path
from .codec import canonical_bytes, sha256_bytes, strict_json_bytes

HEX = re.compile(r'^[0-9a-f]{64}$')
NONCE = re.compile(r'^[0-9a-f]{32}$')
STREAM = re.compile(r'^[a-z][a-z0-9_]*$')
ZERO = '0' * 64
MAXINT = 2**53-1

class RecoveryError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code=code


def assert_json_domain(x):
    if x is None or isinstance(x, (str, bool)):
        if isinstance(x, str):
            x.encode('utf-8', errors='strict')
        return
    if type(x) is int and -MAXINT <= x <= MAXINT:
        return
    if isinstance(x, list):
        for z in x: assert_json_domain(z)
        return
    if isinstance(x, dict):
        for k, v in x.items():
            if not isinstance(k, str): raise ValueError('non-string key')
            k.encode('utf-8', errors='strict')
            assert_json_domain(v)
        return
    raise ValueError('unsupported JSON type')


def read_strict(path):
    x = strict_json_bytes(path.read_bytes())
    assert_json_domain(x)
    return x


def props(x, names):
    return type(x) is dict and set(x) == set(names)


def valid_requires(x, streams, owner):
    if type(x) is not list: return False
    previous = None
    for r in x:
        if not props(r, ['stream','seq','event_id']): return False
        if r['stream'] not in streams or r['stream']==owner or type(r['seq']) is not int or not (1<=r['seq']<=MAXINT) or not isinstance(r['event_id'],str) or not HEX.fullmatch(r['event_id']): return False
        key = (r['stream'],r['seq'],r['event_id'])
        if previous is not None and previous >= key: return False
        previous = key
    return True


def read_case(root, out):
    try:
        raw_out = Path(out).absolute()
        # An existing symlink in the destination path must not redirect a
        # privileged recovery process into a different filesystem subtree.
        cursor = Path(raw_out.anchor)
        for part in raw_out.parts[1:]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RecoveryError('INVALID_INPUT')
        if raw_out.exists() and not raw_out.is_dir():
            raise RecoveryError('INVALID_INPUT')
        for relative in ('CURRENT','error.json','generations'):
            if (raw_out/relative).is_symlink():
                raise RecoveryError('INVALID_INPUT')
        root = Path(root).resolve(strict=True)
        out = raw_out.resolve(strict=False)
    except (OSError, ValueError, RuntimeError) as exc:
        raise RecoveryError('INVALID_INPUT') from exc
    if root == out or root in out.parents or out in root.parents:
        raise RecoveryError('INVALID_INPUT')
    casepath = root/'case.json'
    if casepath.is_symlink() or not casepath.is_file():
        raise RecoveryError('INVALID_INPUT')
    try:
        manifest = read_strict(casepath)
        if not props(manifest,['protocol','streams','snapshots','archives','integrity']) or type(manifest['protocol']) is not int or manifest['protocol'] != 2: raise ValueError('bad manifest')
        streams=manifest['streams']
        if type(streams) is not list or len(streams)<1 or any(type(s) is not str or not STREAM.fullmatch(s) for s in streams) or streams != sorted(set(streams)): raise ValueError('streams')
        if not all(type(manifest[k]) is dict and set(manifest[k])==set(streams) for k in ('snapshots','archives')): raise ValueError('map')
        declared=set()
        for s in streams:
            snaps=manifest['snapshots'][s]
            archives=manifest['archives'][s]
            if type(snaps) is not list or type(archives) is not list: raise ValueError('lists')
            for p in snaps:
                if not isinstance(p,str) or p in declared: raise ValueError('duplicate path')
                declared.add(p)
            reps=set()
            for a in archives:
                if not props(a,['replica','fragments']) or not isinstance(a['replica'],str) or not 0<len(a['replica'])<=100 or not a['replica'].isascii() or any(ord(c)<32 or c in '/\\' for c in a['replica']) or a['replica'] in reps: raise ValueError('replica')
                reps.add(a['replica'])
                if type(a['fragments']) is not list: raise ValueError('fragments')
                for p in a['fragments']:
                    if not isinstance(p,str) or p in declared: raise ValueError('duplicate path')
                    declared.add(p)
        if type(manifest['integrity']) is not dict or set(manifest['integrity']) != {p for v in manifest['snapshots'].values() for p in v} or any(not isinstance(h,str) or not HEX.fullmatch(h) for h in manifest['integrity'].values()): raise ValueError('integrity')
        for rel in declared:
            if (not isinstance(rel,str) or not rel or rel.startswith('/') or '\\' in rel or '\x00' in rel or any(part in ('','.','..') for part in rel.split('/')) or any(ord(c)<32 for c in rel)): raise ValueError('path syntax')
            p = root/rel
            if not p.resolve().is_relative_to(root) or not p.is_file(): raise ValueError('file absent')
            q=root
            for part in rel.split('/'):
                q=q/part
                if q.is_symlink(): raise ValueError('symlink')
        hashes={'case.json':sha256_bytes(casepath.read_bytes())}
        for rel in sorted(declared): hashes[rel]=sha256_bytes((root/rel).read_bytes())
        return root,manifest,hashes
    except (ValueError,UnicodeError,KeyError,OSError,TypeError,RecursionError) as exc:
        raise RecoveryError('INVALID_INPUT') from exc


def read_snapshots(root,m,hashes):
    streams=m['streams']
    result={}
    for s in streams:
        found=[]
        for p in m['snapshots'][s]:
            if hashes[p] != m['integrity'][p]: continue
            try:
                x=read_strict(root/p)
                if not props(x,['id','stream','seq','tip','state_format','state','requires','witnesses']): continue
                if x['stream']!=s or not isinstance(x['id'],str) or not x['id'].isascii() or not (0<len(x['id'])<=100) or any(c in '/\\' or ord(c)<32 for c in x['id']): continue
                if type(x['seq']) is not int or not 0<=x['seq']<=MAXINT or type(x['state_format']) is not int or x['state_format'] not in (1,2): continue
                if not isinstance(x['tip'],str) or not HEX.fullmatch(x['tip']) or type(x['state']) is not dict: continue
                if not valid_requires(x['requires'],streams,s): continue
                if type(x['witnesses']) is not dict: continue
                if any(type(k) is not str or not re.fullmatch(r'[1-9][0-9]*',k) or int(k)>x['seq'] or type(v) is not str or not HEX.fullmatch(v) for k,v in x['witnesses'].items()): continue
                if (x['seq']==0 and (x['tip']!=ZERO or x['witnesses'])) or (x['seq']>0 and str(x['seq']) not in x['witnesses']): continue
                found.append(x)
            except (ValueError,UnicodeError,TypeError,OSError,OverflowError): pass
        idcount=defaultdict(int)
        for x in found:idcount[x['id']]+=1
        result[s]=[x for x in found if idcount[x['id']]==1]
        if not result[s]: raise RecoveryError('NO_USABLE_SNAPSHOT')
    return result


def validate_op(op,fmt):
    if type(op) is not dict or type(op.get('kind')) is not str: return False
    if fmt==1:
        if op['kind']=='set': return props(op,['kind','name','payload']) and isinstance(op['name'],str)
        if op['kind']=='remove': return props(op,['kind','name']) and isinstance(op['name'],str)
    else:
        if op['kind']=='put': return props(op,['kind','key','value']) and isinstance(op['key'],str)
        if op['kind']=='delete': return props(op,['kind','key']) and isinstance(op['key'],str)
    return False


def read_records(root,m):
    streams=m['streams']; raw=defaultdict(dict); equivocations=defaultdict(set)
    for s in streams:
        for archive in m['archives'][s]:
            replica=archive['replica']
            for path in archive['fragments']:
                with (root/path).open('rb') as fh:
                    for line_num,line in enumerate(fh, 1):
                        try:
                            r=strict_json_bytes(line)
                            assert_json_domain(r)
                            if not props(r,['stream','seq','nonce','event_id','format','operation','requires','prev','digest']): continue
                            if r['stream']!=s or type(r['seq']) is not int or not 1<=r['seq']<=MAXINT: continue
                            if type(r['format']) is not int or r['format'] not in (1,2): continue
                            if not all(isinstance(r[k],str) and bool(HEX.fullmatch(r[k])) for k in ('event_id','prev','digest')): continue
                            if not isinstance(r['nonce'],str) or not NONCE.fullmatch(r['nonce']) or not validate_op(r['operation'],r['format']) or not valid_requires(r['requires'],streams,s): continue
                            identity={k:r[k] for k in ('stream','seq','nonce','format','operation')}
                            if sha256_bytes(canonical_bytes(identity)) != r['event_id']: continue
                            digest=sha256_bytes(canonical_bytes({k:v for k,v in r.items() if k != 'digest'}))
                            if digest != r['digest']: continue
                            key=(s,r['seq'],r['event_id'])
                            equivocations[key].add(r['digest'])
                            location=(replica,path,line_num)
                            if r['digest'] not in raw[s] or location < raw[s][r['digest']][1]:
                                raw[s][r['digest']] = (r,location)
                        except (ValueError,UnicodeError,TypeError,OverflowError,RecursionError): continue
    forbidden={k for k,ds in equivocations.items() if len(ds)>1}
    records={s: {k:v for k,v in raw[s].items() if (s,v[0]['seq'],v[0]['event_id']) not in forbidden} for s in streams}
    return records


def maximal_paths(snap, records):
    """Enumerate complete rooted histories without recursing per WAL record."""
    edges=defaultdict(list)
    for r,location in records.values():
        edges[(r['seq'],r['prev'])].append((r,location))
    for children in edges.values(): children.sort(key=lambda x:x[0]['digest'])
    start=(snap['seq']+1,snap['tip'])
    # Explicit stack: each frame contains an iterator of children of one parent.
    stack=[iter(edges.get(start,()))]
    path=[]; result=[]
    while stack:
        try:
            item=next(stack[-1]); path.append(item)
            next_key=(item[0]['seq']+1,item[0]['digest'])
            stack.append(iter(edges.get(next_key,())))
        except StopIteration:
            if len(stack)==1 and not path:
                result.append(())
            elif path and len(stack)>1 and not edges.get((path[-1][0]['seq']+1,path[-1][0]['digest'])):
                result.append(tuple(path))
            stack.pop()
            if path: path.pop()
    # Remove accidentally duplicated terminal paths from overlapping records.
    return list({tuple(x[0]['digest'] for x in p):p for p in result}.values())


def reference_satisfied(req,choice,cuts):
    stream=req['stream']; snap,path=choice[stream]
    seq=req['seq']
    if seq>cuts[stream]: return False
    if seq<=snap['seq']:
        return snap['witnesses'].get(str(seq))==req['event_id']
    return path[seq-snap['seq']-1][0]['event_id']==req['event_id']


def evaluate(choice, streams):
    cuts={s: choice[s][0]['seq'] + len(choice[s][1]) for s in streams}
    while True:
        altered=False
        for s in streams:
            snap,path=choice[s]
            if any(not reference_satisfied(d,choice,cuts) for d in snap['requires']): return None
            for r,_ in path[:cuts[s]-snap['seq']]:
                if any(not reference_satisfied(d,choice,cuts) for d in r['requires']):
                    cuts[s]=r['seq']-1; altered=True; break
        if not altered: break
    heads={s:(choice[s][0]['tip'] if cuts[s]==choice[s][0]['seq'] else choice[s][1][cuts[s]-choice[s][0]['seq']-1][0]['digest']) for s in streams}
    plan={'protocol':2,'cut':cuts,'snapshots':{s:choice[s][0]['id'] for s in streams},'heads':heads,'objective':sum(cuts.values()),'replay':{s:[r['digest'] for r,loc in choice[s][1][:cuts[s]-choice[s][0]['seq']]] for s in streams}}
    return plan


def select(snaps, records, streams):
    """Globally optimal branch search with admissible causal upper bounds.

    The search branches only on checkpoint/lineage alternatives, not on every
    possible sequence cut. For fixed lineages, the greatest causally closed cut
    is found by monotone rollback. At a partial choice, unassigned lineages
    are treated optimistically; thus an incomplete search node can be safely
    pruned only when its optimistic plan cannot beat the incumbent.
    """
    alternatives = {}
    ids_by_stream = {}
    for s in streams:
        opts = []
        for snap in snaps[s]:
            for path in maximal_paths(snap, records[s]):
                event_ids = {int(k): v for k, v in snap['witnesses'].items()}
                for r, _ in path:
                    event_ids[r['seq']] = r['event_id']
                opts.append((snap, path, event_ids, snap['seq']+len(path)))
        if not opts:
            raise RecoveryError('NO_CONSISTENT_RECOVERY')
        # Largest options first establishes a strong incumbent early.
        opts.sort(key=lambda o:(-o[3], o[0]['id'], o[0]['tip'],
                                tuple(r['digest'] for r, _ in o[1])))
        alternatives[s] = opts
        by_id = defaultdict(set)
        for opt in opts:
            for seq, event_id in opt[2].items():
                by_id[seq].add(event_id)
        ids_by_stream[s] = by_id

    # Stream ordering uses the most constrained domains first. When equally
    # constrained, larger foreign-dependency surfaces are considered first.
    def constraints(s):
        opts = alternatives[s]
        ndeps = max(sum(len(r['requires']) for r,_ in opt[1]) + len(opt[0]['requires'])
                    for opt in opts)
        return (len(opts), -ndeps, s)

    order = sorted(streams, key=constraints)
    best = None
    best_choice = None
    assigned = {}
    best_rank = None
    max_length = {s: max(o[3] for o in alternatives[s]) for s in streams}
    min_snapshot = {s: min(o[0]['id'] for o in alternatives[s]) for s in streams}
    # All possible heads have lowercase hexadecimal digests; a zero digest is
    # a safe optimistic lower bound for an unassigned alternative.

    def optimistic_cut():
        # Each stream has a domain of checkpoint/historical lineage options.
        # Propagate upper cuts over *all* currently possible options, including
        # unassigned streams. Removing an unsupported option and truncating a
        # record only removes behavior impossible in every completion.
        domains={s:[[opt,opt[3]] for opt in (
                 (assigned[s],) if s in assigned else alternatives[s])]
                 for s in streams}

        def has_support(req):
            for alternative,limit in domains[req['stream']]:
                if (limit>=req['seq'] and
                    alternative[2].get(req['seq'])==req['event_id']):
                    return True
            return False

        while True:
            changed=False
            for s in streams:
                current=[]
                for option, cap in domains[s]:
                    snap,path,_,end=option
                    if any(not has_support(req) for req in snap['requires']):
                        changed=True
                        continue
                    new_cap=cap
                    for record,_ in path[:cap-snap['seq']]:
                        if any(not has_support(req) for req in record['requires']):
                            new_cap=record['seq']-1
                            break
                    if new_cap!=cap:
                        changed=True
                    current.append([option,new_cap])
                if not current:
                    return None
                domains[s]=current
            if not changed:
                break
        return {s:max(limit for _,limit in domains[s]) for s in streams}

    def incumbent_beats_bound(cuts):
        if best is None:
            return False
        score = sum(cuts.values())
        if score < best['objective']:
            return True
        if score > best['objective']:
            return False
        current_vector = tuple(cuts[s] for s in streams)
        best_vector = tuple(best['cut'][s] for s in streams)
        if current_vector < best_vector:
            return True
        if current_vector > best_vector:
            return False
        # Equal score and cut: find a lower bound on checkpoint names. If this
        # bound is already worse, no descendant can win the tie-breaker.
        snap_vector = tuple(assigned[s][0]['id'] if s in assigned
                            else min_snapshot[s] for s in streams)
        best_snaps = tuple(best['snapshots'][s] for s in streams)
        if snap_vector > best_snaps:
            return True
        if snap_vector < best_snaps:
            return False
        # The minimum possible head digest is an admissible tie-breaker bound.
        head_vector = []
        for s in streams:
            if s not in assigned:
                head_vector.append(ZERO)
                continue
            snap, path, _, _ = assigned[s]
            cut = cuts[s]
            head_vector.append(snap['tip'] if cut == snap['seq']
                               else path[cut-snap['seq']-1][0]['digest'])
        return tuple(head_vector) >= tuple(best['heads'][s] for s in streams)

    def consider(choice):
        nonlocal best,best_choice
        plan=evaluate(choice,streams)
        if plan is None:
            return
        rank=(-plan['objective'], tuple(-plan['cut'][s] for s in streams),
              tuple(plan['snapshots'][s] for s in streams),
              tuple(plan['heads'][s] for s in streams))
        if best is None or rank<(-best['objective'],
                                tuple(-best['cut'][s] for s in streams),
                                tuple(best['snapshots'][s] for s in streams),
                                tuple(best['heads'][s] for s in streams)):
            best,best_choice=plan,choice.copy()

    # Feasible complete assignments provide lower bounds, never a substitute
    # for proof of optimality. An early incumbent helps when a tempting local
    # history breaks a strongly connected component of causal dependencies.
    seedings=(
        {s:(alternatives[s][0][0],alternatives[s][0][1]) for s in streams},
        {s:(opt[0],opt[1]) for s in streams
         for opt in [min(alternatives[s],key=lambda o:(o[0]['id'],-o[3],o[0]['tip']))]},
        {s:(opt[0],opt[1]) for s in streams
         for opt in [max(alternatives[s],key=lambda o:(len(o[0]['requires'])+
                    sum(len(r['requires']) for r,_ in o[1]),o[3]))]},
    )
    for initial in seedings:
        consider(initial)

    def search(depth):
        nonlocal best, best_choice
        optimistic = optimistic_cut()
        if optimistic is None or incumbent_beats_bound(optimistic):
            return
        if depth == len(order):
            consider({s:assigned[s][:2] for s in streams})
            return
        s = order[depth]
        for option in alternatives[s]:
            assigned[s] = option
            search(depth+1)
            del assigned[s]

    search(0)
    if best is None:
        raise RecoveryError('NO_CONSISTENT_RECOVERY')
    return best,best_choice

def save_json(path,x):
    with open(path,'wb') as f:
        f.write(canonical_bytes(x))
        f.flush();os.fsync(f.fileno())


def syncdir(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def materialize(tmp,plan,choice,hashes,streams):
    save_json(tmp/'plan.json', plan)
    conn=sqlite3.connect(str(tmp/'restored.sqlite'))
    try:
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('CREATE TABLE kv(stream TEXT NOT NULL,key TEXT NOT NULL,value_json TEXT NOT NULL,PRIMARY KEY(stream,key))')
        conn.execute('CREATE TABLE applied(stream TEXT NOT NULL,seq INTEGER NOT NULL,event_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(stream,seq))')
        conn.execute('CREATE TABLE checkpoint(stream TEXT PRIMARY KEY,snapshot_id TEXT NOT NULL,base_seq INTEGER NOT NULL,final_seq INTEGER NOT NULL,final_digest TEXT NOT NULL)')
        provenance={}
        for s in streams:
            snap,path=choice[s]
            state=dict(snap['state'])
            selected=path[:plan['cut'][s]-snap['seq']]
            provenance[s]=[]
            for r,loc in selected:
                op=r['operation'];kind=op['kind']
                if kind in ('put','set'):
                    state[op['key'] if kind=='put' else op['name']]=op['value'] if kind=='put' else op['payload']
                else: state.pop(op['key'] if kind=='delete' else op['name'],None)
                conn.execute('INSERT INTO applied VALUES(?,?,?,?)',(s,r['seq'],r['event_id'],r['digest']))
                provenance[s].append({'digest':r['digest'],'replica':loc[0],'path':loc[1],'line':loc[2]})
            for k,v in state.items():
                conn.execute('INSERT INTO kv VALUES(?,?,?)',(s,k,canonical_bytes(v).decode('utf-8')))
            conn.execute('INSERT INTO checkpoint VALUES(?,?,?,?,?)',(s,snap['id'],snap['seq'],plan['cut'][s],plan['heads'][s]))
        conn.commit()
    finally: conn.close()
    dbfd=os.open(str(tmp/'restored.sqlite'),os.O_RDONLY)
    try:os.fsync(dbfd)
    finally:os.close(dbfd)
    gen=sha256_bytes(canonical_bytes({'protocol':2,'plan':plan,'input_sha256':hashes}))
    ev={'protocol':2,'cut':plan['cut'],'snapshots':plan['snapshots'],'heads':plan['heads'],'input_sha256':hashes,'provenance':provenance,'recovery_status':'complete','generation_id':gen}
    save_json(tmp/'evidence.json',ev)
    syncdir(tmp)
    return gen


def publish(output,plan,choice,hashes,streams):
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    generations=output/'generations';generations.mkdir(exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix='.staging-',dir=output))
    try:
        gen=materialize(stage,plan,choice,hashes,streams)
        dest=generations/gen
        if dest.exists():
            # Immutable reuse only when bytes and logical database are already correct.
            if dest.is_symlink() or not dest.is_dir() or any(not (dest/f).is_file() for f in ('plan.json','evidence.json','restored.sqlite')) or (stage/'plan.json').read_bytes()!=(dest/'plan.json').read_bytes() or (stage/'evidence.json').read_bytes()!=(dest/'evidence.json').read_bytes():
                raise RuntimeError('Existing generation conflicts')
            with sqlite3.connect(str(dest/'restored.sqlite')) as a, sqlite3.connect(str(stage/'restored.sqlite')) as b:
                for table in ('kv','applied','checkpoint'):
                    if a.execute('SELECT * FROM '+table+' ORDER BY 1,2').fetchall()!=b.execute('SELECT * FROM '+table+' ORDER BY 1,2').fetchall(): raise RuntimeError('Existing generation database conflicts')
        else:
            os.rename(stage,dest)
            stage=None
        syncdir(generations)
        fd,temp=tempfile.mkstemp(prefix='.current-',dir=output)
        try:
            with os.fdopen(fd,'wb') as fp:
                fp.write(('generations/'+gen+'\n').encode('utf-8'))
                fp.flush();os.fsync(fp.fileno())
            os.replace(temp,output/'CURRENT')
        finally:
            if os.path.exists(temp):os.unlink(temp)
        syncdir(output)
        if (output/'error.json').exists(): (output/'error.json').unlink()
    finally:
        if stage and stage.exists():shutil.rmtree(stage)


def recover(input_dir,output_dir):
    try:
        root,m,hashes=read_case(input_dir,output_dir)
        snaps=read_snapshots(root,m,hashes)
        records=read_records(root,m)
        plan,choice=select(snaps,records,m['streams'])
        publish(output_dir,plan,choice,hashes,m['streams'])
    except RecoveryError as exc:
        out=Path(output_dir)
        if not out.exists() or (out.is_dir() and not out.is_symlink() and not (out/'error.json').is_symlink()):
            out.mkdir(parents=True,exist_ok=True)
            save_json(out/'error.json',{'protocol':2,'code':exc.code})
        raise SystemExit(2)
