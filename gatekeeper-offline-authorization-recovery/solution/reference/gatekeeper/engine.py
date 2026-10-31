"""Gatekeeper reference authorization and recovery engine.

Protocol: /workspace/contract/PROTOCOL_V2.md.
"""
import json
import re
import sqlite3
from .primitives import canonical, digest, verify_signed, proof_valid, EMPTY
from .store import StateError, connection, get, put, transaction, status_state

MAX = 2**63 - 1
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}\Z',re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z',re.ASCII)
SEG = re.compile(r'/([A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*)?\Z',re.ASCII)
ACTIONS = {'inspect','calibrate','restart'}
GRANT_KEYS = {'kind','tenant','grant_id','parent_id','issuer_key','issued_seq','holder','holder_key','resource_prefix','actions','not_before','expires','delegable','remaining_depth','signature'}
CHK_KEYS = {'kind','tenant','seq','previous_digest','issued_tick','revoked_ids','issuance_count','issuance_root','signer','signature'}
ROT_KEYS = {'kind','tenant','seq','previous_digest','issued_tick','old_signer','new_signer','new_root_public_key','old_signature','new_signature'}
BUNDLE_KEYS = {'kind','grant','proof'}
PROOF_KEYS = {'checkpoint_seq','index','count','siblings'}
REQ_KEYS = {'kind','tenant','request_id','holder','resource','action','chain','signature'}

def num(v):return type(v) is int and 0<=v<=MAX

def ident(v):return type(v) is str and bool(IDENT.fullmatch(v))

def pub_b64(v):
    import base64
    if type(v) is not str: return False
    try:
        raw=base64.b64decode(v,validate=True)
        return len(raw)==32 and base64.b64encode(raw).decode()==v
    except (ValueError,TypeError): return False

def sig_b64(v):
    import base64
    if type(v) is not str:return False
    try:
        raw=base64.b64decode(v,validate=True)
        return len(raw)==64 and base64.b64encode(raw).decode()==v
    except (ValueError,TypeError):return False

def path(v):return type(v) is str and len(v)<=1024 and bool(SEG.fullmatch(v))

def subset_path(child,parent):return child==parent or parent=='/' or child.startswith(parent.rstrip('/')+'/')

def ordered_ids(value):return type(value) is list and all(ident(x) for x in value) and value==sorted(set(value))

def schema(record,kind):
    if type(record) is not dict:raise StateError('INVALID_INPUT')
    expected = {'checkpoint':CHK_KEYS,'rotate':ROT_KEYS,'grant':GRANT_KEYS,'issuance_bundle':BUNDLE_KEYS,'request':REQ_KEYS}.get(kind)
    if expected is None or set(record)!=expected or record.get('kind')!=kind:raise StateError('INVALID_INPUT')
    if kind in ('checkpoint','rotate'):
        if not all(num(record[k]) for k in ('seq','issued_tick')) or not all(ident(record[k]) for k in ('tenant',)) or not HEX.fullmatch(record['previous_digest'] if type(record['previous_digest']) is str else ''):raise StateError('INVALID_INPUT')
        if kind=='checkpoint':
            if not (ordered_ids(record['revoked_ids']) and num(record['issuance_count']) and num(record['seq']) and HEX.fullmatch(record['issuance_root'] if type(record['issuance_root']) is str else '') and ident(record['signer']) and sig_b64(record['signature'])):raise StateError('INVALID_INPUT')
        else:
            if not (ident(record['old_signer']) and ident(record['new_signer']) and pub_b64(record['new_root_public_key']) and sig_b64(record['old_signature']) and sig_b64(record['new_signature'])):raise StateError('INVALID_INPUT')
    if kind=='grant':
        if not(all(ident(record[k]) for k in ('tenant','grant_id','holder')) and num(record['issued_seq']) and num(record['not_before']) and num(record['expires']) and num(record['remaining_depth']) and record['expires']>record['not_before'] and path(record['resource_prefix']) and pub_b64(record['holder_key']) and sig_b64(record['signature'])):raise StateError('INVALID_INPUT')
        if type(record['delegable']) is not bool:raise StateError('INVALID_INPUT')
        if (type(record['actions']) is not list or not record['actions'] or record['actions']!=sorted(set(record['actions'])) or not set(record['actions'])<=ACTIONS):raise StateError('INVALID_INPUT')
        if record['parent_id'] is not None and not ident(record['parent_id']):raise StateError('INVALID_INPUT')
        if not ((record['parent_id'] is None and ident(record['issuer_key'])) or (record['parent_id'] is not None and record['issuer_key']=='holder:'+record['parent_id'])):raise StateError('INVALID_INPUT')
    if kind=='issuance_bundle':
        schema(record['grant'],'grant');p=record['proof']
        if type(p) is not dict or set(p)!=PROOF_KEYS:raise StateError('INVALID_INPUT')
        if not (all(num(p[k]) for k in ('checkpoint_seq','index','count')) and type(p['siblings']) is list and all(type(x) is str and HEX.fullmatch(x) for x in p['siblings'])):raise StateError('INVALID_INPUT')
    if kind=='request':
        if not(all(ident(record[k]) for k in ('tenant','request_id','holder')) and path(record['resource']) and record['action'] in ACTIONS and type(record['chain']) is list and 1<=len(record['chain'])<=8 and all(ident(x) for x in record['chain']) and sig_b64(record['signature'])):raise StateError('INVALID_INPUT')
    return record

def unpack(row):return json.loads(row[0]) if row else None

def tenant(db):return get(db,'tenant')

def root_before(db, seq):
    if seq==1:
        t=json.loads(get(db,'trust'))
        return t['genesis_root_key_id'],t['genesis_root_public_key']
    row=db.execute('SELECT trusted_root_id,root_pubkey FROM authority WHERE seq=?',(seq-1,)).fetchone()
    return tuple(row) if row else None

def authority_by_digest(db,parent):
    if parent=='0'*64:
        return (0,'0'*64,0)  # seq, digest, issued_tick
    return db.execute('SELECT seq,digest,issued_tick FROM authority WHERE digest=?',(parent,)).fetchone()

def ingest_reply(r,state,reason=None,seq=None):
    return {'record_digest':digest(r['grant'] if r['kind']=='issuance_bundle' else r), 'state':state,'reason':reason,'seq':seq}

def mark_grant(db,grant,signature_checked=True):
    current=db.execute('SELECT digest FROM grants WHERE grant_id=?',(grant['grant_id'],)).fetchone()
    d=digest(grant)
    if current:
        if current[0]!=d and signature_checked:
            db.execute('INSERT OR IGNORE INTO grant_conflicts(grant_id,digest) VALUES(?,?)',(grant['grant_id'],d))
            return 'REJECTED','CONFLICT'
        return 'DUPLICATE',None
    db.execute('INSERT INTO grants(grant_id,digest,record_json,parent_id,authenticated) VALUES(?,?,?,?,1)',(grant['grant_id'],d,canonical(grant),grant['parent_id']))
    return 'APPLIED',None

def authenticate_root(db,rec, persist=True):
    g=rec['grant'];proof=rec['proof']
    cp=db.execute('SELECT record_json,trusted_root_id,root_pubkey FROM authority WHERE seq=?',(g['issued_seq'],)).fetchone()
    if cp is None:
        return 'PENDING','MISSING_CHECKPOINT'
    cpdata=json.loads(cp[0])
    if cpdata['kind']!='checkpoint':return 'REJECTED','BAD_LINK'
    if not (g['parent_id'] is None and proof['checkpoint_seq']==g['issued_seq'] and g['issuer_key']==cp[1] and g['not_before']>=cpdata['issued_tick']):return 'REJECTED','BAD_LINK'
    if not verify_signed(g,'grant',cp[2]):return 'REJECTED','BAD_SIGNATURE'
    if proof['count']!=cpdata['issuance_count'] or not proof_valid(g,proof['index'],proof['count'],proof['siblings'],cpdata['issuance_root']):return 'REJECTED','BAD_PROOF'
    return mark_grant(db,g)

def authenticate_delegate(db,g):
    if g['parent_id'] is None:return 'REJECTED','BAD_LINK'
    parent_row=db.execute('SELECT record_json FROM grants WHERE grant_id=?',(g['parent_id'],)).fetchone()
    if parent_row is None:return 'PENDING','MISSING_GRANT_PARENT'
    parent=json.loads(parent_row[0])
    if g['tenant']!=parent['tenant']:return 'REJECTED','WRONG_TENANT'
    if not verify_signed(g,'grant',parent['holder_key']):return 'REJECTED','BAD_SIGNATURE'
    if not (parent['delegable'] and parent['remaining_depth']>0 and g['remaining_depth']<parent['remaining_depth'] and g['issued_seq']>=parent['issued_seq'] and g['issued_seq']<=int(get(db,'seq')) and set(g['actions'])<=set(parent['actions']) and subset_path(g['resource_prefix'],parent['resource_prefix']) and g['not_before']>=parent['not_before'] and g['expires']<=parent['expires'] and (g['remaining_depth']!=0 or not g['delegable'])):
        return 'REJECTED','BAD_LINK'
    return mark_grant(db,g)

def pending_grant(db,r,kind):
    d=digest(r['grant'] if kind=='issuance_bundle' else r)
    db.execute('INSERT OR IGNORE INTO pending_grants(digest,grant_id,record_json) VALUES(?,?,?)', (d,r['grant']['grant_id'] if kind=='issuance_bundle' else r['grant_id'],canonical(r)))

def drain_grants(db):
    while True:
        changed=False
        for d,encoded in list(db.execute('SELECT digest,record_json FROM pending_grants')):
            obj=json.loads(encoded)
            state,reason=(authenticate_root(db,obj) if obj['kind']=='issuance_bundle' else authenticate_delegate(db,obj))
            if state!='PENDING':
                db.execute('DELETE FROM pending_grants WHERE digest=?',(d,));changed=True
        if not changed:break

def ingest_authority(db,rec):
    d=digest(rec)
    # Duplicates must not advance state, or create an artificial fork.
    known=db.execute('SELECT seq FROM authority WHERE digest=?',(d,)).fetchone()
    if known:return 'DUPLICATE',None,known[0]
    existing=db.execute('SELECT digest FROM pending_authority WHERE digest=?',(d,)).fetchone()
    parent=authority_by_digest(db,rec['previous_digest'])
    if parent is None:
        if not existing:
            db.execute('INSERT INTO pending_authority(digest,record_json,previous_digest,seq) VALUES(?,?,?,?)',(d,canonical(rec),rec['previous_digest'],rec['seq']))
        return 'PENDING','MISSING_PARENT',rec['seq']
    seq=parent[0]+1
    if rec['seq']!=seq or rec['issued_tick']<parent[2]:return 'REJECTED','BAD_LINK',rec['seq']
    roots=root_before(db,seq)
    if roots is None:return 'REJECTED','BAD_LINK',rec['seq']
    rid,rpub=roots
    if rec['kind']=='checkpoint':
        if rec['signer']!=rid or not verify_signed(rec,'checkpoint',rpub):return 'REJECTED','BAD_SIGNATURE',rec['seq']
        if rec['issuance_count']==0 and rec['issuance_root']!=EMPTY.hex():return 'REJECTED','BAD_PROOF',rec['seq']
        new_id,new_pub=rid,rpub
    else:
        if rec['old_signer']!=rid or rec['new_signer']==rid or not verify_signed(rec,'rotate',rpub,signature_field='old_signature',excluded=['old_signature','new_signature']) or not verify_signed(rec,'rotate',rec['new_root_public_key'],signature_field='new_signature',excluded=['old_signature','new_signature']):return 'REJECTED','BAD_SIGNATURE',rec['seq']
        new_id,new_pub=rec['new_signer'],rec['new_root_public_key']
    old=db.execute('SELECT digest FROM authority WHERE seq=?',(seq,)).fetchone()
    if old is not None:
        if old[0]==d:return 'DUPLICATE',None,seq
        db.execute('INSERT OR IGNORE INTO authority_forks(parent_digest,child_digest,record_json) VALUES(?,?,?)',(rec['previous_digest'],d,canonical(rec)))
        put(db,'quarantined',1)
        return 'QUARANTINED','CONFLICT',seq
    # A previously verified parent off-tip would imply conflict, but the
    # contiguous applied history is represented by one seq per parent.
    db.execute('INSERT INTO authority(seq,digest,record_json,previous_digest,issued_tick,kind,trusted_root_id,root_pubkey) VALUES(?,?,?,?,?,?,?,?)',(seq,d,canonical(rec),rec['previous_digest'],rec['issued_tick'],rec['kind'],new_id,new_pub))
    put(db,'seq',seq);put(db,'last_digest',d);put(db,'last_issued_tick',rec['issued_tick']);put(db,'root_id',new_id);put(db,'root_pubkey',new_pub)
    if rec['kind']=='checkpoint':
        put(db,'last_checkpoint_tick',rec['issued_tick']);put(db,'last_checkpoint_seq',seq)
        for gid in rec['revoked_ids']:
            db.execute('INSERT OR IGNORE INTO revoked(grant_id,revoked_at_seq) VALUES(?,?)',(gid,seq))
    return 'APPLIED',None,seq

def drain_authority(db):
    while True:
        changed=False
        for d,raw in list(db.execute('SELECT digest,record_json FROM pending_authority ORDER BY seq,digest')):
            r=json.loads(raw)
            if authority_by_digest(db,r['previous_digest']) is None:continue
            state,_,_=ingest_authority(db,r)
            db.execute('DELETE FROM pending_authority WHERE digest=?',(d,))
            changed=True
        if not changed:break

def ingest_state(state,rec):
    if type(rec) is not dict or type(rec.get('kind')) is not str:raise StateError('INVALID_INPUT')
    schema(rec,rec['kind'])
    db=connection(state)
    try:
        with transaction(db,write=True):
            if rec['kind']=='issuance_bundle':
                g=rec['grant']; relevant=g
            else:relevant=rec
            if relevant.get('tenant')!=tenant(db):return ingest_reply(rec,'REJECTED','WRONG_TENANT')
            if rec['kind'] in ('checkpoint','rotate'):
                state_,reason,seq=ingest_authority(db,rec)
                if state_ in ('APPLIED','QUARANTINED'):
                    drain_authority(db);drain_grants(db)
                return ingest_reply(rec,state_,reason,seq)
            elif rec['kind']=='issuance_bundle':
                state_,reason=authenticate_root(db,rec)
                if state_=='PENDING':pending_grant(db,rec,'issuance_bundle')
                if state_=='APPLIED':drain_grants(db)
                return ingest_reply(rec,state_,reason)
            elif rec['kind']=='grant':
                state_,reason=authenticate_delegate(db,rec)
                if state_=='PENDING':pending_grant(db,rec,'grant')
                if state_=='APPLIED':drain_grants(db)
                return ingest_reply(rec,state_,reason)
            else:raise StateError('INVALID_INPUT')
    except sqlite3.DatabaseError as e:raise StateError('STATE_CORRUPT') from e
    finally:db.close()

def grant_chain(db,req):
    chain=req['chain']
    found=[]
    for grant_id in chain:
        row=db.execute('SELECT record_json FROM grants WHERE grant_id=?',(grant_id,)).fetchone()
        if row is None:
            pending=db.execute('SELECT 1 FROM pending_grants WHERE grant_id=? LIMIT 1',(grant_id,)).fetchone()
            return None,'PENDING_GRANT' if pending else 'INVALID_CHAIN'
        found.append(json.loads(row[0]))
    if found[0]['parent_id'] is not None or any(found[i]['parent_id']!=found[i-1]['grant_id'] for i in range(1,len(found))) or found[-1]['holder']!=req['holder'] or len(set(chain))!=len(chain):return None,'INVALID_CHAIN'
    return found,None

def decide_state(state,req,tick):
    schema(req,'request')
    if not num(tick):raise StateError('INVALID_INPUT')
    db=connection(state)
    try:
        with transaction(db,write=True):
            max_tick=int(get(db,'highest_protected_tick'))
            if tick>=max_tick:put(db,'highest_protected_tick',tick)
            old=db.execute('SELECT request_digest,effect_index FROM receipts WHERE request_id=?',(req['request_id'],)).fetchone()
            cpseq=int(get(db,'last_checkpoint_seq',0)) or None
            path=[]
            def res(decision,reason,applied=False,checkpoint=cpseq,grant_path=None):
                return {'request_id':req['request_id'],'decision':decision,'reason':reason,'applied':applied,'checkpoint_seq':checkpoint,'grant_path':grant_path if grant_path is not None else path}
            if old:
                if old[0]!=digest(req):return res('DENY','REQUEST_ID_REUSE')
                existing=db.execute('SELECT checkpoint_seq,grant_path_json FROM effects WHERE effect_index=?',(old[1],)).fetchone()
                if not existing:raise StateError('STATE_CORRUPT')
                return res('ALLOW','DUPLICATE',False,existing[0],json.loads(existing[1]))
            if get(db,'quarantined','0')=='1':return res('DEFER','QUARANTINED')
            if tick<max_tick or tick<int(get(db,'last_issued_tick',0)):return res('DEFER','TIME_ROLLBACK')
            checkpoint=get(db,'last_checkpoint_tick','null')
            if checkpoint=='null':return res('DEFER','NO_CHECKPOINT')
            trust=json.loads(get(db,'trust'))
            if tick>int(checkpoint)+trust['offline_window_ticks']:return res('DEFER','STALE_CHECKPOINT')
            if req['tenant']!=tenant(db):return res('DENY','CROSS_TENANT')
            grants,reason=grant_chain(db,req)
            if reason:return res('DEFER' if reason=='PENDING_GRANT' else 'DENY',reason)
            if not verify_signed(req,'request',grants[-1]['holder_key']):return res('DENY','BAD_SIGNATURE')
            if any(db.execute('SELECT 1 FROM grant_conflicts WHERE grant_id=?',(g['grant_id'],)).fetchone() for g in grants):return res('DENY','INVALID_CHAIN')
            if any(db.execute('SELECT 1 FROM revoked WHERE grant_id=?',(g['grant_id'],)).fetchone() for g in grants):return res('DENY','REVOKED')
            if any(req['action'] not in g['actions'] or not subset_path(req['resource'],g['resource_prefix']) for g in grants):return res('DENY','OUT_OF_SCOPE')
            if any(tick<g['not_before'] for g in grants):return res('DENY','NOT_YET_VALID')
            if any(tick>=g['expires'] for g in grants):return res('DENY','EXPIRED')
            path=[g['grant_id'] for g in grants]
            index=db.execute('SELECT COALESCE(MAX(effect_index),0)+1 FROM effects').fetchone()[0]
            db.execute('INSERT INTO effects(effect_index,request_id,request_digest,tick,authority_seq,checkpoint_seq,grant_path_json) VALUES(?,?,?,?,?,?,?)',(index,req['request_id'],digest(req),tick,int(get(db,'seq')),cpseq,canonical(path).decode()))
            db.execute('INSERT INTO receipts(request_id,request_digest,effect_index) VALUES(?,?,?)',(req['request_id'],digest(req),index))
            return res('ALLOW','AUTHORIZED',True,cpseq,path)
    except sqlite3.DatabaseError as e:raise StateError('STATE_CORRUPT') from e
    finally:db.close()

def effects_state(state,after,limit):
    if not (num(after) and num(limit) and 1<=limit<=1000):raise StateError('INVALID_INPUT')
    db=connection(state)
    try:
        with transaction(db):
            rows=db.execute('SELECT effect_index,request_id,request_digest,tick,authority_seq,checkpoint_seq,grant_path_json FROM effects WHERE effect_index>? ORDER BY effect_index LIMIT ?',(after,limit)).fetchall()
            effects=[{'index':r[0],'request_id':r[1],'request_digest':r[2],'tick':r[3],'authority_seq':r[4],'checkpoint_seq':r[5],'grant_path':json.loads(r[6])} for r in rows]
            return {'effects':effects,'next_after':rows[-1][0] if rows else after}
    except sqlite3.DatabaseError as e:raise StateError('STATE_CORRUPT') from e
    finally:db.close()
