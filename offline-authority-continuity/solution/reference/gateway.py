"""Durable signed-policy interpreter used by the reference solution.

Each input command runs in one SQLite write transaction. A single transaction
covers the authorization check, request state changes, and the effect journal.
"""
import hashlib
import json
import re
import sqlite3
from collections import defaultdict, deque
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .canonical import canonical_json, content_hash, parse_line

MAX = (1 << 63) - 1
ZERO = '0' * 64
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX128 = re.compile(r'^[0-9a-f]{128}$')
EVENT_FIELDS = {
    'grant': {'type', 'authority', 'principal', 'asset', 'action', 'valid_from_tick', 'expires_at_tick'},
    'revoke': {'type', 'authority', 'principal', 'asset', 'action'},
    'delegate': {'type', 'authority', 'delegator', 'delegatee', 'asset', 'action', 'valid_from_tick', 'expires_at_tick'},
    'undelegate': {'type', 'authority', 'delegator', 'delegatee', 'asset', 'action'},
    'retire_key': {'type', 'key_id'},
}


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX


def word(value):
    return type(value) is str and bool(value)


def exact(obj, keys):
    return type(obj) is dict and set(obj) == set(keys)


def reply(status, code=None):
    return {'status': status, 'code': code or status}


def reject(code):
    return reply('rejected', code)


def deny(code):
    return reply('denied', code)


def trust_data(path):
    raw = Path(path).read_text('utf-8')
    config = parse_line(raw)
    if not exact(config, ('sites',)) or type(config['sites']) is not dict:
        raise ValueError('Invalid trust file')
    sites = config['sites']
    for site, info in sites.items():
        if not word(site) or not (type(info) is dict and set(info) in ({'keys', 'critical'}, {'keys', 'critical', 'checkpoint_keys'})):
            raise ValueError('Invalid site trust settings')
        if type(info['keys']) is not list or type(info['critical']) is not list or type(info.get('checkpoint_keys', [])) is not list:
            raise ValueError('Invalid trust collections')
        keys = set()
        for k in info['keys']:
            if not exact(k, ('key_id', 'public_key_hex', 'from_seq', 'through_seq')):
                raise ValueError('Invalid key specification')
            if not word(k['key_id']) or k['key_id'] in keys:
                raise ValueError('Duplicate/invalid key identifier')
            keys.add(k['key_id'])
            if not (type(k['public_key_hex']) is str and HEX64.fullmatch(k['public_key_hex'])):
                raise ValueError('Invalid public key')
            if not (integer(k['from_seq'], 1) and integer(k['through_seq'], 1) and
                    k['from_seq'] <= k['through_seq']):
                raise ValueError('Invalid signing sequence window')
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(k['public_key_hex']))
        checkpoint_ids = set()
        for k in info.get('checkpoint_keys', []):
            if not exact(k, ('key_id', 'public_key_hex', 'from_seq', 'through_seq')):
                raise ValueError('Invalid checkpoint signing key')
            if not word(k['key_id']) or k['key_id'] in keys or k['key_id'] in checkpoint_ids:
                raise ValueError('Conflicting checkpoint signing key identifier')
            checkpoint_ids.add(k['key_id'])
            if type(k['public_key_hex']) is not str or not HEX64.fullmatch(k['public_key_hex']):
                raise ValueError('Invalid checkpoint public key')
            if not (integer(k['from_seq'], 1) and integer(k['through_seq'], 1) and
                    k['from_seq'] <= k['through_seq']):
                raise ValueError('Invalid checkpoint signing window')
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(k['public_key_hex']))
        pairs = set()
        for item in info['critical']:
            if not exact(item, ('asset', 'action')) or not word(item['asset']) or not word(item['action']):
                raise ValueError('Invalid critical action')
            pair = (item['asset'], item['action'])
            if pair in pairs:
                raise ValueError('Duplicate critical action')
            pairs.add(pair)
    return config, content_hash(config)


class Gateway:
    def __init__(self, trust_path, state_path):
        self.trust, fingerprint = trust_data(trust_path)
        self.db = sqlite3.connect(state_path, timeout=45, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA busy_timeout=45000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self._schema()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            old = self.db.execute("SELECT value FROM meta WHERE key='trust_fingerprint'").fetchone()
            if old is None:
                self.db.execute('INSERT INTO meta VALUES (?,?)', ('trust_fingerprint', fingerprint))
                for site in self.trust['sites']:
                    self.db.execute('INSERT INTO site VALUES (?,?,?,?)', (site, 1, ZERO, -1))
            elif old['value'] != fingerprint:
                raise ValueError('Incompatible trusted bootstrap')
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            raise

    def _schema(self):
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS site(site TEXT PRIMARY KEY, next_seq INTEGER NOT NULL,
            last_hash TEXT NOT NULL, max_tick INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS accepted(site TEXT NOT NULL, start_seq INTEGER NOT NULL,
            end_seq INTEGER NOT NULL, raw TEXT NOT NULL, PRIMARY KEY(site,start_seq));
        CREATE INDEX IF NOT EXISTS accepted_span ON accepted(site,end_seq);
        CREATE TABLE IF NOT EXISTS receipts(site TEXT NOT NULL, start_seq INTEGER NOT NULL,
            end_seq INTEGER NOT NULL, raw_hash TEXT NOT NULL, PRIMARY KEY(site,start_seq));
        CREATE INDEX IF NOT EXISTS receipt_span ON receipts(site,end_seq);
        CREATE TABLE IF NOT EXISTS checkpoints(site TEXT PRIMARY KEY, through_seq INTEGER NOT NULL,
            anchor_hash TEXT NOT NULL, state_hash TEXT NOT NULL, signed_raw TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pending(site TEXT NOT NULL, start_seq INTEGER NOT NULL,
            end_seq INTEGER NOT NULL, raw TEXT NOT NULL, PRIMARY KEY(site,start_seq));
        CREATE INDEX IF NOT EXISTS pending_span ON pending(site,end_seq);
        CREATE TABLE IF NOT EXISTS retired(site TEXT NOT NULL, key_id TEXT NOT NULL,
            PRIMARY KEY(site,key_id));
        CREATE TABLE IF NOT EXISTS policy(site TEXT NOT NULL, seq INTEGER NOT NULL,
            pkey TEXT NOT NULL, typ TEXT NOT NULL, authority TEXT NOT NULL,
            principal TEXT, delegator TEXT, delegatee TEXT, asset TEXT NOT NULL,
            action TEXT NOT NULL, from_tick INTEGER NOT NULL, until_tick INTEGER NOT NULL,
            active INTEGER NOT NULL, PRIMARY KEY(site,seq));
        CREATE INDEX IF NOT EXISTS policy_query ON policy(site,asset,action,active);
        CREATE INDEX IF NOT EXISTS policy_key ON policy(site,pkey,active);
        CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY, site TEXT NOT NULL,
            principal TEXT NOT NULL, asset TEXT NOT NULL, action TEXT NOT NULL,
            seqs TEXT NOT NULL, prepare_hash TEXT NOT NULL, committed INTEGER NOT NULL,
            commit_tick INTEGER);
        CREATE TABLE IF NOT EXISTS effects(request_id TEXT PRIMARY KEY, site TEXT NOT NULL,
            principal TEXT NOT NULL, asset TEXT NOT NULL, action TEXT NOT NULL,
            prepare_hash TEXT NOT NULL, commit_tick INTEGER NOT NULL);
        ''')

    def process(self, cmd):
        if type(cmd) is not dict:
            return deny('malformed')
        kind = cmd.get('kind')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            if kind == 'ingest':
                result = self._ingest(cmd)
            elif kind == 'prepare':
                result = self._prepare(cmd)
            elif kind == 'commit':
                result = self._commit(cmd)
            elif kind == 'checkpoint':
                result = self._checkpoint(cmd)
            elif kind == 'checkpoint_status':
                result = self._checkpoint_status(cmd)
            else:
                result = deny('malformed')
            self.db.execute('COMMIT')
            return result
        except (ValueError, TypeError, OverflowError, KeyError):
            self.db.execute('ROLLBACK')
            return reject('malformed') if kind in ('ingest','checkpoint') else deny('malformed')
        except Exception:
            self.db.execute('ROLLBACK')
            raise

    def _validate_events(self, events, site):
        if type(events) is not list or not events:
            return False
        ids = {k['key_id'] for k in self.trust['sites'][site]['keys']}
        for e in events:
            if type(e) is not dict or e.get('type') not in EVENT_FIELDS:
                return False
            if set(e) != EVENT_FIELDS[e['type']]:
                return False
            if e['type'] == 'retire_key':
                if not word(e['key_id']) or e['key_id'] not in ids:
                    return False
                continue
            if (e['authority'] not in ('operations', 'safety') or not word(e['asset']) or
                    not word(e['action'])):
                return False
            names = ('principal',) if e['type'] in ('grant', 'revoke') else ('delegator', 'delegatee')
            if not all(word(e[name]) for name in names):
                return False
            if e['type'] in ('grant', 'delegate') and not (
                integer(e['valid_from_tick']) and integer(e['expires_at_tick']) and
                e['valid_from_tick'] < e['expires_at_tick']):
                return False
        return True

    def _batch(self, b):
        if not exact(b, ('site','start_seq','prev_hash','key_id','events','signature')):
            return 'malformed', None
        site = b['site']
        if not word(site):
            return 'malformed', None
        if site not in self.trust['sites']:
            return 'unknown_site', None
        if not integer(b['start_seq'],1) or not (type(b['prev_hash']) is str and HEX64.fullmatch(b['prev_hash'])):
            return 'malformed', None
        if not word(b['key_id']) or not (type(b['signature']) is str and HEX128.fullmatch(b['signature'])):
            return 'malformed', None
        if not self._validate_events(b['events'], site):
            return 'malformed', None
        end = b['start_seq'] + len(b['events']) - 1
        if end > MAX:
            return 'malformed', None
        keys = {k['key_id']: k for k in self.trust['sites'][site]['keys']}
        key = keys.get(b['key_id'])
        if key is None:
            return 'unknown_key', None
        if b['start_seq'] < key['from_seq'] or end > key['through_seq']:
            return 'key_range', None
        payload = {k: v for k,v in b.items() if k != 'signature'}
        body = canonical_json(payload)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key['public_key_hex'])).verify(
                bytes.fromhex(b['signature']), hashlib.sha256(body).digest())
        except InvalidSignature:
            return 'bad_signature', None
        return None, (site, b['start_seq'], end, content_hash(payload), canonical_json(b).decode('utf-8'))

    def _ingest(self, cmd):
        if not exact(cmd, ('kind','bundle')):
            return reject('malformed')
        err, data = self._batch(cmd['bundle'])
        if err:
            return reject(err)
        site, start, end, bhash, raw = data
        # Identity compares the complete signed batch, not only its interval.
        rows = self.db.execute('SELECT raw FROM accepted WHERE site=? AND start_seq=? UNION ALL '
            'SELECT raw FROM pending WHERE site=? AND start_seq=?', (site,start,site,start)).fetchall()
        receipt = self.db.execute('SELECT raw_hash FROM receipts WHERE site=? AND start_seq=?',
                                  (site,start)).fetchone()
        if (any(row['raw'] == raw for row in rows) or
                (receipt is not None and receipt['raw_hash'] == hashlib.sha256(raw.encode('utf-8')).hexdigest())):
            return reply('duplicate')
        if self.db.execute('SELECT 1 FROM accepted WHERE site=? AND start_seq<=? AND end_seq>=? '
                'UNION ALL SELECT 1 FROM pending WHERE site=? AND start_seq<=? AND end_seq>=? '
                'UNION ALL SELECT 1 FROM receipts WHERE site=? AND start_seq<=? AND end_seq>=? LIMIT 1',
                (site,end,start,site,end,start,site,end,start)).fetchone():
            return reject('overlap')
        current = self.db.execute('SELECT next_seq,last_hash FROM site WHERE site=?',(site,)).fetchone()
        if start < current['next_seq']:
            return reject('overlap')
        if start > current['next_seq']:
            count = self.db.execute('SELECT COUNT(*) FROM pending WHERE site=?',(site,)).fetchone()[0]
            if count >= 64:
                return reject('pending_limit')
            self.db.execute('INSERT INTO pending VALUES (?,?,?,?)',(site,start,end,raw))
            return reply('buffered')
        if bhash is None or cmd['bundle']['prev_hash'] != current['last_hash']:
            return reject('fork')
        if self._retired(site,cmd['bundle']['key_id']):
            return reject('retired_key')
        self._apply(cmd['bundle'], raw, bhash)
        self._drain(site)
        return reply('applied')

    def _retired(self, site, key_id):
        return self.db.execute('SELECT 1 FROM retired WHERE site=? AND key_id=?',
                               (site,key_id)).fetchone() is not None

    def _apply(self, b, raw, bhash):
        site = b['site']
        start = b['start_seq']
        end = start + len(b['events']) - 1
        for i, event in enumerate(b['events']):
            seq = start + i
            typ = event['type']
            if typ == 'retire_key':
                self.db.execute('INSERT OR IGNORE INTO retired VALUES (?,?)', (site,event['key_id']))
                continue
            auth, asset, action = event['authority'], event['asset'], event['action']
            if typ in ('grant','revoke'):
                pkey = json.dumps([auth,'grant', event['principal'],asset,action], separators=(',',':'))
            else:
                pkey = json.dumps([auth,'delegate',event['delegator'],event['delegatee'],asset,action],separators=(',',':'))
            self.db.execute('UPDATE policy SET active=0 WHERE site=? AND pkey=? AND active=1',(site,pkey))
            if typ in ('grant','delegate'):
                self.db.execute('INSERT INTO policy VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (site,seq,pkey,typ,auth,event.get('principal'),event.get('delegator'),
                     event.get('delegatee'),asset,action,event['valid_from_tick'],
                     event['expires_at_tick'],1))
        self.db.execute('INSERT INTO accepted VALUES (?,?,?,?)', (site,start,end,raw))
        self.db.execute('UPDATE site SET next_seq=?,last_hash=? WHERE site=?',(end+1,bhash,site))

    def _drain(self, site):
        while True:
            pos = self.db.execute('SELECT next_seq,last_hash FROM site WHERE site=?',(site,)).fetchone()
            next_batch = self.db.execute('SELECT raw FROM pending WHERE site=? AND start_seq=?',
                                         (site,pos['next_seq'])).fetchone()
            if next_batch is None:
                return
            b = json.loads(next_batch['raw'])
            self.db.execute('DELETE FROM pending WHERE site=? AND start_seq=?',(site,pos['next_seq']))
            # Trust may have changed since this signature was initially accepted.
            if b['prev_hash'] != pos['last_hash'] or self._retired(site,b['key_id']):
                continue
            self._apply(b,next_batch['raw'],content_hash({k:v for k,v in b.items() if k != 'signature'}))

    def _gap(self, site):
        return self.db.execute('SELECT 1 FROM pending WHERE site=? LIMIT 1',(site,)).fetchone() is not None

    def _clock(self, site, tick):
        old = self.db.execute('SELECT max_tick FROM site WHERE site=?',(site,)).fetchone()['max_tick']
        if tick < old:
            return False
        if tick > old:
            self.db.execute('UPDATE site SET max_tick=? WHERE site=?',(tick,site))
        return True

    def _active(self, site, asset, action, tick, fence=None):
        rows = self.db.execute('SELECT * FROM policy WHERE site=? AND asset=? AND action=? '
              'AND active=1 AND from_tick<=? AND until_tick>?', (site,asset,action,tick,tick)).fetchall()
        if fence is not None:
            rows = [row for row in rows if row['seq'] in fence]
        return rows

    def _roots_that_reach(self, rows, authority, principal):
        parents = defaultdict(set)
        roots = set()
        for row in rows:
            if row['authority'] != authority:
                continue
            if row['typ'] == 'grant':
                roots.add(row['principal'])
            else:
                parents[row['delegatee']].add(row['delegator'])
        seen = {principal}
        q = deque([principal])
        found = set()
        while q:
            current = q.popleft()
            if current in roots:
                found.add(current)
            for parent in parents[current]:
                if parent not in seen:
                    seen.add(parent)
                    q.append(parent)
        return found

    def _authorized(self, site, principal, asset, action, tick, rows):
        op = self._roots_that_reach(rows,'operations',principal)
        if not op:
            return False
        critical = any(pair['asset'] == asset and pair['action'] == action
                       for pair in self.trust['sites'][site]['critical'])
        if not critical:
            return True
        safety = self._roots_that_reach(rows,'safety',principal)
        return bool(safety and (len(op | safety) >= 2))

    def _prepare(self, cmd):
        if not exact(cmd, ('kind','request_id','site','principal','asset','action','tick')):
            return deny('malformed')
        if not all(word(cmd[k]) for k in ('request_id','site','principal','asset','action')) or not integer(cmd['tick']):
            return deny('malformed')
        site = cmd['site']
        if site not in self.trust['sites']:
            return deny('unknown_site')
        if not self._clock(site,cmd['tick']):
            return deny('stale_tick')
        existing = self.db.execute('SELECT * FROM requests WHERE request_id=?',(cmd['request_id'],)).fetchone()
        if existing is not None:
            if any(existing[k] != cmd[k] for k in ('site','principal','asset','action')):
                return deny('request_conflict')
            if existing['committed']:
                return deny('already_executed')
            if self._gap(site):
                return deny('gap')
            rows = self._active(site,cmd['asset'],cmd['action'],cmd['tick'],set(json.loads(existing['seqs'])))
            return reply('prepared') if self._authorized(site,cmd['principal'],cmd['asset'],cmd['action'],cmd['tick'],rows) else deny('invalidated')
        if self._gap(site):
            return deny('gap')
        rows = self._active(site,cmd['asset'],cmd['action'],cmd['tick'])
        if not self._authorized(site,cmd['principal'],cmd['asset'],cmd['action'],cmd['tick'],rows):
            return deny('unauthorized')
        seqs = sorted(row['seq'] for row in rows)
        prepare_hash = content_hash({'seqs':seqs})
        self.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?)',
            (cmd['request_id'],site,cmd['principal'],cmd['asset'],cmd['action'],
             json.dumps(seqs,separators=(',',':')),prepare_hash,0,None))
        return reply('prepared')

    def _commit(self, cmd):
        if not exact(cmd, ('kind','request_id','tick')) or not word(cmd['request_id']) or not integer(cmd['tick']):
            return deny('malformed')
        request = self.db.execute('SELECT * FROM requests WHERE request_id=?',(cmd['request_id'],)).fetchone()
        if request is None:
            return deny('unknown_request')
        site = request['site']
        if not self._clock(site,cmd['tick']):
            return deny('stale_tick')
        if request['committed']:
            return reply('already_executed')
        if self._gap(site):
            return deny('gap')
        rows = self._active(site,request['asset'],request['action'],cmd['tick'],
                            set(json.loads(request['seqs'])))
        if not self._authorized(site,request['principal'],request['asset'],request['action'],cmd['tick'],rows):
            return deny('authority_changed')
        self.db.execute('INSERT INTO effects VALUES (?,?,?,?,?,?,?)',
            (cmd['request_id'],site,request['principal'],request['asset'],request['action'],
             request['prepare_hash'],cmd['tick']))
        self.db.execute('UPDATE requests SET committed=1,commit_tick=? WHERE request_id=?',
                         (cmd['tick'],cmd['request_id']))
        return reply('executed')

    def _checkpoint_state(self, site):
        """Canonical projection of local state signed by an independent checkpoint key.

        It includes effects and prepared evidence, not just active permissions.
        This makes a checkpoint attest to the authorization and execution state.
        """
        head = self.db.execute('SELECT next_seq,last_hash,max_tick FROM site WHERE site=?',
                               (site,)).fetchone()
        policy = self.db.execute('SELECT seq,typ,authority,principal,delegator,delegatee,asset,action,'
                                 'from_tick,until_tick FROM policy WHERE site=? AND active=1 ORDER BY seq',
                                 (site,)).fetchall()
        requests = self.db.execute('SELECT request_id,principal,asset,action,seqs,prepare_hash '
                                   'FROM requests WHERE site=? AND committed=0 ORDER BY request_id',
                                   (site,)).fetchall()
        effects = self.db.execute('SELECT request_id,principal,asset,action,prepare_hash,commit_tick '
                                  'FROM effects WHERE site=? ORDER BY request_id', (site,)).fetchall()
        retired = [row[0] for row in self.db.execute('SELECT key_id FROM retired WHERE site=? ORDER BY key_id',
                                                     (site,))]
        accepted = [(row['start_seq'],row['end_seq'],hashlib.sha256(row['raw'].encode('utf-8')).hexdigest())
                    for row in self.db.execute('SELECT start_seq,end_seq,raw FROM accepted WHERE site=?', (site,))]
        compacted = [(row['start_seq'],row['end_seq'],row['raw_hash']) for row in
                     self.db.execute('SELECT start_seq,end_seq,raw_hash FROM receipts WHERE site=?', (site,))]
        identities = sorted(accepted+compacted)
        projection = {'site':site,'through_seq':head['next_seq']-1,'anchor_hash':head['last_hash'],
                      'max_tick':head['max_tick'], 'active_policy':[list(row) for row in policy],
                      'open_requests':[[row['request_id'],row['principal'],row['asset'],row['action'],
                                        json.loads(row['seqs']),row['prepare_hash']] for row in requests],
                      'effects':[list(row) for row in effects], 'retired':retired,
                      'accepted_ids':[list(row) for row in identities]}
        return content_hash(projection)

    def _checkpoint(self, cmd):
        if not exact(cmd, ('kind','checkpoint')):
            return reject('malformed')
        cp = cmd['checkpoint']
        if not exact(cp, ('site','through_seq','anchor_hash','state_hash','key_id','signature')):
            return reject('malformed')
        site = cp['site']
        if not word(site):
            return reject('malformed')
        if site not in self.trust['sites']:
            return reject('unknown_site')
        if (not integer(cp['through_seq'],1) or
                type(cp['anchor_hash']) is not str or not HEX64.fullmatch(cp['anchor_hash']) or
                type(cp['state_hash']) is not str or not HEX64.fullmatch(cp['state_hash']) or
                not word(cp['key_id']) or type(cp['signature']) is not str or
                not HEX128.fullmatch(cp['signature'])):
            return reject('malformed')
        # The checkpoint root is deliberately distinct from all policy-signing keys.
        keys = {k['key_id']:k for k in self.trust['sites'][site].get('checkpoint_keys', [])}
        key = keys.get(cp['key_id'])
        if key is None:
            return reject('unknown_key')
        if not key['from_seq'] <= cp['through_seq'] <= key['through_seq']:
            return reject('key_range')
        payload = {k:v for k,v in cp.items() if k != 'signature'}
        signed = {'domain':'permitgate-checkpoint-v1',**payload}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key['public_key_hex'])).verify(
                bytes.fromhex(cp['signature']), hashlib.sha256(canonical_json(signed)).digest())
        except InvalidSignature:
            return reject('bad_signature')
        current = self.db.execute('SELECT next_seq,last_hash FROM site WHERE site=?',(site,)).fetchone()
        previous = self.db.execute('SELECT through_seq,anchor_hash,state_hash,signed_raw FROM checkpoints WHERE site=?',
                                   (site,)).fetchone()
        if cp['through_seq'] != current['next_seq']-1 or cp['anchor_hash'] != current['last_hash']:
            return reject('stale_checkpoint')
        if self._gap(site):
            return reject('gap')
        if (previous is not None and previous['through_seq']==cp['through_seq'] and
                previous['signed_raw']==canonical_json(cp).decode('utf-8')):
            return reply('duplicate')
        if cp['state_hash'] != self._checkpoint_state(site):
            return reject('state_mismatch')
        # The accepted-batch identity is retained even when the full payload is discarded.
        for row in self.db.execute('SELECT start_seq,end_seq,raw FROM accepted WHERE site=?',(site,)):
            self.db.execute('INSERT INTO receipts VALUES (?,?,?,?)',
                            (site,row['start_seq'],row['end_seq'],
                             hashlib.sha256(row['raw'].encode('utf-8')).hexdigest()))
        self.db.execute('DELETE FROM accepted WHERE site=?',(site,))
        retained=set()
        for row in self.db.execute('SELECT seqs FROM requests WHERE site=? AND committed=0',(site,)):
            retained.update(json.loads(row['seqs']))
        # Inactive evidence is never promoted again; in-flight event IDs are retained for diagnosis.
        for row in self.db.execute('SELECT seq FROM policy WHERE site=? AND active=0',(site,)):
            if row['seq'] not in retained:
                self.db.execute('DELETE FROM policy WHERE site=? AND seq=?',(site,row['seq']))
        self.db.execute('INSERT INTO checkpoints VALUES (?,?,?,?,?) ON CONFLICT(site) DO UPDATE SET '
                        'through_seq=excluded.through_seq,anchor_hash=excluded.anchor_hash,'
                        'state_hash=excluded.state_hash,signed_raw=excluded.signed_raw',
                        (site,cp['through_seq'],cp['anchor_hash'],cp['state_hash'],
                         canonical_json(cp).decode('utf-8')))
        return reply('checkpointed')

    def _checkpoint_status(self, cmd):
        if not exact(cmd, ('kind','site')) or not word(cmd['site']):
            return deny('malformed')
        site=cmd['site']
        if site not in self.trust['sites']:
            return deny('unknown_site')
        row=self.db.execute('SELECT through_seq FROM checkpoints WHERE site=?',(site,)).fetchone()
        through=row['through_seq'] if row else 0
        count=self.db.execute('SELECT COUNT(*) FROM receipts WHERE site=?',(site,)).fetchone()[0]
        raw=self.db.execute('SELECT COUNT(*) FROM accepted WHERE site=?',(site,)).fetchone()[0]
        return {'status':'ok','through_seq':through,'retained_from_seq':through+1,
                'accepted_batch_identities':count+raw,'raw_batches':raw,'gap':self._gap(site)}

    def effects(self):
        return [dict(row) for row in self.db.execute('SELECT request_id,site,principal,asset,action,'
           'prepare_hash,commit_tick FROM effects ORDER BY request_id')]
