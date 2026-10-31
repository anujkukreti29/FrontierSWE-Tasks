"""Durable state, schema, and transaction helpers for the reference engine.

The reference reuses the starter database layout, with authorization and
authority transitions handled by its engine module.
"""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from .primitives import canonical


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS authority (
    seq INTEGER PRIMARY KEY,
    digest TEXT NOT NULL UNIQUE,
    record_json BLOB NOT NULL,
    previous_digest TEXT NOT NULL,
    issued_tick INTEGER NOT NULL,
    kind TEXT NOT NULL,
    trusted_root_id TEXT NOT NULL,
    root_pubkey TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_authority (
    digest TEXT PRIMARY KEY,
    record_json BLOB NOT NULL,
    previous_digest TEXT NOT NULL,
    seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_by_parent ON pending_authority(previous_digest);
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    record_json BLOB NOT NULL,
    parent_id TEXT,
    authenticated INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS grants_by_parent ON grants(parent_id);
CREATE TABLE IF NOT EXISTS pending_grants (
    digest TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    record_json BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS grant_conflicts (grant_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(grant_id,digest));
CREATE TABLE IF NOT EXISTS revoked (
    grant_id TEXT PRIMARY KEY,
    revoked_at_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    request_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    effect_index INTEGER NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS effects (
    effect_index INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    tick INTEGER NOT NULL,
    authority_seq INTEGER NOT NULL,
    checkpoint_seq INTEGER NOT NULL,
    grant_path_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_forks (
    parent_digest TEXT NOT NULL,
    child_digest TEXT PRIMARY KEY,
    record_json BLOB NOT NULL
);
"""


class StateError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code=code


def connection(state, create=False):
    state = Path(state)
    protected = state / 'protected'
    dbfile = protected / 'authority.sqlite3'
    if create: protected.mkdir(parents=True,exist_ok=True)
    if not dbfile.exists() and not create: raise StateError('STATE_MISSING')
    try:
        db = sqlite3.connect(str(dbfile),timeout=20,isolation_level=None)
        db.execute('PRAGMA busy_timeout=20000')
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        return db
    except sqlite3.DatabaseError as e:
        raise StateError('STATE_CORRUPT') from e
    except OSError as e:
        raise StateError('IO_ERROR') from e


@contextmanager
def transaction(db, write=False):
    """One linearization boundary across all authority/decision transactions."""
    db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
    try:
        yield
        db.execute('COMMIT')
    except BaseException:
        try:db.execute('ROLLBACK')
        except Exception:pass
        raise


def get(db,k,default=None):
    row=db.execute('SELECT value FROM settings WHERE key=?',(k,)).fetchone()
    return default if row is None else row[0]


def put(db,k,v):
    db.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,str(v)))


def init_state(state,trust):
    import json
    if type(trust)!=dict or set(trust)!={'schema','tenant','offline_window_ticks','genesis_root_key_id','genesis_root_public_key'}:
        raise StateError('INVALID_INPUT')
    import base64
    import re
    if (type(trust['schema']) is not int or trust['schema'] != 2 or
        type(trust['offline_window_ticks']) is not int or
        not 1 <= trust['offline_window_ticks'] <= (2**63-1)):
        raise StateError('INVALID_INPUT')
    identifier = re.compile(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}\Z', re.ASCII)
    if not all(type(trust[k]) is str and identifier.fullmatch(trust[k])
               for k in ('tenant', 'genesis_root_key_id')):
        raise StateError('INVALID_INPUT')
    public_key = trust['genesis_root_public_key']
    if type(public_key) is not str:
        raise StateError('INVALID_INPUT')
    try:
        raw = base64.b64decode(public_key, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode('ascii') != public_key:
            raise StateError('INVALID_INPUT')
    except (ValueError, TypeError) as exc:
        raise StateError('INVALID_INPUT') from exc
    db=connection(state,create=True)
    try:
        # sqlite3.executescript() commits any open transaction implicitly.
        # Install idempotent table declarations before starting the atomic trust write.
        db.executescript(SCHEMA)
        with transaction(db,write=True):
            existing=get(db,'trust')
            payload=canonical(trust).decode('ascii')
            if existing is not None:
                if existing!=payload: raise StateError('INIT_CONFLICT')
                return {'state':'UNCHANGED','tenant':trust['tenant']}
            put(db,'trust',payload)
            put(db,'tenant',trust['tenant'])
            put(db,'seq',0)
            put(db,'last_digest','0'*64)
            put(db,'last_issued_tick',0)
            put(db,'last_checkpoint_tick','null')
            put(db,'highest_protected_tick',0)
            put(db,'quarantined',0)
            put(db,'root_id',trust['genesis_root_key_id'])
            put(db,'root_pubkey',trust['genesis_root_public_key'])
        return {'state':'INITIALIZED','tenant':trust['tenant']}
    except sqlite3.DatabaseError as e:
        raise StateError('STATE_CORRUPT') from e
    finally:db.close()


def status_state(state):
    db=connection(state)
    try:
        with transaction(db):
            t=get(db,'tenant')
            if t is None:raise StateError('STATE_CORRUPT')
            def count(table):return db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
            checkpoint=get(db,'last_checkpoint_tick','null')
            return {
                'tenant':t,'seq':int(get(db,'seq',0)),
                'last_digest':get(db,'last_digest','0'*64),
                'last_issued_tick':int(get(db,'last_issued_tick',0)),
                'last_checkpoint_tick':None if checkpoint=='null' else int(checkpoint),
                'highest_protected_tick':int(get(db,'highest_protected_tick',0)),
                'quarantined':get(db,'quarantined','0')=='1',
                'pending_authority_count':count('pending_authority'),
                'pending_grant_count':count('pending_grants'),
                'authenticated_grant_count':count('grants'),
                'applied_request_count':count('effects')}
    except sqlite3.DatabaseError as e:raise StateError('STATE_CORRUPT') from e
    finally:db.close()
