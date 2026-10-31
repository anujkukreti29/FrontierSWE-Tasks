"""PUBLIC synthetic signed-vector helpers. Not a gateway implementation or oracle."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from permitgate.canonical import canonical_json, content_hash

SEEDS = {
    'north-a': bytes([17]) * 32,
    'north-b': bytes([19]) * 32,
    'south-a': bytes([23]) * 32,
}

def keypair(key_id):
    signer = Ed25519PrivateKey.from_private_bytes(SEEDS[key_id])
    pub = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return signer, pub

def trust_config():
    return {'sites': {
        'north': {
            'keys': [{'key_id': kid, 'public_key_hex': keypair(kid)[1],
                      'from_seq': 1, 'through_seq': 1000}
                     for kid in ('north-a', 'north-b')],
            'critical': [{'asset':'pump7', 'action':'start'}]
        },
        'south': {
            'keys': [{'key_id':'south-a', 'public_key_hex':keypair('south-a')[1],
                      'from_seq':1, 'through_seq':1000}],
            'critical': []
        }
    }}

def bundle(site, start_seq, prev_hash, key_id, events):
    payload = {'site':site, 'start_seq':start_seq, 'prev_hash':prev_hash,
               'key_id':key_id, 'events':events}
    signer, _ = keypair(key_id)
    return {**payload, 'signature': signer.sign(hashlib.sha256(
        canonical_json(payload)).digest()).hex()}

def bhash(signed_bundle):
    return content_hash({key: value for key, value in signed_bundle.items()
                         if key != 'signature'})


def grant(auth, principal, asset='pump7', action='start'):
    return {'type':'grant', 'authority':auth, 'principal':principal,
            'asset':asset, 'action':action, 'valid_from_tick':10,
            'expires_at_tick':100}

def delegate(auth, parent, child):
    return {'type':'delegate', 'authority':auth, 'delegator':parent,
            'delegatee':child, 'asset':'pump7', 'action':'start',
            'valid_from_tick':10, 'expires_at_tick':100}
