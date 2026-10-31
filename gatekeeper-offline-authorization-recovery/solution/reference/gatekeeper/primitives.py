"""Reusable, public cryptographic primitives. Not an authorization engine.

All inputs still require protocol-specific strict schema validation before
signature verification. Helpers deliberately do not assume a credential is
legitimate merely because its Ed25519 signature verifies.
"""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN=b"GATEKEEPER/V2\x00"
PAD=hashlib.sha256(b"GATEKEEPER/V2-PAD").digest()
EMPTY=hashlib.sha256(b"GATEKEEPER/V2-EMPTY").digest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def strict_load(data: bytes):
    if len(data)>262144: raise ValueError("oversized JSON")
    def pairs(items):
        result={}
        for key,val in items:
            if key in result: raise ValueError("duplicate JSON key")
            result[key]=val
        return result
    def reject_constant(x): raise ValueError("nonfinite JSON number")
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=reject_constant)


def digest(record): return hashlib.sha256(canonical(record)).hexdigest()


def verify_signed(record, kind, pubkey_b64, *, signature_field="signature", excluded=None):
    excluded=set(excluded or [signature_field])
    body={k:v for k,v in record.items() if k not in excluded}
    try:
        pub=base64.b64decode(pubkey_b64, validate=True)
        sig=base64.b64decode(record[signature_field], validate=True)
        if len(pub)!=32 or len(sig)!=64: return False
        if base64.b64encode(pub).decode()!=pubkey_b64 or base64.b64encode(sig).decode()!=record[signature_field]:return False
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, DOMAIN+kind.encode('ascii')+b'\x00'+canonical(body))
        return True
    except (ValueError, KeyError, TypeError, UnicodeError): return False
    except Exception: return False


def merkle_root(records):
    if not records:return EMPTY.hex()
    level=[hashlib.sha256(b'\x00'+canonical(record)).digest() for record in records]
    level += [PAD]*((1<<(len(level)-1).bit_length())-len(level))
    while len(level)>1:
        level=[hashlib.sha256(b'\x01'+level[i]+level[i+1]).digest() for i in range(0,len(level),2)]
    return level[0].hex()


def proof_valid(record, index, count, siblings, expected_root):
    if type(index)!=int or type(count)!=int or not (0<=index<count):return False
    if len(siblings)!=(count-1).bit_length():return False
    h=hashlib.sha256(b'\x00'+canonical(record)).digest()
    try:
        for bit,sib in enumerate(siblings):
            sh=bytes.fromhex(sib)
            if len(sh)!=32:return False
            h=hashlib.sha256(b'\x01'+(h+sh if ((index>>bit)&1)==0 else sh+h)).digest()
        return h.hex()==expected_root
    except (TypeError,ValueError):return False
