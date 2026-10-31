#!/usr/bin/env python3
"""Agent-visible sanity checks; not the hidden evaluator."""
import hashlib, sys
from gatekeeper.primitives import canonical, strict_load, merkle_root, proof_valid, digest

assert canonical({'b':1,'a':2})==b'{"a":2,"b":1}'
assert strict_load(b'{"ok":true}') == {'ok': True}
for bad in [b'{"x":1,"x":2}',b'{"n":NaN}',b'{"a":1}garbage']:
    try: strict_load(bad)
    except (ValueError, TypeError):pass
    else:raise AssertionError('accepted malformed JSON')
for n in (1,2,3,5,8):
    records=[{'grant_id':str(i)} for i in range(n)]
    root=merkle_root(records)
    level=[hashlib.sha256(b'\x00'+canonical(x)).digest() for x in records]
    pad=hashlib.sha256(b'GATEKEEPER/V2-PAD').digest()
    level += [pad]*((1<<(len(level)-1).bit_length())-len(level))
    rows=[level]
    while len(level)>1:
        level=[hashlib.sha256(b'\x01'+level[j]+level[j+1]).digest() for j in range(0,len(level),2)]
        rows.append(level)
    for i in range(n):
        p=[]; k=i
        for row in rows[:-1]:p.append(row[k^1].hex());k//=2
        assert proof_valid(records[i],i,n,p,root)
        assert not proof_valid({'grant_id':'modified'},i,n,p,root)
print('PASS: public canonicalization, strict JSON and padded-Merkle helper checks')
print('NOTE: authorization, recovery, replay and authority reconciliation are not implemented')
