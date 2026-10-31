"""Ensure the trusted scenario generator constructs genuine valid signatures and proofs."""
import tempfile
from scenarios import Driver, tree_and_proofs, EMPTY, CANON, sign, priv, pub, hash_record
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64, hashlib, json

DOMAIN=b'GATEKEEPER/V2\x00'


def verify(rec, key, kind, sig_field='signature', removed=None):
    keys=set(removed or [sig_field])
    body={k:v for k,v in rec.items() if k not in keys}
    data=DOMAIN+kind.encode()+b'\x00'+CANON(body)
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub(key))).verify(base64.b64decode(rec[sig_field]),data)


def run():
    with tempfile.TemporaryDirectory() as tmp:
        d=Driver(tmp)
        g=d.grant(); verify(g,d.key,'grant')
        cp,bundles=d.checkpoint(tick=100,grants=[g],apply=False)
        verify(cp,d.key,'checkpoint')
        assert cp['issuance_count']==1
        assert cp['issuance_root']==hashlib.sha256(b'\x00'+CANON(g)).hexdigest()
        assert bundles[0]['proof']['siblings']==[]
        r=d.request(); verify(r,d.holder_key,'request')
        rotate=d.rotate(apply=False)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(d.trust['genesis_root_public_key'])).verify(
            base64.b64decode(rotate['old_signature']),
            DOMAIN+b'rotate\x00'+CANON({k:v for k,v in rotate.items() if k not in ('old_signature','new_signature')})
        )
        verify(rotate,d.key,'rotate',sig_field='new_signature',removed=('old_signature','new_signature'))
        assert hash_record(rotate)==d.tip
    for size in (0,1,2,3,5,8,9,17):
        records=[{'grant_id':f'g{i}','signature':f'sig{i}'} for i in range(size)]
        root,paths=tree_and_proofs(records)
        if not size: assert root==EMPTY.hex()
        for idx,obj in enumerate(records):
            node=hashlib.sha256(b'\x00'+CANON(obj)).digest()
            for j,sib in enumerate(paths[idx]):
                ss=bytes.fromhex(sib)
                node=hashlib.sha256(b'\x01'+(node+ss if ((idx>>j)&1)==0 else ss+node)).digest()
            assert node.hex()==root,(size,idx)
    print('PASS: verifier data generator cryptographic signatures, rotation dual-signatures and Merkle inclusion for counts 0..17')

if __name__=='__main__':run()
