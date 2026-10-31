"""Untrusted PUBLIC design-conformance demonstration, NOT a gateway reference or verifier.

This validates the task-local padded Merkle batch formula for varied batch sizes.
No gateway, signature, authority, concurrency, or recovery behavior is tested.
"""
import hashlib
import json


def C(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def H(b):
    return hashlib.sha256(b).digest()


PAD = H(b'GATEKEEPER/V2-PAD')
EMPTY = H(b'GATEKEEPER/V2-EMPTY')


def level_tree(records):
    if not records:
        return [[EMPTY]]
    leaves = [H(b'\x00' + C(x)) for x in records]
    power = 1 << (len(leaves) - 1).bit_length()
    leaves.extend([PAD] * (power-len(leaves)))
    levels = [leaves]
    while len(levels[-1]) > 1:
        x = levels[-1]
        levels.append([H(b'\x01'+x[i]+x[i+1]) for i in range(0, len(x), 2)])
    return levels


def inclusion_proof(levels, i):
    p = []
    for row in levels[:-1]:
        p.append(row[i ^ 1])
        i //= 2
    return p


def verify(record, index, count, proof, expected_root):
    if count <= 0 or index < 0 or index >= count:
        return False
    expected_len = (count - 1).bit_length()
    if len(proof) != expected_len:
        return False
    cur = H(b'\x00'+C(record))
    for j, sib in enumerate(proof):
        if len(sib) != 32:
            return False
        cur = H(b'\x01' + (cur + sib if ((index >> j) & 1) == 0 else sib + cur))
    return cur == expected_root


def main():
    checked = 0
    assert level_tree([])[-1][0] == EMPTY
    for size in [1,2,3,4,5,7,8,9,16,17,31,32,33]:
        # Stand-in canonical signed-record structures; the script does not sign them.
        records = [{'kind':'grant', 'grant_id':f'g_{i:03d}', 'signature':f'synthetic-{i}'}
                   for i in range(size)]
        tree = level_tree(records)
        root = tree[-1][0]
        for i in range(size):
            proof = inclusion_proof(tree, i)
            assert verify(records[i], i, size, proof, root)
            assert not verify(dict(records[i], grant_id='changed'), i, size, proof, root)
            assert not verify(records[i], size, size, proof, root)
            if proof:
                bad = proof.copy()
                bad[-1] = H(b'not-an-authentic-sibling')
                assert not verify(records[i], i, size, bad, root)
            checked += 1
    print(f'PASS: {checked} positive inclusion checks, record-mutation and index negative checks, and sibling-mutation checks for nontrivial trees.')
    print('LIMITATION: no Ed25519, authority reconciliation, transaction recovery or agent oracle tested.')


if __name__ == '__main__':
    main()
