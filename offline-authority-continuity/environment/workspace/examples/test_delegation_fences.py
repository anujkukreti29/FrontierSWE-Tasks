"""Checks authenticity of new public vectors, not implementation correctness."""
import hashlib
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from examples.make_delegation_sample import generate
from examples.vectorlib import trust_config
from permitgate.canonical import canonical_json

class DelegationFenceVectors(unittest.TestCase):
    def test_signed_alternative_proofs(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands, expected = generate(tmp)
            self.assertEqual(len(commands), 15)
            self.assertEqual(len(expected), 15)
            trust = trust_config()['sites']['north']['keys']
            keys = {entry['key_id']:entry['public_key_hex'] for entry in trust}
            ingested = [cmd['bundle'] for cmd in commands if cmd['kind']=='ingest']
            self.assertEqual(len(ingested), 5)
            for b in ingested:
                payload = {k:v for k,v in b.items() if k != 'signature'}
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[b['key_id']])).verify(
                    bytes.fromhex(b['signature']),
                    hashlib.sha256(canonical_json(payload)).digest())
            self.assertEqual([b['start_seq'] for b in ingested], [1,7,8,9,11])
            self.assertEqual([len(b['events']) for b in ingested],[6,1,1,2,2])

if __name__=='__main__':
    unittest.main()
