"""Local protocol-vectors construction tests, NOT gateway correctness tests."""
import json
import tempfile
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import hashlib
from permitgate.canonical import canonical_json
from examples.make_sample import generate
from examples.vectorlib import trust_config

class SignedVectors(unittest.TestCase):
    def test_generated_signed_bundles_and_expected_scenarios(self):
        with tempfile.TemporaryDirectory() as td:
            commands, expected = generate(td)
            trust = trust_config()
            self.assertEqual(len(commands), 19)
            self.assertEqual(len(commands), len(expected))
            for command in commands:
                if command['kind'] != 'ingest':
                    continue
                b = command['bundle']
                pubkeys = {k['key_id']:k['public_key_hex']
                           for k in trust['sites'][b['site']]['keys']}
                pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkeys[b['key_id']]))
                payload = {k:v for k,v in b.items() if k != 'signature'}
                pub.verify(bytes.fromhex(b['signature']),
                           hashlib.sha256(canonical_json(payload)).digest())
            stored = json.loads((Path(td)/'expected_status_codes.json').read_text())
            self.assertEqual(stored, [list(x) for x in expected])

    def test_signature_breaks_when_payload_changes(self):
        with tempfile.TemporaryDirectory() as td:
            commands, _ = generate(td)
            b = commands[0]['bundle']
            original = {k:v for k,v in b.items() if k != 'signature'}
            modified = json.loads(json.dumps(original))
            modified['events'][0]['principal'] = 'attacker'
            pub_hex = trust_config()['sites']['north']['keys'][0]['public_key_hex']
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            with self.assertRaises(InvalidSignature):
                pub.verify(bytes.fromhex(b['signature']),
                           hashlib.sha256(canonical_json(modified)).digest())

if __name__ == '__main__':
    unittest.main()
