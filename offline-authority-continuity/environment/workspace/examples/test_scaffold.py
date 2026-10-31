"""Public parser and transport smoke tests (NOT authorization acceptance tests)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from permitgate.canonical import (DuplicateJSONKey, parse_line, canonical_json,
                                  content_hash)

class ScaffoldTest(unittest.TestCase):
    def test_strict_duplicate_json(self):
        with self.assertRaises(DuplicateJSONKey):
            parse_line('{"x":1,"x":2}')
        with self.assertRaises(DuplicateJSONKey):
            parse_line('{"a":{"x":1,"x":2}}')

    def test_strict_non_json_constants_and_unicode(self):
        for raw in ('{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e999}',
                    '{"x":"\\uD800"}', '{"\\uDFFF":1}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_line(raw)

    def test_canonical_order_and_hash(self):
        self.assertEqual(canonical_json({'z': 1, 'a': 2}), b'{"a":2,"z":1}')
        self.assertEqual(len(content_hash({'a': 1})), 64)

    def test_cli_invalid_input_lines_do_not_abort(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            (folder/'trust.json').write_text('{"sites":{}}')
            (folder/'commands.jsonl').write_bytes(
                b'{"x":1,"x":2}\n' + b'\xff\xfe\n' +
                b'{"kind":"commit","request_id":"missing","tick":1}\n')
            proc = subprocess.run(
                [sys.executable, '-m', 'permitgate.cli', 'run',
                 '--trust', str(folder/'trust.json'),
                 '--state', str(folder/'state.sqlite'),
                 '--input', str(folder/'commands.jsonl'),
                 '--output', str(folder/'answers.jsonl')],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            replies = [json.loads(line) for line in (folder/'answers.jsonl').read_text().splitlines()]
            self.assertEqual(len(replies), 3)
            self.assertEqual(replies[0], {'status':'denied', 'code':'malformed'})
            self.assertEqual(replies[1], {'status':'denied', 'code':'malformed'})
            self.assertEqual(replies[2], {'status':'denied', 'code':'unknown_request'})

if __name__ == '__main__':
    unittest.main()
