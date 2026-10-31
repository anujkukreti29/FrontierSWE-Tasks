"""Run a PUBLIC end-to-end contract example against a candidate (starter should fail)."""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from examples.make_sample import generate as generate_basic
from examples.make_delegation_sample import generate as generate_delegation

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', help='Optional location for temporary test SQLite DB')
    parser.add_argument('--scenario', choices=['basic', 'delegation'], default='basic')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as td:
        folder = Path(td)
        commands, expected = (generate_delegation if args.scenario == 'delegation' else generate_basic)(td)
        state = args.state or str(folder/'db.sqlite')
        out = folder/'answers.jsonl'
        cmd = [sys.executable, '-m', 'permitgate.cli', 'run', '--trust',str(folder/'trust.json'),
               '--state',state, '--input',str(folder/'commands.jsonl'), '--output',str(out)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            return result.returncode
        actual = [(v.get('status'),v.get('code')) for v in
                  (json.loads(row) for row in out.read_text().splitlines())]
        mismatches = [(i+1, expected[i], actual[i] if i<len(actual) else None)
                      for i in range(len(expected))
                      if i>=len(actual) or expected[i] != actual[i]]
        for num, want, got in mismatches[:8]:
            print(f'command {num}: expected {want}, got {got}')
        print(f'Public example: {len(expected)-len(mismatches)}/{len(expected)} matched')
        return 1 if mismatches or len(actual)!=len(expected) else 0

if __name__ == '__main__':
    raise SystemExit(main())
