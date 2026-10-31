"""Run this after implementing the recover command; it is NOT the hidden verifier."""
import pathlib
import subprocess
import sys
import tempfile

case = pathlib.Path('/app/fixtures/public_case')
with tempfile.TemporaryDirectory() as folder:
    proc = subprocess.run([sys.executable, '-m', 'cartographer', 'recover',
                           '--input', str(case), '--output', folder],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode:
        print(proc.stderr)
        raise SystemExit('Public smoke test failed: recover command returned nonzero')
    current = pathlib.Path(folder, 'CURRENT')
    assert current.exists(), 'Missing CURRENT pointer'
    print('Public smoke test completed:', current.read_text().strip())
