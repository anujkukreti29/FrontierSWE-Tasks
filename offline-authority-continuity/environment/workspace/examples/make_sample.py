"""Generate PUBLIC non-secret examples of dual-control, retirement and gap behavior."""
import argparse
import json
from pathlib import Path
from .vectorlib import bundle, bhash, grant, delegate, trust_config


def generate(dest):
    folder = Path(dest)
    folder.mkdir(parents=True, exist_ok=True)
    (folder/'trust.json').write_text(json.dumps(trust_config(), indent=2)+'\n')
    events = [grant('operations', 'maintainer'),
              grant('safety', 'inspector'),
              delegate('operations', 'maintainer', 'technician'),
              delegate('safety', 'inspector', 'technician')]
    b1 = bundle('north', 1, '0'*64, 'north-a', events)
    b2 = bundle('north', 5, bhash(b1), 'north-a',
                [{'type':'revoke','authority':'operations', 'principal':'maintainer',
                  'asset':'pump7','action':'start'}])
    b3 = bundle('north', 6, bhash(b2), 'north-b',
                [grant('operations','maintainer')])
    b4 = bundle('north', 7, bhash(b3), 'north-b',
                [{'type':'retire_key','key_id':'north-a'}])
    old = bundle('north', 8, bhash(b4), 'north-a',
                 [grant('operations','someone',asset='unused',action='inspect')])
    b5 = bundle('north', 8, bhash(b4), 'north-b',
                 [grant('operations','someone',asset='unused',action='inspect')])
    south1 = bundle('south', 1, '0'*64, 'south-a',
                    [grant('operations','southern',asset='valve',action='inspect')])
    south2 = bundle('south', 2, bhash(south1), 'south-a',
                    [grant('operations','other',asset='valve',action='inspect')])
    cmds = [
        {'kind':'ingest','bundle':b1},
        {'kind':'prepare','request_id':'req-1','site':'north','principal':'technician',
         'asset':'pump7','action':'start','tick':20},
        {'kind':'commit','request_id':'req-1','tick':21},
        {'kind':'prepare','request_id':'req-2','site':'north','principal':'technician',
         'asset':'pump7','action':'start','tick':22},
        {'kind':'ingest','bundle':b2},
        {'kind':'commit','request_id':'req-2','tick':23},
        {'kind':'ingest','bundle':b3},
        {'kind':'commit','request_id':'req-2','tick':24},
        {'kind':'prepare','request_id':'req-3','site':'north','principal':'technician',
         'asset':'pump7','action':'start','tick':25},
        {'kind':'commit','request_id':'req-3','tick':26},
        {'kind':'ingest','bundle':b4},
        {'kind':'ingest','bundle':old},
        {'kind':'ingest','bundle':b5},
        {'kind':'ingest','bundle':b1},
        {'kind':'ingest','bundle':south2},
        {'kind':'prepare','request_id':'req-s','site':'south','principal':'southern',
         'asset':'valve','action':'inspect','tick':20},
        {'kind':'ingest','bundle':south1},
        {'kind':'prepare','request_id':'req-s','site':'south','principal':'southern',
         'asset':'valve','action':'inspect','tick':21},
        {'kind':'commit','request_id':'req-s','tick':22},
    ]
    expected = [
        ('applied','applied'), ('prepared','prepared'), ('executed','executed'),
        ('prepared','prepared'), ('applied','applied'), ('denied','authority_changed'),
        ('applied','applied'), ('denied','authority_changed'), ('prepared','prepared'),
        ('executed','executed'), ('applied','applied'), ('rejected','retired_key'),
        ('applied','applied'), ('duplicate','duplicate'), ('buffered','buffered'),
        ('denied','gap'), ('applied','applied'), ('prepared','prepared'), ('executed','executed'),
    ]
    assert len(cmds) == len(expected)
    (folder/'commands.jsonl').write_text(''.join(json.dumps(cmd, ensure_ascii=False)+'\n' for cmd in cmds))
    (folder/'expected_status_codes.json').write_text(json.dumps(expected, indent=2)+'\n')
    (folder/'README.txt').write_text(
        'PUBLIC protocol test vectors. The starter is intentionally incomplete and will\n'
        'not match expected_status_codes.json. This fixture does not cover concurrency,\n'
        'large graphs or recovery and is not a benchmark oracle.\n')
    return cmds, expected

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output_dir')
    generate(parser.parse_args().output_dir)
