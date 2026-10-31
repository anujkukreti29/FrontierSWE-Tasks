"""Public manual contract vectors for alternative proofs and post-prepare regrants.

The expected outcomes are normative demonstrations, not an evaluator or private oracle.
"""
import argparse
import json
from pathlib import Path
from .vectorlib import bundle, bhash, grant, delegate, trust_config


def generate(dest):
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    (root / 'trust.json').write_text(json.dumps(trust_config(), indent=2) + '\n')
    first = [
        grant('operations','op-a'),
        grant('operations','op-b'),
        grant('safety','safety-a'),
        delegate('operations','op-a','technician'),
        delegate('operations','op-b','technician'),
        delegate('safety','safety-a','technician')
    ]
    b1 = bundle('north',1,'0'*64,'north-a',first)
    b2 = bundle('north',7,bhash(b1),'north-a',[
        {'type':'undelegate','authority':'operations','delegator':'op-a',
         'delegatee':'technician','asset':'pump7','action':'start'}])
    b3 = bundle('north',8,bhash(b2),'north-a',[
        {'type':'undelegate','authority':'operations','delegator':'op-b',
         'delegatee':'technician','asset':'pump7','action':'start'}])
    b4 = bundle('north',9,bhash(b3),'north-b',[
        grant('operations','op-c'),
        delegate('operations','op-c','technician')])
    b5 = bundle('north',11,bhash(b4),'north-b',[
        {'type':'revoke','authority':'safety','principal':'safety-a',
         'asset':'pump7','action':'start'},
        grant('safety','safety-a')])
    def prepare(rid,tick):
        return {'kind':'prepare','request_id':rid,'site':'north',
                'principal':'technician','asset':'pump7','action':'start','tick':tick}
    def commit(rid,tick):
        return {'kind':'commit','request_id':rid,'tick':tick}
    def ingest(bundle_obj):
        return {'kind':'ingest','bundle':bundle_obj}
    commands = [
        ingest(b1), prepare('alt-path',20), prepare('fenced',20),
        ingest(b2), commit('alt-path',21), ingest(b3), commit('fenced',22),
        ingest(b4), commit('fenced',23), prepare('safety-fence',24),
        ingest(b5), commit('safety-fence',25), prepare('fresh',26),
        commit('fresh',27), commit('fresh',27)
    ]
    expected = [
        ('applied','applied'), ('prepared','prepared'), ('prepared','prepared'),
        ('applied','applied'), ('executed','executed'), ('applied','applied'),
        ('denied','authority_changed'), ('applied','applied'),
        ('denied','authority_changed'), ('prepared','prepared'),
        ('applied','applied'), ('denied','authority_changed'),
        ('prepared','prepared'), ('executed','executed'),
        ('already_executed','already_executed')
    ]
    assert len(commands) == len(expected)
    (root/'commands.jsonl').write_text(''.join(json.dumps(x, ensure_ascii=False)+'\n' for x in commands))
    (root/'expected_status_codes.json').write_text(json.dumps(expected,indent=2)+'\n')
    (root/'README.txt').write_text(
        'PUBLIC signed scenario: alternative old proofs vs changed event IDs; '
        'starter is deliberately incomplete; audit should contain two effects.\n')
    return commands, expected

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output_dir')
    generate(parser.parse_args().output_dir)
