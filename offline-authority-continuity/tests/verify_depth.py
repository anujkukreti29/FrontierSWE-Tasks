"""Additional independent checks for the documented recovery and compaction rules.

These tests use the existing verifier's synthetic keys and public protocol. They
check observable responses and audit records, not candidate storage internals.
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import verify as v


def case_successive_checkpoints_and_replay(r, w):
    """Compacting again must preserve both old receipts and prepared authority."""
    core = [v.evt('grant', 'operations', 'operator'),
            v.evt('grant', 'safety', 'supervisor'),
            v.edge('delegate', 'operations', 'operator', 'tech'),
            v.edge('delegate', 'safety', 'supervisor', 'tech')]
    first = w.b('alpha', 1, '0' * 64, 'alpha-1', core)
    first_policy = [[1, 'grant', 'operations', 'operator', None, None, 'cooler', 'open', 10, 100],
                    [2, 'grant', 'safety', 'supervisor', None, None, 'cooler', 'open', 10, 100],
                    [3, 'delegate', 'operations', None, 'operator', 'tech', 'cooler', 'open', 10, 100],
                    [4, 'delegate', 'safety', None, 'supervisor', 'tech', 'cooler', 'open', 10, 100]]
    holding = [['hold', 'tech', 'cooler', 'open', [1, 2, 3, 4], v.digest({'seqs': [1, 2, 3, 4]})]]
    cp1 = w.cp('alpha', 4, w.hash(first),
               v.checkpoint_projection('alpha', [first], first_policy, tick=20, requests=holding))
    second = w.b('alpha', 5, w.hash(first), 'alpha-2',
                 [v.evt('grant', 'operations', 'auditor', asset='valve', action='inspect')])
    second_policy = first_policy + [[5, 'grant', 'operations', 'auditor', None, None,
                                     'valve', 'inspect', 10, 100]]
    cp2 = w.cp('alpha', 5, w.hash(second),
               v.checkpoint_projection('alpha', [first, second], second_policy,
                                       tick=20, requests=holding))
    fork = w.b('alpha', 1, '0' * 64, 'alpha-1',
               [v.evt('grant', 'operations', 'wrong')])
    last = w.b('alpha', 6, w.hash(second), 'alpha-2', [{'type': 'retire_key', 'key_id': 'alpha-1'}])
    refused = w.b('alpha', 7, w.hash(last), 'alpha-1',
                  [v.evt('grant', 'operations', 'bad')])
    expected = [v.full('applied'), v.full('prepared'), v.full('checkpointed'),
                v.full('applied'), v.full('checkpointed'), v.full('duplicate'),
                v.full('duplicate'), v.full('rejected', 'overlap'),
                {'status': 'ok', 'through_seq': 5, 'retained_from_seq': 6,
                 'accepted_batch_identities': 2, 'raw_batches': 0, 'gap': False},
                v.full('applied'), v.full('rejected', 'retired_key'),
                v.full('executed'), v.full('already_executed')]
    commands = [v.ingest(first), v.p('hold', 20), v.checkpoint_cmd(cp1),
                v.ingest(second), v.checkpoint_cmd(cp2), v.ingest(first),
                v.ingest(second), v.ingest(fork), v.checkpoint_status(),
                v.ingest(last), v.ingest(refused), v.c('hold', 21), v.c('hold', 21)]
    assert r.run(commands, expected) == expected
    effects = r.audit()
    assert len(effects) == 1 and effects[0]['request_id'] == 'hold', effects
    assert effects[0]['prepare_hash'] == v.digest({'seqs': [1, 2, 3, 4]})
    r.run([v.checkpoint_status()],
          [{'status': 'ok', 'through_seq': 5, 'retained_from_seq': 6,
            'accepted_batch_identities': 3, 'raw_batches': 1, 'gap': False}])


def case_strict_bootstrap_rejections(r, w):
    """Each malformed bootstrap is tested against a brand-new database."""
    baseline = json.loads(json.dumps(w.trust))
    cases = []
    def change(fn):
        data = json.loads(json.dumps(baseline))
        fn(data)
        cases.append(data)
    change(lambda x: x['sites']['alpha']['keys'][0].update(from_seq=True))
    change(lambda x: x['sites']['alpha']['keys'][0].update(from_seq=0))
    change(lambda x: x['sites']['alpha']['keys'][0].update(through_seq=2**63))
    change(lambda x: x['sites']['alpha']['keys'][0].update(public_key_hex='00'))
    change(lambda x: x['sites']['alpha']['keys'].append(x['sites']['alpha']['keys'][0].copy()))
    change(lambda x: x['sites']['alpha']['critical'].append({'asset':'cooler','action':'open'}))
    change(lambda x: x['sites']['alpha']['checkpoint_keys'][0].update(key_id='alpha-1'))
    change(lambda x: x['sites']['alpha'].update(extra=True))
    change(lambda x: x['sites']['alpha']['checkpoint_keys'][0].update(from_seq=0))
    change(lambda x: x['sites']['alpha']['checkpoint_keys'][0].update(key_id=''))
    for index, trust in enumerate(cases):
        r.state = r.root / f'invalid-trust-{index}.sqlite'
        r.write_trust(trust)
        try:
            r.run([v.checkpoint_status()])
        except AssertionError as err:
            assert 'Candidate failed' in str(err), (index, str(err))
        else:
            raise AssertionError(f'Malformed bootstrap accepted: variant {index}')
    # Duplicate keys must fail parsing even if a generic JSON loader would overwrite them.
    r.state = r.root / 'duplicate-json-key.sqlite'
    bad = v.enc(baseline).decode('utf-8').replace('"sites":', '"sites":{},"sites":', 1)
    r.trust.write_text(bad, 'utf-8')
    try:
        r.run([v.checkpoint_status()])
    except AssertionError as err:
        assert 'Candidate failed' in str(err), str(err)
    else:
        raise AssertionError('Bootstrap with duplicate JSON keys was accepted')


def case_crash_replay_and_exactly_once(r, w):
    """Interrupt a batch of commits; replaying it may not duplicate or lose effects."""
    first = w.b('alpha', 1, '0' * 64, 'alpha-1', [
        v.evt('grant', 'operations', 'operator'),
        v.evt('grant', 'safety', 'supervisor'),
        v.edge('delegate', 'operations', 'operator', 'tech'),
        v.edge('delegate', 'safety', 'supervisor', 'tech')])
    count = 70
    identifiers = [f'crash-{i:03d}' for i in range(count)]
    prepare = [v.p(rid, 20) for rid in identifiers]
    r.run([v.ingest(first)] + prepare,
          [v.full('applied')] + [v.full('prepared')] * count)
    commits = [v.c(rid, 21) for rid in identifiers]
    r.n += 1
    input_file = r.root / f'kill-commits-{r.n}.jsonl'
    output_file = r.root / f'kill-results-{r.n}.jsonl'
    input_file.write_bytes(b''.join(v.enc(cmd) + b'\n' for cmd in commits))
    input_file.chmod(0o644)
    cmd = [sys.executable, '-m', 'permitgate.cli', 'run', '--trust', str(r.trust),
           '--state', str(r.state), '--input', str(input_file), '--output', str(output_file)]
    env = os.environ.copy()
    env['PYTHONPATH'] = str(r.app)
    def drop():
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
    proc = subprocess.Popen(cmd, cwd=str(r.app), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            preexec_fn=drop if os.name == 'posix' else None)
    killed = False
    try:
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if proc.poll() is not None:
                break
            # The CLI is required to flush each response. Killing after the
            # first durable reply is more reliable than an arbitrary sleep.
            if output_file.exists() and output_file.stat().st_size:
                proc.kill()
                killed = True
                break
            time.sleep(0.003)
        if proc.poll() is None and not killed:
            proc.kill()
            killed = True
        _, stderr = proc.communicate(timeout=10)
        print(f'CRASH_REPLAY worker_killed={killed} exit_code={proc.returncode}', flush=True)
        if not killed and proc.returncode != 0:
            raise AssertionError(f'Commit worker failed: {stderr[:250]!r}')
        if killed:
            # A killed command could have taken effect before its answer was
            # written, so each replay response is either executed or already.
            replay = r.run(commits)
            assert all(row in (v.full('executed'), v.full('already_executed'))
                       for row in replay), replay
        else:
            # Some unusually fast implementations may finish before the kill.
            # Do not reject correct behavior due to a timing-based test.
            r.run(commits, [v.full('already_executed')] * count)
        r.run(commits, [v.full('already_executed')] * count)
        audit = r.audit()
        assert len(audit) == count, (len(audit), count)
        assert {x['request_id'] for x in audit} == set(identifiers)
        assert all(x['prepare_hash'] == v.digest({'seqs': [1, 2, 3, 4]})
                   and x['commit_tick'] == 21 for x in audit)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=10)



def case_checkpoint_commitment_with_live_and_final_requests(r, w):
    """A checkpoint must bind active permissions, unfinished evidence, effects and time."""
    initial = [v.evt('grant', 'operations', 'operator'),
               v.evt('grant', 'safety', 'inspector'),
               v.edge('delegate', 'operations', 'operator', 'tech'),
               v.edge('delegate', 'safety', 'inspector', 'tech')]
    first = w.b('alpha', 1, '0' * 64, 'alpha-1', initial)
    active1 = [[1, 'grant', 'operations', 'operator', None, None, 'cooler', 'open', 10, 100],
               [2, 'grant', 'safety', 'inspector', None, None, 'cooler', 'open', 10, 100],
               [3, 'delegate', 'operations', None, 'operator', 'tech', 'cooler', 'open', 10, 100],
               [4, 'delegate', 'safety', None, 'inspector', 'tech', 'cooler', 'open', 10, 100]]
    original_hash = v.digest({'seqs': [1, 2, 3, 4]})
    hold = ['held', 'tech', 'cooler', 'open', [1, 2, 3, 4], original_hash]
    done_effect = ['done', 'tech', 'cooler', 'open', original_hash, 21]
    cp1 = w.cp('alpha', 4, w.hash(first),
               v.checkpoint_projection('alpha', [first], active1, tick=21,
                                       requests=[hold], effects=[done_effect]))
    # A valid signature cannot endorse a different effect log, clock or open request.
    bad_state = w.cp('alpha', 4, w.hash(first),
                     v.checkpoint_projection('alpha', [first], active1, tick=20,
                                             requests=[hold], effects=[done_effect]))
    r.run([v.ingest(first), v.p('held', 20), v.p('done', 20), v.c('done', 21),
           v.checkpoint_cmd(bad_state), v.checkpoint_cmd(cp1)],
          [v.full('applied'), v.full('prepared'), v.full('prepared'),
           v.full('executed'), v.full('rejected', 'state_mismatch'),
           v.full('checkpointed')])
    revoke = w.b('alpha', 5, w.hash(first), 'alpha-2',
                 [v.evt('revoke', 'operations', 'operator')])
    regrant = w.b('alpha', 6, w.hash(revoke), 'alpha-2',
                  [v.evt('grant', 'operations', 'operator')])
    r.run([v.ingest(revoke), v.c('held', 22), v.ingest(regrant),
           v.p('current', 23), v.c('current', 24)],
          [v.full('applied'), v.full('denied', 'authority_changed'),
           v.full('applied'), v.full('prepared'), v.full('executed')])
    active2 = [active1[1], active1[2], active1[3],
               [6, 'grant', 'operations', 'operator', None, None, 'cooler', 'open', 10, 100]]
    new_hash = v.digest({'seqs': [2, 3, 4, 6]})
    open_requests = [['held', 'tech', 'cooler', 'open', [1, 2, 3, 4], original_hash]]
    effects = [['current', 'tech', 'cooler', 'open', new_hash, 24], done_effect]
    cp2 = w.cp('alpha', 6, w.hash(regrant),
               v.checkpoint_projection('alpha', [first, revoke, regrant], active2,
                                       tick=24, requests=open_requests, effects=effects))
    alternative = w.b('alpha', 5, w.hash(first), 'alpha-2',
                      [v.evt('grant', 'operations', 'attacker')])
    r.run([v.checkpoint_cmd(cp2), v.ingest(first), v.ingest(revoke),
           v.ingest(regrant), v.ingest(alternative), v.checkpoint_status()],
          [v.full('checkpointed'), v.full('duplicate'), v.full('duplicate'),
           v.full('duplicate'), v.full('rejected', 'overlap'),
           {'status': 'ok', 'through_seq': 6, 'retained_from_seq': 7,
            'accepted_batch_identities': 3, 'raw_batches': 0, 'gap': False}])
    # An unresolved future must block only this site, including previously prepared requests.
    missing = w.b('alpha', 7, w.hash(regrant), 'alpha-2',
                  [v.evt('grant', 'operations', 'other')])
    future = w.b('alpha', 8, w.hash(missing), 'alpha-2',
                 [v.evt('grant', 'safety', 'other')])
    beta = w.b('beta', 1, '0' * 64, 'beta-1',
               [v.evt('grant', 'operations', 'tech', 'valve', 'inspect')])
    r.run([v.ingest(future), v.c('held', 25), v.checkpoint_cmd(cp2),
           v.ingest(beta), v.p('beta-works', 25, 'beta', 'tech', 'valve', 'inspect'),
           v.c('beta-works', 26), v.ingest(missing), v.c('held', 27)],
          [v.full('buffered'), v.full('denied', 'gap'), v.full('rejected', 'gap'),
           v.full('applied'), v.full('prepared'), v.full('executed'),
           v.full('applied'), v.full('denied', 'authority_changed')])
    audited = r.audit()
    assert [row['request_id'] for row in audited] == ['beta-works', 'current', 'done'], audited
    assert audited[1]['prepare_hash'] == new_hash
    assert audited[2]['prepare_hash'] == original_hash
    assert r.run([v.p('held', 28)])[0] == v.full('denied', 'invalidated')


def case_large_prefix_retention_and_replay(r, w):
    """Compacting a long signed prefix must retain every accepted batch identity."""
    # This tests actual bounded-history behavior, rather than relying on just two fixtures.
    count = 72
    batches = []
    prior = '0' * 64
    for i in range(count):
        key = 'alpha-1' if i % 2 == 0 else 'alpha-2'
        events = [v.evt('grant', 'operations', f'actor-{i}', 'valve', 'inspect')]
        batch = w.b('alpha', i+1, prior, key, events)
        batches.append(batch)
        prior = w.hash(batch)
    assert r.run([v.ingest(b) for b in batches]) == [v.full('applied')] * count
    active = [[i+1, 'grant', 'operations', f'actor-{i}', None, None,
               'valve', 'inspect', 10, 100] for i in range(count)]
    state = v.checkpoint_projection('alpha', batches, active)
    cp = w.cp('alpha', count, prior, state)
    assert r.run([v.checkpoint_cmd(cp), v.checkpoint_status()]) == [
        v.full('checkpointed'),
        {'status':'ok', 'through_seq':count, 'retained_from_seq':count+1,
         'accepted_batch_identities':count, 'raw_batches':0, 'gap':False}]
    # Reverse replay order and independently signed overlapping intervals.
    replay = [v.ingest(b) for b in reversed(batches)]
    assert r.run(replay) == [v.full('duplicate')] * count
    wrong = w.b('alpha', 40, batches[38]['prev_hash'], 'alpha-2',
                [v.evt('grant','operations','different','valve','inspect')])
    follow = w.b('alpha', count+1, prior, 'alpha-2',
                 [v.evt('grant','operations','later','valve','inspect')])
    assert r.run([v.ingest(wrong), v.ingest(follow),
                  v.p('late', 25, 'alpha', 'later', 'valve', 'inspect'), v.c('late', 26)]) == [
        v.full('rejected','overlap'), v.full('applied'),
        v.full('prepared'), v.full('executed')]
    assert [x['request_id'] for x in r.audit()] == ['late']
    # Another checkpoint must commit to receipts from the first compacted prefix.
    all_batches = batches + [follow]
    active2 = active + [[count+1, 'grant', 'operations', 'later', None, None,
                         'valve', 'inspect', 10, 100]]
    evidence_hash = v.digest({'seqs': list(range(1, count+2))})
    state2 = v.checkpoint_projection('alpha', all_batches, active2, tick=26,
               effects=[['late', 'later', 'valve', 'inspect', evidence_hash, 26]])
    cp2 = w.cp('alpha', count+1, w.hash(follow), state2)
    assert r.run([v.checkpoint_cmd(cp2), v.ingest(batches[0]), v.checkpoint_status()]) == [
        v.full('checkpointed'), v.full('duplicate'),
        {'status':'ok', 'through_seq':count+1, 'retained_from_seq':count+2,
         'accepted_batch_identities':count+1, 'raw_batches':0, 'gap':False}]


DEPTH_CASES = [case_successive_checkpoints_and_replay,
               case_strict_bootstrap_rejections,
               case_crash_replay_and_exactly_once,
               case_checkpoint_commitment_with_live_and_final_requests,
               case_large_prefix_retention_and_replay]
