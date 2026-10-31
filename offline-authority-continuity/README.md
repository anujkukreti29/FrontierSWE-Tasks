# Offline Authorization Continuity

A maintenance gateway must continue authorizing local work when it cannot reach its central policy service. Updates may arrive late, out of order, or after a permission has been revoked. A request prepared under one policy state must not execute using authority granted only later.

Implement the service in `environment/workspace/permitgate/`. It must validate signed, hash-linked policy batches; recover missing update sequences; evaluate delegated permissions; require distinct operational and safety roots for critical work; and record each authorized effect exactly once. Signed checkpoints must allow history compaction without losing replay protection, open-request evidence, or audit records.

All sites, identities, and equipment are simulated. Execution writes to a local SQLite database. There are no external services or real equipment.

## Task files

```text
instruction.md    Required protocol and observable behavior
task.toml         Harbor configuration
environment/      Starter workspace, Dockerfile, and public examples
solution/         Oracle reference implementation
tests/            Independent verifier and Dockerfile
```

The candidate workspace contains the starter and public examples. The reference implementation and independent verifier are not part of that workspace.

## Public checks

The container uses Python 3.12 and `cryptography==44.0.2`. From `environment/workspace/`, run:

```bash
python -m unittest discover -s examples -p 'test_*.py' -v
python -m examples.check_candidate_demo
python -m examples.check_candidate_demo --scenario delegation
python -m examples.check_checkpoint_demo
```

The unit tests cover basic parsing and command transport. The signed examples exercise behavior that the starter does not yet implement. `instruction.md` defines the complete contract, including response codes and recovery rules.

## Evaluation

From the task root:

```bash
harbor run -p . -a oracle
harbor run -p . -a nop
```

The required scores are Oracle `1.000` and NOP `0.000`. Re-run both after changes to the reference, environment, or verifier. The configured agent budget is 72,000 seconds. Each routine `run` or `audit` process started by the verifier has a 35-second limit for the entire process. There is no separately graded bulk-throughput threshold.

The verifier logs `MODEL_SEED` for randomized delegation cases. Replay a failing graph with `PG_VERIFY_SEED=<printed integer>`. Signing keys and temporary identifiers are generated independently for each run.

## Development provenance

The design, reference implementation, verifier, and documentation received substantial AI assistance. That development history does not establish independent human authorship. The contributor must confirm that the work meets the client's ownership and authorship rules before submitting it.
