# Gatekeeper — Offline Authorization and Recovery

Gatekeeper is an authorization service for maintenance gateways that operate during network outages. Gateways receive signed checkpoints, root-key rotations, and delegated grants in arbitrary order. The service must authenticate that history, decide whether a request is permitted, and record each authorized simulated operation exactly once. Decisions and committed effects must survive abrupt termination and restoration of an older disposable cache.

## Task layout

| Path | Contents |
| --- | --- |
| `instruction.md` | Agent-facing objective, required commands, and completion criteria |
| `task.toml` | Harbor configuration, resource limits, and execution budgets |
| `environment/` | Agent Docker image, starter package, binding protocol, and public checks |
| `solution/` | Reference implementation and Oracle entry point; excluded from the agent workspace |
| `tests/` | Isolated verifier, signed-fixture generator, and integration scenarios |

The binding contract is [`environment/workspace/contract/PROTOCOL_V2.md`](environment/workspace/contract/PROTOCOL_V2.md). The `V2` suffix identifies the signed-record protocol; it does not denote a task release. Do not rename its signature domains or change the required on-wire formats. The starter implements trust initialization, read-only status reporting, a SQLite store, and reusable cryptographic helpers. The solver must complete record ingestion, authorization decisions, durable effect recording, and recovery.

## Engineering requirements

The system must satisfy six related guarantees:

1. **Authenticated issuance:** Verify root grants using their historical root keys and Merkle inclusion proofs against committed checkpoint batches.
2. **Authority reconciliation:** Authenticate and apply delayed checkpoints and dual-signed rotations in causal order. Keep unverified descendants pending; distinguish authenticated equivocation from forged claims.
3. **Delegation and revocation:** Enforce permissions, resource-path boundaries, validity intervals, delegation depth, ancestor revocation, and conflicts between authenticated grants.
4. **Protected time:** Persist monotonic decision time and enforce offline freshness from the latest authenticated checkpoint. Key rotation does not extend freshness.
5. **Durable execution:** Serialize authority updates with decisions, and commit each simulated effect and its replay receipt atomically.
6. **Recovery:** Preserve committed authority, revocations, receipts, and effects across restarts and cache rollback. Fail safely if authoritative storage is corrupt.

These requirements are interdependent. A valid signature is not proof of historical issuance; a valid permission check is not sufficient without an atomic, replay-safe effect commit.

## Build and run

Both Dockerfiles use the same digest-pinned Python 3.12 base image and install `cryptography==46.0.4`, `cffi==2.0.0`, and `pycparser==3.0`. The agent image does not install `pytest`. Execution is configured without network access. Verify that the base digest resolves for the deployment architecture and that both images build from a clean extraction; digest pinning alone is not a build test.

From the task directory on Windows:

```bat
python ..\frontierswe-check.py .
harbor run --path "%CD%" --agent oracle
harbor run --path "%CD%" --agent nop
```

Use the options supported by the installed Harbor version. Docker is required for Harbor evaluation. The standalone verifier can also be run in a suitable Linux environment with Python 3.12+ and the pinned dependencies:

```sh
GATEKEEPER_WORKSPACE="$PWD/solution/reference" GATEKEEPER_REWARD_PATH=/tmp/gatekeeper-reference.txt python3 tests/scenarios.py
GATEKEEPER_WORKSPACE="$PWD/environment/workspace" GATEKEEPER_REWARD_PATH=/tmp/gatekeeper-starter.txt python3 tests/scenarios.py
python3 tests/generator_selftest.py
```

The verifier runs the CLI in separate processes and independently checks signed inputs, authorization outcomes, and the durable effect ledger. Candidate processes run with reduced privileges in the verifier image. Trusted test code, grading data, and reward files remain outside the candidate workspace.

## Verification and reproducibility

The verifier contains **37 integration scenarios** covering causal reconciliation, historical keys, proof validation, delegation, revocation, replay, concurrency, process termination, stale caches, protected-store corruption, tenant separation, and integer boundaries. The reward equals the fraction of scenarios passed **only if** at least one designated end-to-end authorization/effect scenario succeeds; otherwise it is zero. Initialization alone receives no credit. The specific partial-credit policy should be confirmed against the receiving benchmark's rules.

Randomized scenarios 31 and 32 generate a fresh seed per run and print `VERIFIER_REPLAY_SEED=<64 hex digits>`. The verifier also writes the seed when `GATEKEEPER_SEED_LOG_PATH` is configured. Set `GATEKEEPER_TEST_SEED=<recorded seed>` to reproduce their signed fixtures, identifiers, input order, and sampling choices. Seed logs belong on the verifier side, not in the agent workspace.

If scenario evaluation crashes, `tests/test.sh` writes a fallback reward of `0`, emits `VERIFIER_ERROR`, and exits nonzero. Such an event is an infrastructure or verifier failure, **not** proof of incorrect candidate behavior.

The agent timeout is **72,000 seconds (20 hours)**; the verifier timeout is **1,800 seconds**. A previous local reference run passed **37/37 scenarios** in approximately 687 seconds, while an earlier unchanged-starter baseline scored **0.000000**. These results are not Harbor Oracle/NOP scores for this exact package. Docker builds, final client checks, Harbor Oracle/NOP, and advanced-agent difficulty calibration remain unverified.

## Release status

The package defines a complete engineering task and includes a reference used for local validation. Neither a successful local test run nor this documentation establishes independent contributor authorship, eligibility under client ownership rules, or acceptance by a benchmark sponsor. Those matters require separate supporting evidence and review.
