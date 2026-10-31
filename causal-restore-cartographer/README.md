# Causal Restore Cartographer

**Category:** Long-Horizon Software Engineering  
**Subcategory:** Distributed Systems / Recovery Engineering  
**Task version:** 1.0.0  
**Agent budget:** 72,000 seconds

## Overview

A logistics platform must recover after an outage using independently captured service checkpoints and archived write-ahead logs. The available records may be incomplete, damaged, duplicated, or split across conflicting replica histories. Restoring each service to its latest local state can leave cross-service dependencies unsatisfied.

Implement a recovery engine that reconstructs valid histories, selects the globally optimal causally consistent recovery, replays the selected operations into SQLite, and publishes the result safely. The work combines integrity validation, cross-service dependency reasoning, exact optimization, database replay, and crash-safe publication.

`instruction.md` states the engineering assignment. `environment/PROTOCOL.md` is the authoritative specification for input formats, output files, integrity checks, selection rules, error precedence, and publication behavior.

## Project layout

```text
instruction.md       Engineering assignment
task.toml            Harbor task configuration
environment/         Starter project, protocol specification, and public fixture
solution/            Reference implementation and its entry point
tests/               Independent verifier and test entry point
README.md            Project overview
```

The reference implementation and verifier are separate from the agent's starting environment. The container images use the same digest-pinned Python base image and operate without network access.

## Implementation interface

From the agent container, run:

```bash
python -m cartographer recover --input /path/to/case --output /path/to/output
```

To run the public smoke test:

```bash
python /app/public_check.py
```

The task permits any correct implementation strategy. The engine must reconstruct hash-linked histories from overlapping archives, check cross-stream event identities, choose the exact global optimum, materialize the specified SQLite state and evidence, and publish an immutable generation without invalidating an earlier committed result.

## Resource limits

The agent environment provides 4 CPUs and 8 GiB of memory. Eight-stream cases with up to twelve divergent rooted histories per stream have a **120-second limit per case**. Four-stream cases with 24,000 replay events have a **180-second limit per case**. The verifier's overall timeout is 1,200 seconds. The agent budget is 72,000 seconds. 

## Development provenance

The task design, reference implementation, and verifier include substantial AI-assisted development. They must not be represented as independently human-authored without evidence of independent contributor work. Eligibility depends on the receiving program's authorship requirements.
