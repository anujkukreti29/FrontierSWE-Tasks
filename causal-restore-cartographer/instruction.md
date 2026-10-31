# Causal Restore Cartographer — Divergent Replica Recovery

A logistics platform is recovering from an outage. Its services retain independent checkpoints and write-ahead log (WAL) archives. The archives may include overlapping fragments, damaged records, and divergent histories. Checkpoints and WAL entries may depend on events from other services, so independently restoring the latest local state does not necessarily produce a consistent global state.

Implement a recovery engine that reconstructs valid replica histories, finds the **globally optimal causally consistent recovery**, restores application state in SQLite, and publishes the result without exposing incomplete data.

The starter module is at `/app/cartographer/`. `/app/PROTOCOL.md` defines the authoritative input and output formats, integrity checks, selection rules, tie-breakers, error precedence, and publication behavior.

## Command

```bash
python -m cartographer recover --input /path/to/case --output /path/to/output
```

A case may contain up to eight streams, each with alternative checkpoints and replica histories. WAL fragments can overlap, appear out of order, contain damaged lines, or omit records found in another replica. Selecting the newest event from each stream independently is not sufficient.

## Required behavior

1. **Validate inputs.** Check the manifest, file paths, checkpoint byte hashes, JSON content, and input/output boundaries. Report the errors defined by the protocol.
2. **Reconstruct histories.** Assemble contiguous, hash-linked WAL paths from valid records across replicas. Deduplicate identical records, report canonical provenance, and exclude conflicting variants of a stable event identity.
3. **Enforce causal dependencies.** Check cross-stream references against exact event identities, including historical events witnessed by checkpoints. Accept complete reciprocal dependency groups but reject incomplete groups.
4. **Select the global optimum.** For each stream, choose a checkpoint, a lineage, and an inclusive cut. Maximize the protocol's recovery objective and apply all tie-breakers in order. A valid but suboptimal selection is incorrect.
5. **Restore application state.** Apply only operations after each selected checkpoint. Build the required SQLite tables and preserve both operation formats, deletion semantics, JSON values, and replay evidence.
6. **Publish a complete generation.** Follow the specified durability and pointer-update sequence. Handle retries, changed archive bytes, interrupted publication, and existing generations.
7. **Preserve committed output on failure.** Apply the required error precedence and leave a previously committed `CURRENT` unchanged if recovery fails.

You may choose the implementation strategy. The solution must work for both highly branched histories and long replay chains. Hardcoded public-example output and exhaustive searches that cannot meet the workload limits are insufficient.

## Testing and limits

The public case is in `/app/fixtures/public_case/`. Run its smoke test with:

```bash
python /app/public_check.py
```

The public fixture demonstrates the command interface; it does not cover the complete contract. The environment provides **4 CPUs and 8 GiB RAM**. Recovery cases with eight streams and up to **12 divergent rooted histories per stream**, sometimes with additional checkpoint choices, must complete within **120 seconds per case**. Four-stream cases with **24,000 replay events** must complete within **180 seconds per case**. Both workloads must satisfy the complete recovery and publication contract.

The agent execution budget is **72,000 seconds (20 hours)**. No particular algorithm, command sequence, or waiting period is required.
