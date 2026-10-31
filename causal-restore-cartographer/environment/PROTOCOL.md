# Causal Restore Cartographer — Recovery Protocol

This protocol defines the data formats, integrity rules, recovery objective, and failure behavior for divergent replica histories and compacted checkpoints. Its manifest and output format use protocol identifier `2`.

## 0. Scope and trust assumptions

An operator supplies checkpoints and archived replica logs from several services. The goal is to recover the most state possible without violating cross-service causal dependencies. This is **not** a consensus-commitment check: the presence of a WAL record does not prove that production acknowledged it. The manifest inventory and checkpoint byte hashes are trusted inputs. Validate WAL records individually, anchor each selected history to a trusted checkpoint, and use a branch only when its entire selected suffix can be reconstructed from the archives.

All services and transactions in the input are synthetic. Recovery runs offline and must not modify the input directory. The output is evaluated against this specification.

### Encoding and canonicalization

- JSON is UTF-8. Object keys must be unique. NaN, infinity, and floating-point numbers are not allowed. Integers must fall within `[-(2^53-1), 2^53-1]`. Sequence numbers satisfy `0 <= seq < 2^53`; WAL records start at sequence 1. Strings and keys may contain Unicode scalar values, but not lone surrogates.
- Stream IDs are unique ASCII strings matching `[a-z][a-z0-9_]*`. The `case.json.streams` array is lexicographically sorted. Replica names and checkpoint IDs are nonempty ASCII strings of at most 100 characters, without separators or control characters. Declared artifact paths are relative POSIX paths with no `.` or `..` components. They must resolve to regular files within the real case root, without traversing symlinks. Every declared artifact path is unique within the manifest.
- Canonical JSON uses `json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)`, encoded as UTF-8 without a trailing newline and restricted to the JSON types above. Do not normalize Unicode; sort keys using Python's Unicode code-point ordering. A file's **byte hash** is the lowercase SHA-256 of its exact contents. Event IDs and WAL record digests must follow the definitions below.
- Fields are exact for the declared version. Unknown or missing fields in case metadata cause `INVALID_INPUT`. Unknown or missing fields in a checkpoint make that checkpoint unusable; in a WAL record, they make only that record unusable. A malformed WAL line does not invalidate the overall case inventory.

## 1. Manifest and archive topology

Example `case.json` (hash placeholders; use the supplied public fixture for an executable case):

```json
{
  "protocol": 2,
  "streams": ["inventory", "orders"],
  "snapshots": {
    "inventory": ["snapshots/inventory/i0.json", "snapshots/inventory/i8.json"],
    "orders": ["snapshots/orders/o0.json"]
  },
  "archives": {
    "inventory": [
      {"replica": "north", "fragments": ["wal/inventory/n0.jsonl", "wal/inventory/n1.jsonl"]},
      {"replica": "south", "fragments": ["wal/inventory/s0.jsonl"]}
    ],
    "orders": [
      {"replica": "north", "fragments": ["wal/orders/n0.jsonl"]}
    ]
  },
  "integrity": {
    "snapshots/inventory/i0.json": "<64 lowercase hexadecimal SHA-256>",
    "snapshots/inventory/i8.json": "<64 lowercase hexadecimal SHA-256>",
    "snapshots/orders/o0.json": "<64 lowercase hexadecimal SHA-256>"
  }
}
```

Every stream has `snapshots` and `archives` arrays; either array may be empty. Replica names must be unique **within a stream**. Fragments may arrive out of order, overlap, or contain competing branches. Array order carries no commitment or branch preference. The `integrity` map contains exactly the checkpoint paths and their expected byte SHA-256 values. WAL fragments have no whole-file inventory hashes, so valid records can be recovered from fragments that also contain damaged data.

Validate the manifest schema, path safety, all declared file paths and types, and separation of input and output roots **before** examining checkpoint validity. Any failure at this stage returns `INVALID_INPUT`, even if a checkpoint would also be unusable.

## 2. Checkpoint contract

Each checkpoint JSON has exactly:

```json
{
  "id": "inventory-8",
  "stream": "inventory",
  "seq": 8,
  "tip": "<64-hex digest of local WAL event at seq 8>",
  "state_format": 2,
  "state": {"sku/11": {"available": 4}},
  "requires": [
    {"stream": "orders", "seq": 3, "event_id": "<64-hex event identity>"}
  ],
  "witnesses": {
    "3": "<64-hex inventory event identity at seq 3>",
    "8": "<64-hex inventory event identity at seq 8>"
  }
}
```

`state` is a JSON map with Unicode keys compared exactly. `state_format` is 1 or 2; both versions represent the same logical map. At `seq=0`, `tip` is exactly 64 zero characters and `witnesses={}`. For `seq>0`, the checkpoint needs a witness at its own sequence identifying the event at the tip. Witness keys are canonical positive decimal strings without leading zeros, at most `seq`; witness values are event IDs, and each sequence appears once. The manifest authenticates the checkpoint's exact bytes, including the state, tip, witnesses, and foreign dependencies. A valid checkpoint can be used without recovering its compacted historical WAL events.

`requires` lists **all foreign event identities** needed for the checkpoint's state to be causally consistent. It may reference the same foreign stream at different sequences, but entries must be sorted and deduplicated lexicographically by `(stream, seq, event_id)`. A checkpoint cannot depend on its own stream. Missing historical `witnesses` entries do not invalidate a checkpoint; they mean the checkpoint cannot prove dependencies on those compacted events. Test cases must cover that distinction.

A checkpoint is unusable if its hash is wrong, its schema is malformed, it references an unknown stream, its ID is duplicated within the same stream, its state format is unsupported, or its self-witness is inconsistent. After case-level validation, return `NO_USABLE_SNAPSHOT` if any stream has no usable checkpoint.

When compacted WAL history is unavailable, the checkpoint self-witness cannot be independently linked to its tip using the archived records. The consistency of authenticated checkpoint metadata beyond the available source material is an **input assumption**; the engine is not expected to prove facts the case cannot establish.

## 3. WAL event IDs, records, and physically archived fragments

Each complete hash-valid JSONL WAL record has exactly:

```json
{
  "stream": "orders",
  "seq": 9,
  "nonce": "00112233445566778899aabbccddeeff",
  "event_id": "<sha256-derived stable identity>",
  "format": 2,
  "operation": {"kind": "put", "key": "order/7", "value": {"status": "packed"}},
  "requires": [
    {"stream": "inventory", "seq": 8, "event_id": "<inventory event identity>"}
  ],
  "prev": "<64-hex digest of immediate local predecessor>",
  "digest": "<record hash>"
}
```

### Stable event identities and reciprocal dependencies

Define `identity_payload = {"stream":stream,"seq":seq,"nonce":nonce,"format":format,"operation":operation}`. The **event ID** is the lowercase hexadecimal `SHA256(canonical_json(identity_payload))`. `nonce` is exactly 32 lowercase hexadecimal characters, and each record's `event_id` must match the computed value. The identity payload excludes `requires`, `prev`, and `digest`. This allows two events to reference each other without circular record hashes.

The **record digest** is `SHA256(canonical_json(record_except_digest))`. It binds the event identity to the predecessor and dependencies. If distinct hash-valid records share the same `(stream,seq,event_id)`, exclude **every** variant of that identity from candidate histories. This conflict rule applies even when one variant would otherwise lead to a longer history.

Each `requires` entry contains exactly `stream`, `seq`, and `event_id`; `seq>=1`, and the target must be another declared stream. Apply the same sorting and deduplication rules as for checkpoints. Malformed records are unusable. Timestamps, replica preference, and sequence numbers alone do not establish causality.

### Operations

- Format 1: `{"kind":"set","name":<string>,"payload":<JSON value>}` or `{"kind":"remove","name":<string>}`.
- Format 2: `{"kind":"put","key":<string>,"value":<JSON value>}` or `{"kind":"delete","key":<string>}`.

Operation objects contain exactly the listed fields. Deleting a missing key succeeds without changing state. Both versions operate on the same per-stream key-value map. Preserve JSON integers exactly; nested JSON values are allowed. Compare application keys as Unicode scalars without normalization.

### Recovering records from fragments

Read each fragment as newline-separated byte records. An unterminated final line is usable if it is a complete, valid UTF-8 JSON object with a verified record hash. Reject malformed, truncated, and wrong-stream lines individually; valid lines later in the same file remain available. However, a record after damaged data is selectable **only when its complete predecessor chain can be reconstructed from other valid records or from the selected checkpoint tip**. Missing history cannot be skipped.

Deduplicate identical records by `(stream,seq,digest)`. For each record, canonical provenance is the lexicographically smallest `(replica, path, 1-based line number)`. Distinct hash-valid records at the same stream and sequence can represent legitimate competing branches; their predecessor links and the remaining rules determine whether they are usable. Fragment iteration order must not affect the result.

### Reconstructible anchored paths

For a checkpoint with `seq=b` and `tip=H`, a selectable suffix is `r_(b+1), ..., r_v`, where `r_(b+1).prev = H` and every later `r_(k+1).prev = r_k.digest`. Sequence numbers increase by exactly one. Select at most one record per sequence. `v=b` is valid and replays nothing. A record with a valid digest but no complete chain to the checkpoint **cannot** be selected. Identical records may be assembled from separate replicas; records from incompatible branches may not be joined.

Checkpoints at the same sequence can belong to different branches and have different `tip` and `witnesses` values. Evaluate each against the paths anchored to its own tip. Never fill a missing sequence with an invented event.

## 4. Exact causal closure and atomic-group semantics

After selecting a checkpoint and path/cut for each stream, a foreign dependency `(t, q, id)` is satisfied only if the chosen history for stream `t` contains **exactly event ID** `id` at sequence `q`:

- If `q <= selected_checkpoint[t].seq`, its `witnesses[str(q)]` must equal `id`.
- If `q > selected_checkpoint[t].seq`, the selected WAL lineage must contain the record with `.seq==q` and `.event_id==id`, within the selected cut.
- If neither holds, the dependency is **unsatisfied**, even when stream `t` has reached a larger sequence number or another event occupies position `q`.

Check the `requires` entries on every selected checkpoint and every replayed WAL record through the chosen cut. The local prefix contains all events on its selected path after the checkpoint. Causal consistency requires **closure under the exact witnessed event identities**; comparing only numeric sequence positions is insufficient.

An atomic group across streams consists of events with **reciprocal dependencies on their exact stable IDs**. A complete directed dependency cycle is valid; a partial group is not. The input explicitly supplies all intended counterpart references, so recovery must not infer missing edges. Records describe committed business effects only; there is no implicit two-phase-commit or speculative-intent protocol. An explicitly reciprocal group contains at most one event from each stream.

## 5. Optimization and deterministic choice

Choose exactly one usable checkpoint and an anchored path for each stream, ending at a cut `v_s >= base_s`. A path may end before the latest archived event. The joint selection must satisfy every causal dependency. Maximize:

`objective = sum(v_s for s in case.json.streams)`.

The objective measures total recovered progress across the streams. Break ties in this order:

1. Lexicographically largest cut vector in `case.json.streams` order.
2. Lexicographically **smallest** checkpoint ID vector.
3. Lexicographically **smallest** final-head-digest vector (the selected snapshot's tip when its cut equals its base; otherwise the digest of its chosen final WAL record).

Under the stated SHA-256 collision-resistance assumption, these rules determine one result among distinct valid lineages. Identical copies use the canonical provenance rule above. Checkpoint age, archive filenames, branch popularity, and wall-clock timestamps do not affect preference.

For a fixed checkpoint and branch, finding a valid cut may be straightforward. The engine must still compare alternative checkpoints and branches to return the **globally optimal** cut. Any optimization method is allowed. An external solver may be used if it is available offline, but it cannot replace record validation, ancestry checks, replay, or durable publication.

Return `NO_CONSISTENT_RECOVERY` when every stream has at least one usable checkpoint but no valid joint checkpoint-and-path selection exists. The error precedence is defined in Section 7.

### Bounded execution on realistic workloads

The environment provides 4 CPUs and 8 GiB of RAM. Evaluation includes cases with eight streams and up to twelve divergent rooted histories per stream, sometimes with an additional authenticated checkpoint on one branch. A recovery case of this kind must finish within 120 seconds. A separate replay case has four streams and 24,000 WAL events distributed across fragments, with a 180-second case limit. The verifier overall has 1,200 seconds. These workload classes are checked independently. No particular search algorithm, dependency index, or database library is required. The engine must still produce the exact optimum and publish it safely at these sizes.


## 6. Required output contract

Command:

`python -m cartographer recover --input <case_dir> --output <output_dir>`

On success, publish an immutable `generations/<generation_id>/` directory containing `plan.json`, `restored.sqlite`, and `evidence.json`. A single `CURRENT` pointer identifies the active generation. Its UTF-8 content is `generations/<64-lowercase-hex-generation-id>\n`.

`plan.json` exactly contains:

- `protocol`: integer `2`;
- `cut`: map stream -> selected final inclusive sequence;
- `snapshots`: map stream -> selected checkpoint ID;
- `heads`: map stream -> checkpoint tip or selected final WAL digest;
- `objective`: sum of all final sequence numbers;
- `replay`: map stream -> array of replay record **digests** in increasing local sequence order.

`restored.sqlite` contains three tables:

- `kv(stream TEXT NOT NULL, key TEXT NOT NULL, value_json TEXT NOT NULL, PRIMARY KEY(stream,key))`, canonical JSON `value_json` for every final state mapping entry.
- `applied(stream TEXT NOT NULL, seq INTEGER NOT NULL, event_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(stream,seq))`, containing exactly the post-checkpoint replayed logical events (no checkpoint history or duplicate copies).
- `checkpoint(stream TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, base_seq INTEGER NOT NULL, final_seq INTEGER NOT NULL, final_digest TEXT NOT NULL)`.

`evidence.json` exactly contains: `protocol`, `cut`, `snapshots`, `heads`, `input_sha256`, `provenance`, `recovery_status`, `generation_id`:

- `protocol=2`; `recovery_status="complete"`; `cut`, `snapshots`, `heads` match `plan.json`.
- `input_sha256` maps **case.json and all declared checkpoint and fragment paths** to SHA-256 of exact file bytes, whether selected or not.
- `provenance` maps stream -> array of `{"digest":<record digest>,"replica":<replica>,"path":<fragment relative path>,"line":<positive one-based integer>}`. Arrays correspond exactly to `plan.replay` and use the canonical physical source location for each record.
- `generation_id = SHA256(canonical_json({"protocol":2,"plan":<parsed plan.json>,"input_sha256":<exact byte-hash map>}))`.

All output JSON follows the encoding and canonicalization rules above. Verification checks event identities, record digests, exact input byte hashes, the selected recovery, SQLite state, provenance, and generation ID. A candidate-reported success flag does not establish correctness.

## 7. Error order, filesystem model and recovery after failure

1. `INVALID_INPUT`: malformed case-level metadata, invalid or missing declared file, unsafe path, input/output overlap, invalid output-root configuration, unsafe symlink boundary. These failures take precedence over all other conditions.
2. `NO_USABLE_SNAPSHOT`: at least one stream has no independently valid authenticated checkpoint.
3. `NO_CONSISTENT_RECOVERY`: all streams have a usable checkpoint, but no legal joint selection exists.

For an error, exit with a nonzero status and write `<output>/error.json` as `{"protocol":2,"code":<one of the above>}`. Do not change an existing `CURRENT` on failure. If `CURRENT` already names a committed generation, a leftover `error.json` is stale and does not represent that generation's result.

Assume a local filesystem with atomic same-filesystem rename and directory `fsync`. No two recovery processes target the same output root concurrently, and external processes do not maliciously modify output files. Construct the generation in a staging directory on the output filesystem. Finalize and close SQLite, including any needed journal or checkpoint work. `fsync` the files and staging directory; promote staging to immutable `generations/<id>`; `fsync` `generations/`; write and `fsync` a temporary pointer; atomically rename that pointer to `CURRENT`; then `fsync` the output directory. Never overwrite a committed generation in place. If the generation ID already exists, verify its expected files and contents before reusing it. Different input-byte maps must produce different IDs even if the selected cut is unchanged.

If the process stops during publication, the previous good `CURRENT` must still resolve to a **complete generation**. Unpublished staging and orphaned generation directories may be cleaned on retry. After a successful retry, `CURRENT` must name the intended complete generation. Evaluation reads one resolved `CURRENT` target rather than following a changing pointer. Output symlinks must not escape the output root.

Process-interruption tests stop recovery at defined I/O boundaries. They do not simulate all storage-controller failures or filesystem behavior. The exercise uses no real credentials or external targets.

## 8. Illustrative consistency examples

**Matching sequence, wrong branch:** Orders event O2 requires inventory event I2-A (stable ID A). Two inventory lineages reach sequence 2: one contains I2-A and the other contains I2-B. A check based only on `inventory_cut >= 2` accepts both. The actual rule accepts only a lineage containing I2-A, or a checkpoint with an authenticated witness for that event.

**Valid reciprocal group:** Events A1 and B1 each derive their stable IDs from their own operations before dependencies are added. Their records can then include `requires` entries referring to each other's IDs. The resulting group must be selected together or not at all; its record hashes are well-defined.

**Repair using another replica:** One fragment has valid records 1 and 3 but a torn record 2. Another contains a hash-valid record 2 whose predecessor is record 1; record 3 points to record 2. The union provides a complete 1–2–3 chain. Selecting records 1 and 3 without record 2 remains invalid.

## 9. Validation scope

Verification covers recovery selection, reconstructed state, archive provenance, and interrupted publication. The interruption checks exercise defined filesystem-call boundaries and partial on-disk states; they do not simulate every type of physical power loss. The recovery requirements in this protocol are independent of any particular test implementation or evaluation platform.
