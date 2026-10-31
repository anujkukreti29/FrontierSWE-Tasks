# Offline Authorization Continuity and Crash-Safe Checkpoints

A maintenance gateway may lose access to its central policy service for days. While disconnected, it must make decisions using previously authenticated policy updates. When connectivity returns, new updates may arrive late or out of order.

Permissions can change between preparing and executing a request. Critical operations require separate operational and safety approval. To control storage growth, the gateway must reclaim old signed batches without losing replay protection or evidence needed by unfinished requests. Implement `/app/permitgate` so these guarantees hold through policy changes, restarts, and concurrent database access. An update takes effect only after the gateway receives and applies it.

All sites, identities, keys, and equipment are simulated. Execution records an effect in local SQLite storage. It does not control physical equipment or contact external services.

## 1. Invocation and trust model

Implement these commands:

```bash
python -m permitgate.cli run --trust TRUST.json --state STATE.sqlite --input COMMANDS.jsonl --output ANSWERS.jsonl
python -m permitgate.cli audit --state STATE.sqlite --output EFFECTS.jsonl
```

`run` reads UTF-8 JSON objects, one per nonblank line. It writes one response object for every input line, preserving input order. A malformed line must not prevent later lines from being processed. Return `{"status":"denied","code":"malformed"}` for invalid UTF-8, invalid JSON, duplicate JSON keys at any depth, non-finite JSON numbers, unpaired Unicode surrogates, or a command that is not a JSON object.

Accept only the fields specified here. Reject unknown fields in commands and policy objects. A JSON Boolean does not count as an integer. Identity strings must be nonempty. Hashes and Ed25519 signatures use lowercase hexadecimal. `audit` reads the saved state rather than replaying the original input. Different processes must be able to reopen the same state database.

The bootstrap trust file has this format:

```json
{
  "sites": {
    "north": {
      "keys": [
        {"key_id":"north-a", "public_key_hex":"<64 lowercase hex>", "from_seq":1, "through_seq":1000},
        {"key_id":"north-b", "public_key_hex":"<64 lowercase hex>", "from_seq":1, "through_seq":1000}
      ],
      "critical": [{"asset":"pump7", "action":"start"}],
      "checkpoint_keys": [{"key_id":"north-checkpoint", "public_key_hex":"<64 lowercase hex>", "from_seq":1, "through_seq":1000}]
    }
  }
}
```

Policy key IDs must be unique within each site. The optional `checkpoint_keys` list uses the same four fields as `keys`; its IDs must be unique and must not collide with policy key IDs. If `checkpoint_keys` is absent, the site cannot install checkpoints. Policy keys cannot sign checkpoints, and checkpoint keys cannot sign policy batches. Checkpoint-key sequence windows are inclusive and positive. Windows for different keys may overlap so that the site can rotate signing keys. Each site also has a unique set of critical `(asset, action)` pairs. Any pair not in that set is ordinary.

Validate the entire bootstrap file at startup and store a fingerprint of the parsed canonical configuration. Reject a saved database if its fingerprint differs from the supplied bootstrap. An invalid bootstrap file or incompatible saved state is a fatal startup error, not a denied policy command.

**Limits and trust assumptions.** Event sequences and ticks are nonnegative signed 64-bit integers, except that sequence numbers start at 1. Treat signed input as potentially hostile. The local command harness is assumed to have authenticated the principal named in `prepare`; local client authentication is outside this protocol. A command's `tick` comes from the gateway's local synthetic trusted clock, not a remote caller. Clock attestation is also outside scope.

The gateway cannot enforce updates it has not received, but it must enforce every revocation it has applied. When it has authenticated a future batch but is missing part of the preceding history, it must deny affected work until the gap is resolved.

## 2. Authenticated, hash-linked history

An `ingest` command has the form `{"kind":"ingest","bundle":BUNDLE}`. Every bundle contains exactly six fields:

```json
{"site":"north","start_seq":1,"prev_hash":"<64 hex>","key_id":"north-a","events":[EVENT],"signature":"<128 hex>"}
```

The signed payload is the first five fields. Produce its canonical bytes with:

```python
json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
```

Verify the Ed25519 signature over `SHA256(canonical_json(payload))`, which is 32 bytes. Do not verify it over the canonical JSON bytes directly. The batch ID is the lowercase hexadecimal SHA256 of those canonical bytes.

A bundle must contain `n > 0` events. Define `end_seq = start_seq + n - 1`; event `i`, counted from zero, has the permanent identity `(site, start_seq + i)`. Reject any signed 64-bit overflow.

The first accepted bundle for a site starts at sequence 1 and has a `prev_hash` of 64 zero characters. Each later accepted bundle must begin immediately after the previous bundle and refer to the previous batch hash. A signing key can authorize a bundle only when its **bootstrap** interval `[from_seq, through_seq]` covers the whole batch and an earlier applied batch has not retired it. Check this against the state before applying the new bundle. A key may retire itself in the bundle it signs, but cannot sign a later bundle.

### Out-of-order delivery

A batch may arrive before its predecessor. Validate its structure, bootstrap key range, and signature before buffering it. If those checks pass, keep the bundle as **pending**. Its predecessor hash and signing-key status must be checked again when the missing history arrives. Pending batches must survive restarts.

An identical repeat of either an accepted or a pending batch returns `duplicate`, even after the signer has retired. A different bundle that overlaps the sequence interval of an accepted or pending bundle returns `overlap`. A contiguous bundle with an incorrect `prev_hash` returns `fork`. Each site may hold at most 64 pending batches. Adding another returns `pending_limit`. Duplicates do not consume additional slots.

**While a site has any unresolved pending future batch, deny all new prepares and commits at that site.** Existing grants do not override this rule. Other sites must continue to work.

After applying a batch, inspect pending batches in sequence order. Apply a pending batch only if it starts at the next required sequence. Before applying it, check its predecessor hash and the signing key's current retirement status again. If either check fails, discard that pending batch without applying any of its events or changing accepted history. More distant pending batches remain pending and continue to block the site. Delivery order and discarded forks must not provide a way around this restriction.

The threat model assumes an attacker cannot replace or roll back the local database. The task covers process crashes, interrupted transactions, retries, and rollback of the synthetic clock. It does **not** cover an administrator restoring an old database snapshot. Protecting against that threat would require an external monotonic hardware anchor.

### Ingest responses

Return an object of the form `{"status":"applied|buffered|duplicate|rejected","code":"..."}`. On success, `code` is the same as `status`. Rejection codes are:

`malformed`, `unknown_site`, `unknown_key`, `bad_signature`, `key_range`, `retired_key`, `overlap`, `fork`, `pending_limit`.

Use `retired_key` when an otherwise contiguous, authenticated incoming batch is signed by a key that a previous applied batch retired. Invalid trusted bootstrap data must instead stop startup. When a command has more than one independent error, any applicable documented rejection code is acceptable; exact-code tests cover single-fault cases. If an incoming bundle applies successfully but draining later reveals an invalid pending bundle, the incoming bundle still returns `applied`.

## 3. Policy events

Every event has exactly the fields listed below. `authority` is either `operations` or `safety`. Principal names, `asset`, and `action` must be nonempty strings. Time windows are half-open and must satisfy `0 <= valid_from_tick < expires_at_tick <= 2^63-1`.

| Event | Fields in addition to `type` | Effect at the event's sequence |
|---|---|---|
| `grant` | `authority`, `principal`, `asset`, `action`, `valid_from_tick`, `expires_at_tick` | Set or replace the active root grant for `(authority, principal, asset, action)` with this event ID and time window. |
| `revoke` | `authority`, `principal`, `asset`, `action` | Remove the active root grant with that exact key, if one exists. |
| `delegate` | `authority`, `delegator`, `delegatee`, `asset`, `action`, `valid_from_tick`, `expires_at_tick` | Set or replace the directed edge keyed by `(authority, delegator, delegatee, asset, action)`. |
| `undelegate` | `authority`, `delegator`, `delegatee`, `asset`, `action` | Remove the active directed edge with that exact key, if one exists. |
| `retire_key` | `key_id` | Permanently disable a known bootstrap signing key for later batches at this site. The current authenticated bundle still applies atomically. |

The site policy authority signs batches containing grants and delegations. Distinct root principals provide **policy-level separation of duties**. They are not independently controlled cryptographic signing keys. The simulation assumes the central authority has approved the root assignments expressed in signed events.

A `delegate` event can be installed even when the delegator has no current authority. When the edge is used, the gateway must establish a valid path from an active root to that delegator. Revoking a nonexistent grant or removing a nonexistent delegation is allowed; the event still consumes a sequence number. Repeatedly retiring an already retired but known key is also allowed. Trying to retire an unknown key makes the entire bundle malformed. Cycles are valid graph structure but cannot create authority without a root.

Every active grant and delegation edge keeps the immutable sequence identity of the event that established it. Replacing a record creates a new identity, even when the replacement has exactly the same fields.

## 4. Delegated authorization and independent approval

For each `(site, asset, action, tick)`, evaluate the current policy as two directed graphs: one for `operations` and one for `safety`.

- A time-valid root `grant` authorizes its principal and serves as a starting point in that authority's graph.
- A time-valid `delegate` edge from A to B carries that authority to B only when a directed path from a valid root reaches A.
- A grant or edge can be used only if it is the currently active version of its exact key and the requested tick lies within its time window.
- Any valid path is sufficient. Cycles, redundant edges, and multiple roots are permitted. An incoming delegation edge alone does not establish authority.

For an **ordinary** `(asset, action)` pair, the principal needs a valid `operations` path. For a **critical** pair, the principal needs both an `operations` path and a `safety` path, **starting from different root principals**. The two paths may share intermediate delegates. What matters here is the difference between the root principals and authority labels. A principal holding a valid root grant can use the zero-edge path to itself.

For example, an `operations` path from `maintainer-a` through a delegation to `technician`, together with a `safety` path from `inspector-b` to `technician`, allows a critical operation. If both paths start from `maintainer-a`, they do not. Removed root grants, expired intermediary edges, and revoked delegations must affect both graphs immediately when the changes are applied.

Any graph representation or traversal method is acceptable. The service need not report which valid path it used.

## 5. Preparation and commit

A `prepare` command has exactly these fields:

```json
{"kind":"prepare","request_id":"r7","site":"north","principal":"technician","asset":"pump7","action":"start","tick":20}
```

A request can be prepared only if section 4 authorizes it and no pending history gap blocks the site. It permanently binds the globally unique `request_id` to the supplied request tuple and a snapshot of the policy evidence at that tick.

That evidence is the set of event IDs of **all currently active, time-valid root grants and delegation edges** for the requested site, asset, and action. It includes records that are not used by a particular successful path. Different implementations may find different authorization paths, but must save the same set of available evidence. Call this set `S_prepare`.

Save a durable `prepare_hash` calculated as:

```python
SHA256(canonical_json({"seqs": sorted(S_prepare)})).hexdigest()
```

Each event ID in the sorted list is its site-local integer sequence. The hash appears in the audit record, not in the `prepare` reply.

A `commit` command has exactly:

```json
{"kind":"commit","request_id":"r7","tick":21}
```

At commit, check authorization again under section 4, using **only** records whose event IDs belong to `S_prepare`, are still active, and have time windows covering the commit tick. Perform this check within the same atomic transaction that saves the effect and the request's final status.

A grant or delegation received after preparation cannot authorize that earlier request. A previously available alternative path can still authorize the request if it remains valid. Revoking a grant and then recreating it, even with identical fields, creates a new event ID and cannot restore an older request. Unrelated policy updates should not invalidate a surviving proof. A pending gap at the site blocks commits.

### Request IDs and retries

Request IDs are unique across all sites. Reusing an ID with a different request tuple must not change the original binding. Repeating `prepare` with the same ID and tuple may return `prepared` only while the request remains uncommitted and its **original** evidence still authorizes it at the new tick. The repeated call must not replace the saved evidence. Once committed, a request must never generate another effect.

### Local clock handling

Store a nondecreasing `max_tick_seen` for each site. For a syntactically valid `prepare` at a known site, or a `commit` that refers to a known request, compare the command tick with this maximum. A lower tick returns `stale_tick` **before any other authorization check**. An equal tick is allowed. For a new maximum, save it durably before returning, even if the request is ultimately denied. Malformed commands, unknown sites, and unknown requests must not change a site's clock.

This prevents the local clock from moving below an observed value. It does not authenticate time supplied by a remote caller.

### Prepare responses

Success is `{"status":"prepared","code":"prepared"}`. Denials use `{"status":"denied","code":CODE}` with one of:

`malformed`, `unknown_site`, `stale_tick`, `request_conflict`, `already_executed`, `gap`, `unauthorized`, `invalidated`.

A repeat of a committed request uses `already_executed`. A repeat of the same ID and tuple that can no longer be authorized from the saved evidence uses `invalidated`. A new request without the necessary proof at its specified tick uses `unauthorized`. For a new `prepare`, check request-ID conflicts before gaps or proof validity, but after the tick check.

### Commit responses

The first successful effect returns `{"status":"executed","code":"executed"}`. A retry at the same or later tick returns `{"status":"already_executed","code":"already_executed"}`. Denials have the form `{"status":"denied","code":CODE}`, with one of:

`malformed`, `unknown_request`, `stale_tick`, `gap`, `authority_changed`.

Use `authority_changed` when the original prepared evidence no longer establishes the necessary approval, even if some later policy change creates a new path. Check `stale_tick` before returning `already_executed` for a committed request. A retry must never create another effect. The replies may contain only the fields documented above.

## 6. Atomicity, recovery, concurrency, and audit

Once committed, accepted batches, pending batches, prepared requests, checkpoints, clock advances, and recorded effects must survive a process crash. Use ACID storage, such as SQLite. If a process stops partway through a command, the durable state must be either the state before that command or the complete state after it. Do not leave behind partial events, partially resolved gaps, half-applied key retirement, or a recorded effect without its matching request status. Retrying the command after restart must be safe.

Multiple processes may open the same state database. Their results must match a valid serial execution order. In particular, handle a revocation racing a commit, and two processes trying to commit the same request. The authorization decision and effect write must be part of the same atomic operation.

The `audit` command emits **all and only** committed effects, sorted by lexicographic `request_id`. Write one JSON object per line, containing exactly these fields:

```json
{"request_id":"r7","site":"north","principal":"technician","asset":"pump7","action":"start","prepare_hash":"<64 lowercase hex>","commit_tick":21}
```

Do not include preparations, denied operations, or rejected policy events. Effects must survive restarts, and a request may have **at most one** effect. The verifier inspects exported effects as well as command responses. Do not put signing secrets, expected test results, or private grading code in `/app/permitgate`.

## 7. Authenticated checkpoints and safe compaction

Signed policy batches accumulate while a site operates offline. The gateway must install authenticated checkpoints and reclaim old accepted-batch payloads without losing event identities, authorization evidence, or committed effects.

### Checkpoint authority and signatures

Each site may define `checkpoint_keys` in its trusted bootstrap, as described in section 1. A checkpoint signing key is separate from every policy signing key. Key windows cover the checkpoint's `through_seq`. The gateway must not accept a checkpoint signed with a policy key or a checkpoint key whose window does not cover that sequence.

Install a checkpoint with:

```json
{"kind":"checkpoint","checkpoint":{"site":"north","through_seq":5,"anchor_hash":"<64 lowercase hex>","state_hash":"<64 lowercase hex>","key_id":"north-checkpoint","signature":"<128 lowercase hex>"}}
```

The inner `checkpoint` object contains exactly those six fields. The five fields other than `signature` form the checkpoint payload. Construct `signed = {"domain":"permitgate-checkpoint-v1", **payload}` and verify the Ed25519 signature over `SHA256(canonical_json(signed))`, not over the JSON bytes. The domain field prevents a signed checkpoint from being mistaken for a policy bundle. All hashes, signatures, names, integers, sequence windows, and unknown-field handling follow the strict conventions in sections 1 and 2. A checkpoint must have a positive `through_seq`.

The checkpoint may cover only the site's current, fully accepted prefix. Its `through_seq` must equal `next_seq - 1`; `anchor_hash` must equal the last accepted batch hash. A site with any pending batch cannot checkpoint, even when the gap begins after the claimed sequence. A checkpoint must not apply missing events or invent policy authority.

### State commitment

Recompute `state_hash` from durable local state. A valid signature is not sufficient when the reported state is wrong. The hash is `SHA256(canonical_json(PROJECTION)).hexdigest()`. `PROJECTION` is a JSON object with exactly the following fields:

- `site`: site name.
- `through_seq`: last accepted event sequence.
- `anchor_hash`: last accepted batch hash.
- `max_tick`: site's highest observed trusted tick, or `-1` before any valid request.
- `active_policy`: array of every currently active grant or delegation record, sorted by event sequence. Each row is `[seq, type, authority, principal_or_null, delegator_or_null, delegatee_or_null, asset, action, valid_from_tick, expires_at_tick]`. Expired but not revoked records remain active for this purpose.
- `retired`: lexicographically sorted array of retired policy key IDs.
- `open_requests`: array of uncommitted requests, sorted by `request_id`. Each row is `[request_id, principal, asset, action, sorted_evidence_event_sequences, prepare_hash]`. The evidence sequences are JSON integers, not an implementation-dependent serialized string.
- `effects`: array of committed effects at this site, sorted by `request_id`. Each row is `[request_id, principal, asset, action, prepare_hash, commit_tick]`.
- `accepted_ids`: array of all accepted batch identities at the site, sorted by `start_seq`. Each row is `[start_seq, end_seq, SHA256(canonical_json(FULL_SIGNED_BUNDLE)).hexdigest()]`. This includes already compacted batches and the currently un-compacted accepted suffix. `FULL_SIGNED_BUNDLE` includes `signature`.

Use the exact canonical JSON encoding from section 2. The projection defines protocol state, not a SQLite schema. Different storage layouts must produce the same hash.

### Responses, compaction, and retries

A valid, newly installed checkpoint returns `{"status":"checkpointed","code":"checkpointed"}`. A byte-identical repeat of the currently installed checkpoint at the same accepted head returns `{"status":"duplicate","code":"duplicate"}` and must not change anything. Replaying an older checkpoint after a newer policy batch has been accepted returns `rejected/stale_checkpoint`. A pending gap takes precedence over duplicate checkpoint recognition. Any rejection leaves the site unchanged.

Use `{"status":"rejected","code":CODE}` for failures, where `CODE` is one of `malformed`, `unknown_site`, `unknown_key`, `key_range`, `bad_signature`, `stale_checkpoint`, `gap`, or `state_mismatch`. `state_mismatch` means the checkpoint's signed state digest differs from the locally recomputed projection. Verify structure and signature before evaluating the claimed state. Where independent errors coexist, any applicable documented rejection code is acceptable; single-fault tests assert specific codes.

After checkpoint installation, remove the full payload of each accepted batch through `through_seq`. Keep compact identity receipts for each discarded batch so exact repeats still return `duplicate`, conflicting intervals return `overlap`, and new batches must extend the existing hash chain. Preserve all active authorization records, signing-key retirements, committed effects, and preparation evidence event IDs needed by uncommitted requests. You may remove inactive records that cannot be used again, but never remove a record still referenced by an uncommitted request. A replacement grant has a new event ID even when its contents match the old one.

Checkpoint activation, receipt creation, payload reclamation, and any policy pruning must be one crash-safe atomic transaction. A crash before the transaction commits leaves the original state usable. A crash after commit leaves the compacted state usable, with exactly the same authorization and audit results. Concurrent ingestion, preparation, commit, and checkpoint installation must have results consistent with a legal serial order. An in-progress checkpoint must never make an already committed effect disappear or change a saved `prepare_hash`.

The read-only command `{"kind":"checkpoint_status","site":"north"}` returns these exact fields:

```json
{"status":"ok","through_seq":5,"retained_from_seq":6,"accepted_batch_identities":2,"raw_batches":0,"gap":false}
```

`through_seq` is the most recently checkpointed sequence (zero before any checkpoint); `retained_from_seq` is `through_seq + 1`; `accepted_batch_identities` counts all accepted batches, compacted or not; `raw_batches` counts accepted batches whose full payloads are still retained; and `gap` reports whether any pending future batch blocks the site. For an unknown site return `denied/unknown_site`; for malformed commands return `denied/malformed`. This status query must not change the site's clock or durable state. Tests check the reported counts against delivery histories, and test authorization and replay behavior after compaction.

## 8. Workload and engineering constraints

The implementation must handle unfamiliar synthetic sites and Ed25519 keys, delegation cycles, multiple approval roots, conflicting signed histories, reordered delivery, concurrent writers, and recovery after thousands of commands.

The verifier runs multi-site histories, concurrent commits, delegation changes, checkpoint recovery, and command files with multiple operations. **Each routine `run` or `audit` process launched by the verifier has a 35-second execution limit.** The limit applies to the entire process, not to each JSONL command. A process that exceeds it fails its test case. The crash-recovery test may terminate a worker to check replay safety; its result depends on when the process exits. The overall verifier timeout is configured separately in `task.toml`.

Each site has a mandatory limit of 64 pending batches. Storage and lookups must remain practical as policy history and prepared requests grow. There is no separate graded bulk-throughput target.

The service must run without network access or runtime downloads. Store durable state on a local filesystem that supports ACID transactions. Network filesystems and malicious modification of the database files are outside the trust model.

The provided image uses Python 3.12 and `cryptography==44.0.2`. You may use any internal design that satisfies the observable requirements. The public `examples/` folder contains signed examples and basic tests, including a checkpoint example. It is not the independent verifier.

The verifier checks command responses, audit records, and durable behavior, not implementation details. In particular, an effect must have valid preparation-time evidence at commit, critical work must have distinct approval roots, and retries or reordered updates must never create a second effect or bypass an applied revocation.
