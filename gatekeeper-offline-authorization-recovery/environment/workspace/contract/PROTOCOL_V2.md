# Gatekeeper — Signed-record protocol and command contract

**Status:** Binding contract for protocol schema 2. Incompatible earlier record formats are not accepted. The verifier assesses only requirements specified here or in `instruction.md`.

## 1. Threat model, time, and durable state

Each state directory belongs to one tenant. A trusted local driver supplies a nonnegative logical `--tick T` rather than wall-clock time. Root signing and request keys are synthetic Ed25519 keys. An attacker may submit malformed or forged records, delay or reorder authentic records, replay requests, restore an older `cache/`, and terminate or restart processes. The attacker **cannot** roll back or deliberately rewrite `protected/`, forge an uncompromised key, alter the trusted tick source, access a real actuator or use the network.

A retired root key may be compromised *after* its authenticated rotation, but an already committed historical checkpoint and its issuance commitment remain immutable within `protected/`. A new root grant backdated under that retired key is invalid unless its digest was in the already signed issuance batch. This is a bounded guarantee: if the root is compromised before the gateway ever authenticates its historical chain, it may be impossible to distinguish forged historical checkpoints until contrary authenticated evidence arrives. An offline gateway cannot detect unseen remote revocations.

Trusted state includes genesis configuration, verified authority history, current and historical root keys, cumulative revocations, authenticated grants and conflicts, the highest protected tick, quarantine status, and the append-only logical ledger of successful effects and replay receipts. `cache/` contains only rebuildable indexes; after cache loss or rollback correctness is unchanged. A fresh process never derives trusted history exclusively from cache.

## 2. JSON and signatures

All input files contain a single UTF-8 JSON object, maximum 256 KiB. Reject duplicate keys, unknown keys for a given record kind, non-finite values, booleans standing for integers, and unsigned integer overflows. Schema and counters use integers in `[0, 2^63-1]`. Grant IDs, holders, root key IDs, request IDs and tenant IDs are 1–128 ASCII bytes matching `[A-Za-z0-9][A-Za-z0-9:._-]*`. A delegated `issuer_key` has the special form `holder:` followed by an admissible grant ID and therefore may be up to 135 ASCII bytes. JSON fields with `null` are allowed only where explicitly shown. Public keys and signatures use canonical RFC 4648 standard Base64 with padding and lengths 32 and 64 bytes respectively. A malformed input is a command error, not an authenticated conflict.

Canonical bytes `C(x)` are `json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')` on strictly validated values. Every Ed25519 signature authenticates `b'GATEKEEPER/V2\x00' + kind.encode('ascii') + b'\x00' + C(body)`, where `body` is the record without `signature` (or without `old_signature` and `new_signature` for rotations). Record digest `D(r)=SHA256(C(r)).hexdigest()` includes signature fields. A root `grant` is signed by the historically authoritative root key; a delegated grant is signed by its parent's holder key. An `issuance_bundle` is an unsigned transport envelope; the signed grant, checkpoint and Merkle proof provide its authenticity.

Path syntax: `/` or slash-separated nonempty segments `[A-Za-z0-9_-]+`, total length <=1024. A prefix matches full path segments only. Actions are sorted, unique nonempty subsets of `inspect`, `calibrate`, `restart`. Validity interval is `[not_before, expires)`.

## 3. Trust / init

Trust file:
```
{"schema":2,"tenant":"north","offline_window_ticks":30,
 "genesis_root_key_id":"root-a","genesis_root_public_key":"<base64 Ed25519 key>"}
```
The trust object must use the identifier, integer and canonical 32-byte Ed25519 public-key rules in §2; `offline_window_ticks` is an integer in `[1, 2^63-1]`. `init` atomically persists this immutable trust object. Repeating `init` with the same bytes-as-data trust object is idempotent; different trust configuration is a command error. Genesis authority: `seq=0`, `last_digest` is 64 hex zeroes, `last_issued_tick=0`, `last_checkpoint_tick=null`, `highest_protected_tick=0`, root key `root-a`, no revocations or applied requests. **No new effect before a verified checkpoint.**

## 4. Authenticated authority history

Accepted authority records are `checkpoint` and `rotate`. Both include `kind`, `tenant`, `seq`, `previous_digest`, `issued_tick`; `seq=parent.seq+1`, previous digest is `D(parent)` (genesis zero digest), and `issued_tick >= parent.issued_tick`. Every record is verified under the root key determined by its *authenticated parent*; do not trust the `signer` string alone.

Checkpoint:
```
{"kind":"checkpoint","tenant":"north","seq":1,
 "previous_digest":"<64 lowercase hex>","issued_tick":100,
 "revoked_ids":["old-grant"],"issuance_count":2,
 "issuance_root":"<64 lowercase hex>",
 "signer":"root-a","signature":"<base64>"}
```
`revoked_ids` is the **delta newly revoked at this checkpoint**, sorted, unique; the protected revocation set is the union of all applied deltas. No signed operation unrevoke exists. A checkpoint advances `last_checkpoint_tick=issued_tick`. It commits exactly one batch of root-grant digests with a Merkle root defined below. `issuance_count=0` requires the empty-tree hash. A checkpoint may revoke a grant and commit other root grants in the same record; the same transaction's effect decisions see the entire checkpoint or none of it.

Rotate:
```
{"kind":"rotate","tenant":"north","seq":2,
 "previous_digest":"<64 lowercase hex>","issued_tick":101,
 "old_signer":"root-a","new_signer":"root-b",
 "new_root_public_key":"<base64>",
 "old_signature":"<base64>","new_signature":"<base64>"}
```
`old_signature` verifies using the parent's active root; `new_signature` under the supplied new root. Signer IDs must differ. After a committed rotation, new checkpoints and new root-grant batches use the new root. Rotation alone does **not** renew freshness and does **not** retroactively invalidate preexisting grants or proofs.

## 5. Merkle-anchored root-grant issuance

A root grant has the following exact schema (example values):
```
{"kind":"grant","tenant":"north","grant_id":"g0",
 "parent_id":null,"issuer_key":"root-a","issued_seq":1,
 "holder":"technician:lead","holder_key":"<base64>",
 "resource_prefix":"/units/pump","actions":["inspect","restart"],
 "not_before":100,"expires":180,"delegable":true,
 "remaining_depth":2,"signature":"<base64>"}
```
Root grants are **not accepted on signature alone**. The signer must be the active root at the grant's `issued_seq`, which MUST identify a committed checkpoint (not a rotation). The grant's digest must belong to that checkpoint's committed issuance batch, as proved by an inclusion path. Also require `not_before >= checkpoint.issued_tick`, `expires>not_before`. The `issued_seq` field alone is not evidence of issuance.

The checkpoint producer constructs its issuance tree from its newly issued root-grant records, sorted ascending by `grant_id` (ties prohibited by the issuer). For one grant `r`, leaf hash `L(r)=SHA256(0x00 || C(r))` (where `r` includes the signature). Pad the leaf sequence to the smallest power of two >= `issuance_count` using `P=SHA256(b'GATEKEEPER/V2-PAD')` as a padding leaf. Each internal node is `SHA256(0x01 || left32 || right32)`. For no grants the root is `SHA256(b'GATEKEEPER/V2-EMPTY')`. The root is transmitted as lowercase 64-hex `issuance_root`. These formulas are a **task-local fixed-tree variant**, not a claim of bit-for-bit compatibility with RFC 9162's unbalanced tree.

A root grant is delivered in an issuance bundle:
```
{"kind":"issuance_bundle","grant":{...signed root grant...},
 "proof":{"checkpoint_seq":1,"index":0,"count":2,
          "siblings":["<64 lowercase hex>"]}}
```
The index must satisfy `0 <= index < count`, count equals the trusted checkpoint `issuance_count`, checkpoint sequence equals `grant.issued_seq`, and `siblings` contains exactly `log2(next_power_of_two(count))` hashes in bottom-up order. Starting at `L(grant)`, at level `j` combine as `(node,sibling)` if bit `j` of index is zero, else `(sibling,node)`. A computed root identical to the checkpoint's root plus a correct historical root signature authenticates the root grant. There are no accepted membership proofs for empty batches. If the checkpoint is missing, buffer the envelope **without making it authoritative**; do not reject it as an invalid signature merely because the historical root key is not yet known. Invalid proofs at an available checkpoint are rejected. The verifier may generate new root batches and inclusion proofs independently.

A signed holder-to-holder delegated grant uses the same `grant` schema, but `parent_id` is a nonnull grant ID, `issuer_key='holder:'+parent_id`, and no issuance proof is required. It is valid only with an authenticated parent, a valid signature by that parent's holder key, `issued_seq >= parent.issued_seq`, `issued_seq <= current committed authority seq`, and no cycle. Its actions, prefix and validity interval must be subsets of the parent's; depth strictly decreases; `remaining_depth=0` implies `delegable=false`. A chain contains 1–8 grants including root and leaf. Parent grant invalidity, conflict or revocation invalidates descendants. Independently **authenticated** distinct records reusing an ID conflict; an unauthenticated forged ID collision must not poison valid grants. Earlier accepted effects are not retroactively undone.

## 6. Causal ingestion, forks, quarantine

`ingest` may receive authentic records in *any* order. Persist non-authenticated candidates only as **pending untrusted data** until a verified parent becomes available; unknown signer claims do not confer authority. When a parent becomes known, validate its child's signature/key relation, seq, digest and issued tick, then recursively reconcile newly connectable descendants. Invalid pending candidates are rejected and removed from pending. A forged pending record cannot independently cause quarantine, suppress authorization, change the clock, change revocations or renew freshness.

Two **distinct, individually authenticated authority children** with the same authenticated `(tenant,parent_digest,parent.seq+1)` constitute equivocation. This holds even if one child was already applied and a second arrives later. The gateway persists permanent `quarantined=true` and any future **new effects** yield `DEFER/QUARANTINED`; existing committed effects remain in the ledger and identical prior successful requests can still receive `ALLOW/DUPLICATE` receipts. No automatic branch selection, reset or recovery of quarantine within the same state directory. If a previously applied record is simply repeated verbatim, it is a harmless duplicate. A conflicting but unauthenticated record is rejected without quarantine.

A disconnected candidate for seq `N` is not evidence that seq `N-1` exists. Therefore **unverified pending records must not force `AUTHORITY_GAP` denial**. New effects are governed by the *last verified contiguous authority tip*, protected clock, checkpoint freshness and grant proofs. This bounds how long the gateway can act on its latest verified checkpoint; it does not provide knowledge of revocations that have not arrived. Historical parent keys must remain available to evaluate a delayed authenticated fork after rotation.

## 7. Requests, decisions and freshness

Signed request:
```
{"kind":"request","tenant":"north","request_id":"req-1",
 "holder":"technician:field","resource":"/units/pump/a",
 "action":"inspect","chain":["g0","g1"],
 "signature":"<base64>"}
```
The request signature verifies with the leaf's holder key. The chain is an exact root-to-leaf ancestry sequence whose terminal holder equals request `holder`. Every ancestor must allow resource and action, and be valid at the supplied tick. No wildcard resource matching.

`decide` writes exactly one JSON object with fields `request_id` (string), `decision` (`ALLOW|DENY|DEFER`), `reason` (enum below), `applied` (boolean), `checkpoint_seq` (integer or null), and `grant_path` (list of grant IDs, possibly empty). No extra fields. A successful first decision commits a simulated effect record plus a receipt of the full canonical signed request **within the same durable transaction**. No real equipment is controlled. A read-only `effects` command exposes the committed mock effect ledger to independent verification; the ledger records simulated operations; it does not represent a score supplied by the implementation.

Reason / decision priority for well-formed requests:
1. Prior successful identical canonical signed request `request_id`: `ALLOW/DUPLICATE`, `applied=false`, replay the original checkpoint_seq/path, never apply a second effect; a reused successful ID with changed content: `DENY/REQUEST_ID_REUSE`.
2. Permanently quarantined: `DEFER/QUARANTINED`.
3. `--tick` below stored `highest_protected_tick` or latest committed `last_issued_tick`: `DEFER/TIME_ROLLBACK`.
4. No committed checkpoint: `DEFER/NO_CHECKPOINT`; `tick > last_checkpoint_tick + offline_window_ticks`: `DEFER/STALE_CHECKPOINT` (checked overflow-free).
5. Unauthorized request: in order `CROSS_TENANT`, `BAD_SIGNATURE`, `INVALID_CHAIN`, `REVOKED`, `OUT_OF_SCOPE`, `NOT_YET_VALID`, `EXPIRED`, each `DENY`, with `applied=false`. When ancestry cannot yet be authenticated because **an actually ingested, pending** issuance bundle or child grant is part of the requested chain, return `DEFER/PENDING_GRANT`; a completely unknown, never-ingested grant ID is `DENY/INVALID_CHAIN`. If the requested leaf is authenticated but the request signature is invalid, return `DENY/BAD_SIGNATURE`; if no authenticated leaf key exists and nothing is pending, return `DENY/INVALID_CHAIN`.
6. Authorized and uncommitted: `ALLOW/AUTHORIZED`, `applied=true`, plus checkpoint seq and grant path used.

All well-formed `decide` calls with tick not below the already stored maximum must atomically advance `highest_protected_tick` to max(old,tick), **including DENY/DEFER and duplicate acknowledgements**. A decision at a lower tick can acknowledge a prior identical effect but cannot authorize a new one. Denied and deferred `request_id`s are not permanently reserved. A previously allowed request with the same ID but different content never gets a second effect. A failed parse/schema check returns a command error and does not advance the protected tick. The test driver supplies trusted ticks; direct manipulation of that time source is outside the threat model.

## 8. Process and crash semantics

`init`, `ingest`, `decide`, `status`, and read-only `effects` may be invoked by multiple independent local processes. Every successful command must be **linearizable** to a single serial order consistent with process-call happens-before. `decide` and authority commits race: an allowed effect must see all revocations committed *before* its linearization point, and may precede or follow a genuinely concurrent revocation, but cannot read the old revocation set and commit the effect after a later conflicting state without serializable coordination.

An operation may be interrupted before or after durable commit. On restart, all committed updates must be present; no incomplete update may be visible as a committed security transition. A successful effect and its signed request receipt share one commit boundary. If a crash occurs after effect commit but before stdout, retry returns DUPLICATE and has no second effect. If a crash happens before commit, a valid retry may apply once (subject to any later revocation/time conditions). `cache/` rollback must not alter decisions or duplicate state; rebuilding from `protected/` is permitted.

For recoverable transaction interruption, the recovered committed prefix is authoritative. An irrecoverably corrupt `protected/` database or missing necessary protected history causes a command error (`STATE_CORRUPT`/`STATE_MISSING`) and **no effect**, not a reset. Tests may use `SIGKILL` during or between API calls, or simulate lost stdout after successful commit; they must not require an undocumented debug hook. The verifier may not expect a specific outcome if it kills a process *during* an indivisible commit; it must accept either legal pre- or post-commit state and require correctness after replay. Crash diagnostics may be provided, but the verifier must not require an undocumented implementation-specific hook.

## 9. CLI and schemas

Commands are invoked from `/workspace`:
```
python3 -m gatekeeper init   --state DIR --trust TRUST_JSON
python3 -m gatekeeper ingest --state DIR --file RECORD_JSON
python3 -m gatekeeper decide --state DIR --file REQUEST_JSON --tick N
python3 -m gatekeeper status --state DIR
python3 -m gatekeeper effects --state DIR --after N --limit M
```
All commands except errors write exactly one JSON object on stdout. `init` -> `{"state":"INITIALIZED|UNCHANGED","tenant":"<tenant>"}`. `ingest` -> `{"record_digest":"<64hex>","state":"APPLIED|PENDING|DUPLICATE|REJECTED|QUARANTINED","reason":null|"<enum>","seq":null|integer}`. Allowed ingest reasons: `MISSING_PARENT`, `MISSING_CHECKPOINT`, `MISSING_GRANT_PARENT`, `BAD_SIGNATURE`, `BAD_PROOF`, `BAD_LINK`, `CONFLICT`, `WRONG_TENANT`; `reason=null` for APPLIED/DUPLICATE. `QUARANTINED` reports `reason="CONFLICT"`. `record_digest` for `issuance_bundle` is `D(grant)`, otherwise `D(record)`; on rejected *well-formed* envelopes digest is still computed. `status` -> `{"tenant":string,"seq":integer,"last_digest":string,"last_issued_tick":integer,"last_checkpoint_tick":null|integer,"highest_protected_tick":integer,"quarantined":boolean,"pending_authority_count":integer,"pending_grant_count":integer,"authenticated_grant_count":integer,"applied_request_count":integer}`. `effects` is read-only and returns `{"effects":[{"index":integer,"request_id":string,"request_digest":string,"tick":integer,"authority_seq":integer,"checkpoint_seq":integer,"grant_path":[string,...]},...],"next_after":integer}`. The effect `index` is a dense monotonically increasing integer starting at 1 in commit order; `request_digest=D(request)` includes signature fields. Effect rows are sorted by increasing index. `--after` defaults to 0 and selects rows with `index>after`; `--limit` defaults to 100 and is an integer from 1 to 1000. `next_after` is the index of the final returned row, or the incoming `after` if none. Effects never disappear across restarts or cache rollback. An implementation may store receipt and effect in the same transactional row, provided the observable semantics are identical. Output key order is not significant.

Malformed JSON/schema, inaccessible files, invalid `--tick`, missing state, and irrecoverably corrupt protected state exit nonzero; no stdout; a JSON error `{"error":"INVALID_INPUT|IO_ERROR|STATE_MISSING|STATE_CORRUPT|INIT_CONFLICT"}` is emitted on stderr. This error policy is separate from a *well-formed* signed record with invalid signature, which yields `ingest REJECTED/BAD_SIGNATURE` without mutating trusted state. If an input is syntactically well-formed but a signature or membership proof is invalid, it is rejected semantically. Unknown historical signers before their parent has arrived remain pending until verifiable. Do not claim to know a future record is authentic without its parent.

## 10. Capacity, performance and test boundaries

Every CLI process starts and exits; correct operation cannot depend on an in-memory singleton surviving restart. The implementation must remain correct across repeated authority updates, grant issuance, authorization requests, process restarts, and concurrent calls. No separate throughput benchmark or bulk-record target is scored. The verifier imposes per-command safety timeouts (normally 9 seconds, and up to 20 seconds in process-recovery or concurrency checks) to detect hangs; these are not graded performance tiers. Correctness tests must not rely on wall-clock races or a particular thread schedule; concurrent outcomes are checked against legal serial histories. Network access and real credentials are prohibited. The verifier must accept any implementation that satisfies the documented interfaces and state guarantees, without requiring a particular library or internal design. Private test material must remain outside the candidate workspace.
