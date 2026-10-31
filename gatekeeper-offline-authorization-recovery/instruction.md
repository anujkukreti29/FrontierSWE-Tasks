# Gatekeeper — Offline Authorization and Recovery

A remote maintenance gateway must authorize simulated equipment operations while disconnected from its central authority. It receives signed checkpoints, root-key rotations, and grants in arbitrary order. Revocations may race with incoming requests; processes may be terminated and restarted; an outdated local cache may be restored.

Complete the `gatekeeper` package so that each authorized request produces **one durable simulated effect** based on a consistent, authenticated authority history. A retry must not apply the effect again. Invalid evidence must not gain authority, and valid requests must remain serviceable whenever the trusted evidence and freshness limits permit them.

## Workspace and commands

The starting code is in `/workspace/gatekeeper/`. The binding contract, including all record and response schemas, is `/workspace/contract/PROTOCOL_V2.md`. Public diagnostics are under `/workspace/tools/`.

Implement these commands:

```text
python3 -m gatekeeper init    --state DIR --trust TRUST_JSON
python3 -m gatekeeper ingest --state DIR --file RECORD_JSON
python3 -m gatekeeper decide --state DIR --file REQUEST_JSON --tick N
python3 -m gatekeeper status --state DIR
python3 -m gatekeeper effects --state DIR --after N --limit M
```

The gateway handles only synthetic credentials and simulated effects. It must not access external systems or physical equipment. Commands may run in separate, concurrent local processes. Authoritative state belongs in `protected/`; optional `cache/` contents are disposable and must not affect correctness when removed or restored from an older copy.

## Required behavior

1. **Validate inputs and signatures.** Enforce the contract's exact JSON schemas, canonical encoding, Ed25519 signatures, and domain separation. Malformed input must not mutate trusted state.
2. **Verify issuance and delegation.** Authenticate each root grant against the historical signing key and its checkpoint's Merkle issuance commitment. Validate delegated grants through their parent holders, including permissions, resource prefixes, validity windows, and delegation depth.
3. **Reconcile authority records.** Verify checkpoints and dual-signed rotations through authenticated parent records, regardless of arrival order. Hold unresolved descendants as untrusted pending data. Quarantine genuinely authenticated forks, but not forged conflicts.
4. **Authorize against current trusted state.** Check the complete grant chain and cumulative revocations. Match full path segments. Calculate freshness from the latest authenticated checkpoint rather than from a key rotation.
5. **Protect decision time.** Persist the highest accepted tick for well-formed decisions, including denials and deferrals. Invalid inputs must not advance it, and a restarted process must not authorize a new effect at a rolled-back tick.
6. **Commit ordered effects durably.** Serialize decisions with authority updates across processes. Commit each applied effect and its replay receipt atomically. Provide the append-only logical ledger through `effects`.

Use the output schemas, decision and error precedence, and boundary rules in `PROTOCOL_V2.md` exactly. Denying every request is incorrect: eligible requests within the authenticated freshness window must succeed.

## Failure handling

The implementation must handle delayed ancestors, historical keys, multiple grants per issuance batch, authenticated and forged conflicts, multi-generation delegation, ancestor revocation, resource-path boundaries, expiry and freshness limits, request-ID reuse, concurrent requests, abrupt termination, and stale-cache restoration. Integer ranges and error codes are specified in the binding contract.

An interrupted transaction may leave either its fully committed or fully uncommitted outcome. Once restarted, the service must preserve all committed updates, reveal no partial transition as committed, and never repeat an effect. The verifier does not require a special crash hook or a particular database implementation.

Irrecoverably corrupt authoritative storage must produce the specified command error and **must not** trigger automatic reinitialization.

## Local diagnostics

```sh
python3 /workspace/tools/public_selfcheck.py
python3 /workspace/tools/starter_smoke.py
```

These check the starter and public cryptographic helpers, not the completed authorization engine. Initialization, input parsing, and response formatting do not by themselves earn credit. Partial credit requires at least one working end-to-end authorization and effect scenario. No separate throughput benchmark is scored.

**Agent timeout: 72,000 seconds (20 hours).** This is the available execution budget, not a required runtime.
