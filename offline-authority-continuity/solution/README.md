# Reference implementation

`solve.sh` installs `reference/gateway.py` and `reference/cli.py` into `/app/permitgate` for Oracle evaluation.

The reference keeps accepted and pending policy batches, active grants and delegations, key retirement, prepared requests, signed checkpoints, and committed effects in SQLite. Transactions protect policy application, checkpoint installation, and effect commits. A process crash must not leave partially applied state.

Checkpoint signatures use separate trust keys. After installation, compact batch-identity receipts retain duplicate and overlap detection without keeping the original accepted-batch payloads. Open requests retain their preparation evidence, and committed effects remain available through `audit`.

This implementation is not a required database design. `instruction.md` defines the contract; the independent verifier checks external behavior.

## Provenance

The reference implementation received substantial AI assistance, including checkpoint development. No independent human-authorship claim is made. Submission eligibility must be assessed against the actual contributor record and client rules.
