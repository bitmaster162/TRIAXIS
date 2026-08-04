# TRIAXIS CONTROL STACK v2.38-RC1 Recovery — Checkpoint Receipt Delta

## Status

```text
SPECIFICATION_STATUS: Release Candidate
IMPLEMENTATION_STATUS: Partially implemented — recovered deterministic authority path
BASELINE_EVIDENCE_COMMIT: d5d5c805591cb18d8f378e5341a461f99b0e2039
PRODUCTION_QUALIFIED: NO
EXTERNAL_ACTION_PERMISSION: NOT IMPLIED
```

## Trigger

The exact v2.37 product passed 70/70 tests but failed five checkpoint-receipt
cases in frozen protocol v3.1. Internal parent state was omitted from the public
receipt, which also lacked a self-digest and validator.

## Normative receipt contract

Active receipt contract:

```text
TRIAXIS_PROVENANCE_TRUST_CHECKPOINT_v3
```

The v2 identifier remains exported for lineage compatibility. A v3 receipt
contains:

```text
contract_id
sequence
envelope_sha256
snapshot_sha256
previous_envelope_sha256
issued_at
evaluation_tick
authority_id
key_id
authority_root_sha256
checkpoint_sha256
```

`checkpoint_sha256` is canonical SHA-256 over the exact receipt with its own
digest field blank. Genesis explicitly serializes a null parent; successors
serialize one exact 64-hex parent envelope digest.

## Verification

`validate_checkpoint_receipt()` is fail-closed, rejects unknown/missing fields,
checks exact types, chain-parent semantics and the canonical digest, and returns
`checkpoint_receipt_digest_mismatch` for mutation under an old digest.

## Non-claims

A self-verifying receipt is not a durable ledger, transparency log, external
time proof, independent certification or permission for live action.
