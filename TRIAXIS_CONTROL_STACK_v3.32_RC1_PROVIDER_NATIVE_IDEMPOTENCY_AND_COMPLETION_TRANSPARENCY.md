# TRIAXIS v3.32-RC1 — Provider-Native Idempotency Contract and Completion Transparency Quorum

## Status

- Specification: Release Candidate
- Implementation: executable local reference
- Production-qualified: no
- Real provider control-plane integration: not established
- Physical multi-host independence: not established
- Administrative independence: not established
- Physical WORM / object-lock conformance: not established
- KMS/HSM or hardware monotonicity: not established
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.31 closes the missing-witness availability gap and introduces a logical
content-addressed immutable completion anchor. It still cannot prove two
properties that belong outside the caller's administrative domain:

1. the external provider durably claimed the stable `effect_id` before causing
   the effect; and
2. the latest completion-anchor head is remembered by independently pinned
   transparency checkpoints.

v3.32 defines those two contracts and provides executable references without
relabelling local filesystem or SQLite state as physical independence.

## Provider-native durable idempotency contract

The provider namespace MUST:

- validate the pinned provider policy as current at the evaluation tick, not merely match a historical policy digest;

- use the exact stable `effect_id` as the idempotency key;
- bind one payload digest to that key for its lifetime;
- persist `IN_FLIGHT` before the external side effect is attempted;
- treat `IN_FLIGHT`, `UNKNOWN` and `COMPLETED` as retry-blocking;
- permit a new generation only after authoritative `NO_EFFECT`;
- preserve a signed append-only transition chain;
- issue fresh challenge-bound signed status and signed head objects;
- expose no caller-controlled mechanism that makes blocking states permissive;
- grant no TRIAXIS execution authority.

The bundled `FilesystemProviderNativeIdempotencyReference` is a protocol
reference. It is not evidence that any real provider honors the contract.

## Completion transparency quorum

The transparency layer consists of an operator-pinned threshold set. Each
member stores the highest accepted signed immutable-anchor head and refuses:

- lower sequence rollback;
- same-sequence fork;
- signer, key, service or trust-domain substitution;
- stale or replayed verifier challenges.

The verifier requires a threshold statement exactly matching the current local
anchor head. The response inner `issued_at` / `valid_until` window MUST exactly
match the signed envelope window; split freshness semantics are rejected. A valid minority reporting a strictly newer head or a
same-sequence fork is a hard veto; an old majority cannot erase that evidence.

## Cumulative decision rule

A high-risk external effect may pass the v3.32 extension only when:

1. the full v3.31 in-process guard returned `PASS`;
2. the provider-native status is fresh and is exactly `ABSENT` or `NO_EFFECT`;
3. the completion transparency quorum matches the current signed immutable
   anchor head; and
4. separate action authorization remains valid.

`GOOD REASONING != AUTHORIZED ACTION` remains invariant. Evidence services do
not mint, broaden or replace authorization.

## Failure semantics

Return `BLOCK` for any of the following:

- provider-native status missing, stale, replayed or identity-substituted;
- payload conflict under an existing `effect_id`;
- provider-native state `IN_FLIGHT`, `UNKNOWN` or `COMPLETED`;
- transparency threshold not reached;
- valid transparency minority reports a newer head;
- valid transparency member reports a same-sequence fork;
- quorum configuration substitution;
- challenge or verifier-epoch mismatch;
- any attempt to claim physical independence from this local reference.

## Terminal local-reference boundary

v3.32 is the last permitted same-host/local-reference feature release in this
line. A successor version MUST NOT claim stronger external durability merely by
adding another local file, SQLite database, process, key or loopback service.

The next release number is gated on external evidence defined in
`TRIAXIS_PHYSICAL_EVIDENCE_GATE_v1.md`.

## Claim boundary

A v3.32 PASS means only that the frozen code, tests, schemas and local process
references satisfy the specified protocol and negative cases. It does not
establish provider-native behavior at a real vendor, independent
administration, physical WORM, external transparency publication, protected
monotonic memory, trusted time, mTLS, production availability, capacity,
exactly-once execution or independent certification.
