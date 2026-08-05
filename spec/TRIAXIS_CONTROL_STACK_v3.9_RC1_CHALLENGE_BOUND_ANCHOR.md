# TRIAXIS Control Stack v3.9-RC1 — Challenge-Bound Registry Anchor

## Status

Release Candidate. Not production-qualified. External execution permission is not implied.

## Defect closed

v3.8 detected whole-registry rollback only when the verifier received the newest external witness. An attacker could restore an old registry database and replay the matching old, still-valid witness.

## New boundary

v3.9 requires a verifier-generated, unpredictable, single-use challenge for every registry-head query. The signed anchor response binds:

- anchor identity;
- registry identity;
- exact sequence and snapshot SHA-256;
- verifier identity;
- SHA-256 of the verifier challenge;
- exact challenge issuance time;
- response issuance and expiry.

The verifier keeps challenges in a durable SQLite ledger. A challenge is consumed only after signature validation, freshness validation, exact registry-head matching, and successful registry materialization.

## Mandatory rules

1. A timestamp-only witness is not sufficient for freshness.
2. A response for one challenge cannot answer another challenge.
3. A consumed challenge cannot be reused.
4. A forged or malformed response does not consume a valid challenge.
5. The anchor response must be no older than the configured response-age limit.
6. Registry sequence and digest must match exactly before operational keys are returned.

## Remaining boundaries

- rollback of the challenge-ledger database can restore a consumed challenge;
- one trusted anchor may equivocate by signing different heads for different verifiers;
- external trusted time and anchor availability are operational dependencies;
- no threshold anchor quorum or transparency log is implemented;
- hostile local-administrator resistance is not established.
