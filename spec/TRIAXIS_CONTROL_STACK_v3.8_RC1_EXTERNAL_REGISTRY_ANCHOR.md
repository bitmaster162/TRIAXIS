# TRIAXIS Control Stack v3.8-RC1 — External Registry Anchor

## Status

Release Candidate. Not production-qualified. External execution permission is not implied.

## Defect closed

v3.7 rejected rollback inside one persistent registry store, but restoration of an older copy of the entire SQLite database erased the newer head and revived revoked keys.

## New boundary

v3.8 requires a separately signed external head witness before operational keys are loaded.

The witness binds:

- anchor identity;
- registry identity;
- exact current sequence;
- exact current snapshot SHA-256;
- issuance and expiry window.

The anchor signing key has the dedicated `TRUST_REGISTRY_ANCHOR` purpose and is held outside the operational registry.

## Load rule

The local registry head must match the external witness exactly:

- local sequence below witness → `local_registry_rollback`;
- local sequence above witness → `stale_external_anchor`;
- equal sequence with another digest → `local_registry_fork`;
- missing local state → block;
- invalid, expired, forged or wrong-domain witness → block.

Only after exact agreement may the operational `TrustKeyRegistry` be loaded.

## Remaining boundary

A previously issued but still-valid anchor witness can be replayed together with a matching old database unless the witness is obtained through a freshness protocol. Challenge binding or an authoritative online minimum sequence is the next required evidence class.
