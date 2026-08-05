# TRIAXIS Control Stack v3.11-RC1 — Authenticated Quorum Policy

## Status

Release Candidate. Not production-qualified. External execution permission is not implied.

## Defect closed

v3.10 enforced quorum mechanics but accepted the anchor-authority map and threshold as caller inputs. A caller could lower an intended threshold or substitute another set of already trusted anchor keys.

## New policy boundary

v3.11 introduces `TRIAXIS_ANCHOR_QUORUM_POLICY_v1`, signed by a separately pinned quorum-policy root. The policy binds:

- policy identity and version;
- previous policy digest;
- registry and anchor-set identity;
- exact threshold;
- exact anchor ID, signer ID, key ID and trust domain for every member;
- validity window.

The local policy store accepts only root-signed genesis and exact sequential successors. It rejects rollback, forks, version gaps and parent substitution.

Every quorum member witness binds the exact current policy SHA-256. The registry loader no longer accepts a threshold or authority map from the caller; both are derived from the verified current policy.

## Remaining boundaries

- restoring the entire quorum-policy SQLite database can restore an older signed policy;
- the pinned policy-root registry and code remain local roots of trust;
- compromise of the policy root or a configured anchor threshold is not solved;
- organizational independence of trust domains remains an administrative claim;
- no external policy-head witness, transparency log or HSM-backed production service is implemented.
