# TRIAXIS v3.14-RC1 — Policy Transparency Floor

## Status

Release Candidate reference implementation. Not production-qualified. No external execution permission is implied.

## Problem closed

v3.13 can resist one rolled-back or compromised Policy Head Authority, but a threshold of stale authorities and a stale client can still agree on an older, correctly signed policy. v3.14 adds a distinct transparency-witness plane that preserves the highest signed policy history independently from the policy-head quorum.

## Architecture

```text
Policy root-signed append-only history
        ↓
Independent transparency witnesses
        ↓
Fresh verifier epoch + single-use challenge
        ↓
Signed minimum-policy floor responses
        ↓
Pinned 2-of-3 witness configuration
        ↓
Exact floor must occur in local signed history
        ↓
Current policy must be at or above floor
```

## New invariants

1. **Role separation:** policy-head authorities and transparency witnesses use distinct signing purposes and identities.
2. **Head-config binding:** every floor response binds the exact Policy Head Quorum configuration digest.
3. **Freshness:** responses bind verifier identity, ephemeral verifier epoch, single-use challenge and request time.
4. **Distinct quorum:** threshold requires distinct witness IDs, log IDs, signer IDs, keys and trust domains.
5. **Append-only containment:** a floor is valid only when the exact version/digest exists in the verified local signed history.
6. **No regression:** current policy version must be greater than or equal to the witnessed floor.
7. **Fail closed:** fork, split view, stale response, replay, config substitution or witness equivocation blocks acceptance.

## Added contracts

- `TRIAXIS_POLICY_TRANSPARENCY_FLOOR_RESPONSE_v1`
- `TRIAXIS_POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_v1`
- signing purpose `POLICY_TRANSPARENCY_WITNESS`

## Explicit boundary

Trust-domain labels are administrative assertions, not proof of physical separation. A threshold compromise or coordinated rollback of both policy-head authorities and transparency witnesses remains outside this local reference implementation.

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
production_qualified=false
```
