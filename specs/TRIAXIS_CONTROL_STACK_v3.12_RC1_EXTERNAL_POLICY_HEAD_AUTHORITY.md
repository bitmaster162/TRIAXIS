# TRIAXIS v3.12-RC1 — External Policy Head Authority

## Status

Release Candidate reference implementation. Not production-qualified. No deployment or external execution permission is implied.

## Problem closed

TRIAXIS v3.11 stores a root-signed, monotonic anchor-quorum policy locally. Restoring the entire local policy database can resurrect an older, lower-threshold policy because the restored database is internally self-consistent.

v3.12 moves policy-head freshness outside the local failure domain.

## Trust flow

```text
root-signed quorum policy
        ↓
external Policy Head Authority installs monotonic policy history
        ↓
verifier creates ephemeral epoch and single-use random challenge
        ↓
authority signs exact current policy version + digest + challenge
        ↓
client verifies authority identity, trust domain, signature and freshness
        ↓
local policy version/digest must match external head exactly
        ↓
optional operator minimum version/digest floor
        ↓
challenge consumed only after all checks pass
```

## New contracts and components

- `TRIAXIS_POLICY_HEAD_AUTHORITY_RESPONSE_v1`
- `POLICY_HEAD_AUTHORITY` Ed25519 signing purpose
- `SQLitePolicyHeadAuthorityService`
- `load_policy_with_external_head`
- `PolicyHeadHTTPApplication`
- `/healthz`
- `/v1/head/challenge`
- admin-gated `/v1/policies/install`
- systemd and container reference deployment templates

## Invariants

1. A local policy cannot certify its own freshness.
2. Policy-head responses bind authority, policy ID, exact version, exact digest, verifier ID, verifier epoch, challenge, request time and expiry.
3. A challenge is consumed only after signature, subject, freshness, local-head and operator-floor verification.
4. Local version lower than external head is rollback.
5. Same version with another digest is fork.
6. Local version higher than authority head is stale authority.
7. Administrative policy installation is disabled unless an explicit bearer-token digest is configured.
8. Private signing keys are process inputs and are not serialized by the reference service.

## Explicit boundaries

v3.12 does not prove:

- resistance to rollback or compromise of the external authority itself;
- independent physical administration;
- HSM/KMS key custody;
- trusted external time;
- transparency-log consistency;
- multi-authority quorum;
- TLS or reverse-proxy authentication;
- complete mediation at a production tool boundary.

## Safety state

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
production_qualified=false
```
