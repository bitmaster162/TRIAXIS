# TRIAXIS RHE — Review Adjudication R1

Status: `DESIGN/TEST LANE ONLY`

Branch: `product/rhe-execution-boundary-canary-r1`

Base: `main @ ae280d905c63e4ba0bcadb4633f01a1fb9657920`

## Decision

The active RHE product lane is the existing TRIAXIS execution boundary:

`workload identity -> authorize_action -> PEP -> Cedar -> authorization token -> identity-aware SQLite ledger -> PREPARED`

The first RHE canary stops at `PREPARED` and performs no external execution effect.

## External-review adjudication

### Private GitHub repository

`bitmaster162/TRIAXIS` is private. A public-web 404 is not evidence that the repository is absent. The coordinator has authenticated repository access and this branch/PR is bound to the live repository.

### Historical FINAL89/V036/JIT lane

The previous Object-Lock/RFC3161 signer canary is historical and is **not authority for the current execution-boundary canary**.

Current canary does not depend on:
- V036 object existence or narrative lineage;
- successor signer secret;
- Secrets Manager consuming marker;
- JIT IAM attach/detach;
- RFC3161;
- S3 Object Lock.

The previously prepared JIT-stage packet was also observed by independent review to be incomplete for standalone preflight because the required local design/schema assets were not bundled. Do not repair or execute that obsolete packet as part of this lane.

Classification:

`OLD_RHE_JIT_CANARY=SUPERSEDED_NOT_TO_RUN`

### Key custody / KMS

The recommendation to replace raw private-key retrieval with an asymmetric managed signer is accepted for a future signed/effectful tier.

Preferred future direction:
- asymmetric KMS/HSM-backed signing;
- private key never leaves managed key service;
- CloudTrail-observable Sign API usage;
- least-privilege signer role;
- no `GetSecretValue` for signing material.

This is intentionally **not added to R1**, because R1 has no signer and no external effect.

### Consuming marker

Accepted finding: a consuming Secrets Manager marker is excessive for normal repeatable authorization runtime and creates avoidable self-DoS/release-burn semantics.

R1 uses existing single-use/idempotent ledger semantics instead:
- same token + same workload => same PREPARED row;
- conflicting token/nonce or different workload => reject;
- no second external effect exists in R1.

### RFC3161 / Object Lock

Removed from normal R1 hot path.

Future policy:
- R0/R1: no TSA/WORM requirement by default;
- R2 irreversible/external commit: optional/required by action class;
- R3 capital/trading/security-admin: strongest evidence tier, separately designed and owner-gated.

### JIT IAM

For this R1 zero-external-effect test lane, per-event cloud IAM mutation is not required.

JIT/temporary credentials remain a valid control only when a future runtime actually needs cloud/provider permissions.

### Owner approval

Human approval is risk-tiered, not universal ceremony.

The current canary is a test of authorization machinery and stops before external execution. A future effectful authorization must define its human-approval requirement explicitly by risk class.

## Current R1 acceptance target

Positive path:

`verified workload -> valid principal/task/action/resource -> verified PEP ALLOW -> authorization token -> identity-aware ledger PREPARED -> STOP`

Negative/control paths:
- invalid delegation;
- invalid task;
- unauthorized capability;
- wrong resource;
- claimed workload identity mismatch;
- unverified workload identity;
- PDP exception/error;
- cross-workload token replay.

Idempotency control:
- same token + same verified workload may return the same PREPARED row;
- it must not create a second row or external effect.

## Frozen safety invariants

- `external_execution=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `AWS_effects=0`
- `SecretsManager_effects=0`
- `RFC3161_calls=0`
- `ObjectLock_writes=0`

## Separate governance incident

Historical PowerShell launchers using `-ExecutionPolicy Bypass` are not trusted merely because they are wrapped in a hash-oriented ceremony. Any launcher whose expected SHA-256 is malformed or whose payload was not independently reviewed must be treated as a supply-chain/provenance incident and must not be reused as authority for this lane.

This incident is separate from PR #15 and does not expand R1 runtime scope.

## Merge gate

`MERGE=DENY`

until:
1. adversarial review of the actual PR diff;
2. focused canary tests pass;
3. PI-001/PI-002 regression passes in a compatible runtime;
4. no product-source mutation is introduced without a new gate.
