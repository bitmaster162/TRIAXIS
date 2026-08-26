# TRIAXIS RHE — Execution Boundary Canary R1

Status: `DRAFT / TEST-ONLY / ZERO EXTERNAL EFFECT`

Branch: `product/rhe-execution-boundary-canary-r1`

Baseline: `main @ ae280d905c63e4ba0bcadb4633f01a1fb9657920`

## Purpose

Prove the existing TRIAXIS product execution boundary, not another timestamping ceremony.

Primary path:

`verified workload identity -> authorize_action -> PEP -> Cedar-compatible decision -> ALLOW token -> identity-aware SQLite ledger -> PREPARED -> STOP`

The canary intentionally stops before any external executor/provider effect.

## Positive acceptance case

A correctly verified workload with the expected human, agent, SPIFFE identity, delegation, task, capability, resource and policy must produce:

`ALLOW token -> PREPARED`

and the PREPARED row must keep:
- `outcome_sha256 = null`
- `effect_id = null`
- `receipt = null`

No call to `complete()` is part of the canary.

## Idempotency semantics

A same-token/same-workload retry may return the same PREPARED row. It must not create a second row or external effect.

A different workload presenting the token must be rejected before ledger mutation.

## Negative controls

- invalid delegation grant;
- invalid task;
- unauthorized capability;
- wrong execution target;
- claimed agent-instance spoof;
- claimed SPIFFE-ID spoof;
- unverified workload identity;
- untrusted workload-identity provider at authorization issuance;
- PDP invocation failure;
- cross-workload token replay.

Expected invariant for every negative path:

`NO NEW PREPARED ROW`

## New PI-002 provenance finding

Static review found that the existing ledger PREPARED API can trust a caller-supplied `VerifiedWorkloadIdentity` object when registry/provider provenance is omitted. PR #15's positive path uses the stronger registry + exact provider-instance path, but passing this canary alone would not prove weaker product call paths are impossible.

See:
- `RHE_PI002_EXECUTION_IDENTITY_PROVENANCE_FINDING_R1.md`
- `RHE_PI002_EXECUTION_IDENTITY_PROVENANCE_WORK_ORDER_R1.md`

## Architecture minimization

Normal R1 runtime does not require:
- AWS IAM mutation;
- Secrets Manager marker;
- signer-secret retrieval;
- RFC3161;
- S3 Object Lock;
- trading/capital/deployment APIs.

Historical FINAL89/V036/JIT artifacts are not runtime authority for this canary.

## Safety invariants

- `external_execution=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `AWS_effects=0`
- `SecretsManager_effects=0`
- `RFC3161_calls=0`
- `ObjectLock_writes=0`

## Merge gate

`MERGE=DENY`

until all are true:
1. actual current PR diff receives adversarial review;
2. focused canary tests pass in a compatible runtime;
3. PI-001 and PI-002 regression suites pass;
4. execution-time identity provenance contract is resolved and independently reviewed;
5. no product-source mutation is introduced into PR #15 without a new bounded gate.

No deploy or external execution is authorized by this document.
