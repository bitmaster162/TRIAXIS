# TRIAXIS RHE — Execution Boundary Canary R1

Status: `DRAFT / TEST-ONLY / ZERO EXTERNAL EFFECT`

Branch: `product/rhe-execution-boundary-canary-r1`

Baseline: `main @ ae280d905c63e4ba0bcadb4633f01a1fb9657920`

## Purpose

Prove the existing TRIAXIS product execution boundary, not another timestamping ceremony.

Primary path:

`verified workload identity -> authorize_action -> PEP -> Cedar-compatible decision -> ALLOW token -> identity-aware SQLite ledger -> PREPARED -> STOP`

The canary intentionally stops before any external executor/provider effect.

## Why this is the first useful RHE canary

TRIAXIS already contains:
- action-envelope and policy binding;
- PEP receipt correlation;
- Cedar reference authorization;
- SPIFFE/SPIRE workload identity support;
- single-use/idempotent SQLite execution ledger;
- fail-closed DENY/ERROR semantics.

R1 tests that integrated boundary directly.

## Positive acceptance case

A correctly verified workload with the expected:
- human principal;
- agent instance;
- SPIFFE identity;
- delegation grant;
- task;
- capability;
- resource;
- policy;

must produce:

`ALLOW token -> PREPARED`

and the PREPARED row must have:
- `outcome_sha256 = null`
- `effect_id = null`
- `receipt = null`

No call to `complete()` is part of the canary.

## Idempotency semantics

A same-token/same-workload retry is allowed to return the same PREPARED row.

This is not treated as an unsafe replay because it creates no second row and no external effect.

A different workload presenting the token must be rejected before it can mutate the prepared ledger state.

## Negative controls

The canary covers:
- invalid delegation grant;
- invalid task;
- unauthorized capability;
- wrong execution target;
- claimed agent-instance spoof;
- claimed SPIFFE-ID spoof;
- unverified workload identity;
- untrusted workload-identity provider;
- PDP invocation failure;
- cross-workload token replay.

Expected invariant for every negative path:

`NO NEW PREPARED ROW`

Identity failures must occur before PEP/Cedar invocation where applicable.

## Cedar evidence

The deterministic positive path uses a Cedar-compatible PDP adapter to test the product PEP contract without external dependencies.

An optional local-Cedar test uses the existing TRIAXIS Cedar fixture when a compatible Cedar binary is available.

The repository already contains a previously accepted real SPIRE + real X509-SVID + Cedar + PREPARED integration suite; R1 does not rebuild that environment from scratch.

## Architecture minimization

Normal R1 runtime does not require:
- AWS IAM mutation;
- Secrets Manager marker;
- signer-secret retrieval;
- RFC3161;
- S3 Object Lock;
- trading/capital/deployment APIs.

Historical FINAL89/V036/JIT artifacts are not runtime authority for this canary.

See `RHE_REVIEW_ADJUDICATION_R1.md`.

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
1. actual PR diff receives adversarial review;
2. focused canary tests pass in a compatible runtime;
3. PI-001 and PI-002 regression suites pass;
4. optional full regression is reviewed if available;
5. no product-source mutation is introduced without a new bounded gate.

No deploy or external execution is authorized by this document.
