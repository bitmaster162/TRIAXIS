# TRIAXIS RHE Execution Boundary Canary R1

## Status

`CANDIDATE / NO MERGE / NO DEPLOY / NO EXTERNAL EXECUTION`

Baseline:

- repository: `bitmaster162/TRIAXIS`
- branch: `main`
- baseline HEAD: `ae280d905c63e4ba0bcadb4633f01a1fb9657920`
- `src/triaxis/action_assurance.py` blob: `d1c637855dc1625910e95fdb3b2dcee61652ba56`
- `src/triaxis/authorization/pep.py` blob: `57c1d7de35de4fb72a01acb3b27bc4171b839cbe`
- `src/triaxis/identity/contract.py` blob: `50f89d6bb26cfd39c597e69e16775e970f24c085`
- accepted post-PI002 regression evidence: `607 / 607 PASS`

## Purpose

This canary proves the existing TRIAXIS product boundary instead of timestamping a synthetic JSON payload.

Positive path:

`verified workload identity -> authorize_action -> PEP -> Cedar decision -> ALLOW token -> identity-aware SQLiteExecutionLedger.prepare_for_workload -> PREPARED -> STOP`

The canary MUST NOT call:

- an external executor or tool;
- `SQLiteExecutionLedger.complete`;
- trading/capital/deployment paths;
- AWS IAM, Secrets Manager, S3, RFC3161, or Object Lock.

## What is tested

1. Positive deterministic product-boundary path reaches exactly `PREPARED`.
2. Same-token / same-workload retry is idempotent and does not create a second row/effect.
3. Cross-workload replay of an already authorized token is rejected and cannot mutate the ledger row.
4. Claimed workload identity mismatch fails before PEP/PDP evaluation.
5. Unverified workload identity fails before PEP/PDP evaluation.
6. Wrong delegation grant, task, capability, or target returns DENY and never prepares the ledger.
7. PDP exception is converted by PEP to ERROR/DENY and never prepares the ledger.
8. Optional local real-Cedar anchor reaches exactly PREPARED when the Cedar binary is available.

## Existing real-runtime anchor

The canary does not duplicate SPIRE provisioning. The accepted PI-002 test already covers:

`REAL SPIRE -> Workload API -> X509-SVID -> SPIFFE mapping -> CompoundPrincipal -> REAL Cedar -> PEP -> token -> SQLite PREPARED`

in:

`tests/test_pi002_spire_integration.py::test_real_spire_primary_positive_e2e`

R1 therefore adds a compact regression canary around the existing execution boundary rather than another environment-management ceremony.

## Replay semantics clarified

TRIAXIS currently implements:

- identical token + identical workload + identical nonce: idempotent return of existing `PREPARED` row;
- conflicting token/nonce: rejected;
- same authorized token presented by a different verified workload identity: rejected before ledger mutation.

Therefore the RHE requirement is **no duplicate effect**, not “every repeated API call must error.”

## Success criteria

- deterministic canary suite: PASS;
- optional real-Cedar test: PASS when Cedar is installed, otherwise explicit SKIP;
- ledger positive terminal state: exactly `PREPARED`;
- external effects: `0`;
- `can_trade=false`;
- `capital_permission=DENY`;
- `deploy_permission=DENY`.

## Next gate

Independent code review can be delegated to Manus.

Do not use Claude for routine regression review.

No merge until:
1. canary tests pass in a compatible local/CI environment;
2. diff is reviewed;
3. owner explicitly selects merge.
