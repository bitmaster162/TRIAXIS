# TRIAXIS v3.2-RC1 Operator Card

## Default posture

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
external_side_effects=DENY_UNLESS_EXACT_TOKEN_AND_RESOURCE_GATE
```

## Use

1. Freeze intent and initial authority.
2. Select the minimum assurance plan.
3. Compile claims/evidence/defeaters/falsifier.
4. Validate evidence package.
5. Synthesize a candidate action without permission.
6. Evaluate active policy and authenticated state.
7. Issue one exact, expiring, single-use token.
8. Prepare the execution ledger at the resource boundary.
9. Complete or mark UNKNOWN and reconcile.

## Stop conditions

- correlated or stale load-bearing evidence;
- missing authoritative adapter for security-critical facts;
- policy rollback, expiry or revocation;
- subject/object/payload/state mismatch;
- missing approvals;
- reused nonce with different token;
- unknown outcome without reconciliation;
- any attempt by a reasoning component to grant permission.
