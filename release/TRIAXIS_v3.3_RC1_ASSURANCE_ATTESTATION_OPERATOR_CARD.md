# TRIAXIS v3.3-RC1 Operator Card

## Default posture

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
external_side_effects=DENY_UNLESS_EXACT_TOKEN_AND_RESOURCE_GATE
```

## Required execution chain

1. Freeze intent and initial authority.
2. Compile and validate the Decision Assurance Case.
3. Validate the Evidence Report.
4. Produce a PASS attestation for the exact subject and exact artifact digests.
5. Verify issuer and trust domain against an external registry.
6. Bind attestation, policy, state, payload, target, approvals and nonce into the
   action scope.
7. Issue one expiring single-use authorization token.
8. Re-read state at the resource boundary.
9. Execute, receipt and reconcile unknown outcomes.

## Immediate stop conditions

- missing or untrusted assurance issuer;
- decision/evidence/subject mismatch;
- non-PASS or expired assurance attestation;
- policy/state/payload mismatch;
- missing approval;
- replay conflict;
- unavailable resource-boundary enforcement.
