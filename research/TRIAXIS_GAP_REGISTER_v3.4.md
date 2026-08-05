# TRIAXIS v3.4 Gap Register

## Closed since v3.3

- PASS attestations are bound to exact action semantics.
- Payload/tool/target/state/policy/risk substitution changes the assured-action
  digest and fails closed.
- Set-only trust registries are rejected.

## P0 before production side effects

1. Real cryptographic signatures and workload identities through KMS/PKI/SPIFFE.
2. Gate placement at the actual tool/API/resource boundary with no bypass credentials.
3. Trusted external time and signed policy/state freshness authorities.
4. Durable signed policy lifecycle and emergency revocation.
5. Resource-specific canonical payload and object adapters.
6. Transactional side-effect integration and reconciliation adapters.
7. Secret management, key rotation and compromise recovery.
8. Multi-tenant isolation and namespace ownership.
9. Transparency log for assurance attestations, tokens and revocations.
10. Distributed fencing/multi-host consistency where more than one executor exists.

## P1 to prove that full TRIAXIS is worth the complexity

1. Equal-budget ablation against `Primary + external verifier + deterministic gate`.
2. Independent evaluator and hidden test set.
3. Real incident/pilot corpus.
4. DEVIL true-positive/false-positive measurement.
5. ANGEL over-refusal benefit without safety regression.
6. Human review-time and escalation-cost measurement.
7. Calibration by model/task/version.
8. Evidence independence and citation-entailment scoring.
9. Production trace-to-regression loop.
10. Willingness-to-pay evidence.
