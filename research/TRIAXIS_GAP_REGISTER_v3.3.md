# TRIAXIS v3.3 Gap Register

## Closed since v3.2

- The Action Assurance Envelope can no longer rely on arbitrary well-formed
  Decision Assurance Case and Evidence Report digests.
- A trusted, fresh PASS attestation must bind the exact subject and artifact
  pair.
- The attestation digest is bound into action scope and authorization token.

## P0 — required before production side effects

1. KMS/PKI/SPIFFE-class cryptographic identity and signature verification for
   assurance issuers, policy issuers, adapters, principals and gates.
2. Gate placement at the actual tool/API/resource boundary; no bypass
   credentials.
3. Trusted external time and policy/state freshness authority.
4. Persistent signed policy registry with lifecycle events and emergency
   revocation.
5. Resource-specific adapters for exact object/payload/state binding.
6. Transactional outbox or equivalent integration around external side effects.
7. Recovery and reconciliation adapters for timeout/unknown outcomes.
8. Secret management and key rotation.
9. Multi-tenant isolation and namespace ownership.
10. Transparency/audit log for assurance attestations and revocations.

## P1 — required to prove product value

1. Equal-budget ablation against `Primary + external verifier + gate`.
2. Independent benchmark implementation and evaluator.
3. Real pilot incident corpus.
4. Human review-time measurement.
5. DEVIL precision/recall and false-positive cost.
6. ANGEL safety versus over-refusal delta.
7. Calibration by task class and model version.
8. Evidence-quality and source-independence scoring.
9. Production trace-to-regression loop.
10. Measured willingness to pay.

## P2 — platform moat

1. Domain policy packs.
2. Evidence connector ecosystem.
3. Decision Assurance Receipt interoperability.
4. Role/model routing leaderboard.
5. Private/on-prem deployment.
6. Continuous assurance and drift monitoring.
7. Human Decision Cockpit.
