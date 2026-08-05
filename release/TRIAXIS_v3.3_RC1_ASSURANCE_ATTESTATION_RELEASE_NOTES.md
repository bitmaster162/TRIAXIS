# TRIAXIS v3.3-RC1 Assurance Attestation — Release Notes

## Reason for release

A fresh post-product trigger against exact v3.2-RC1 found assurance provenance
laundering: arbitrary, unrelated decision/evidence digests could receive ALLOW.
The evidence was committed before corrective code.

## Added

- `TRIAXIS_ASSURANCE_PASS_ATTESTATION_v1`.
- Action Envelope v2 with mandatory attestation.
- Exact subject, decision-case and evidence-report binding.
- Freshness and accepting-synthesis checks.
- External issuer/trust-domain allowlist at authorization time.
- Attestation digest in action scope and authorization token.
- Six-case deterministic closure trigger.
- JSON Schemas and end-to-end examples.

## Validation before product commit

- 183 unit/historical tests passed.
- Assurance-attestation trigger: 6/6 pass.
- End-to-end operational assurance example completed.

## Boundaries

- Canonical sealing is not a digital signature.
- The caller-provided trust registry is a reference interface, not a KMS/PKI implementation.
- Complete mediation, trusted time and production identity remain unimplemented.
