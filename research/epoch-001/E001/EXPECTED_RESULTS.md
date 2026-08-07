# EXPECTED RESULTS — E001

1. Valid workload attestation yields SVID matching `spiffe://triaxis.internal/ns/prod/sa/harness-engine`.
2. Invalid attestation selector (e.g. mismatched UID or path) returns `ATTRIBUTABLE_BLOCK`.
3. SVID cryptographic signature validates against Trust Bundle CA; tampered or expired SVID returns `VERIFICATION_FAILURE`.
4. Automated SVID rotation updates identity document seamlessly prior to expiration window.
