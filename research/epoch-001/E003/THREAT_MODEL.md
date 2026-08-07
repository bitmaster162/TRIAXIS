# E003 — THREAT MODEL

## Threat Vectors Evaluated

1. **Policy Payload Modification (Man-in-the-Middle / Storage Attack)**:
   - *Attack*: Attacker alters authorization policy JSON in storage or transit.
   - *Mitigation*: in-toto subject hash mismatch (`PAYLOAD_MISMATCH` -> `DENY`).

2. **Forged Attestation Signature**:
   - *Attack*: Attacker generates arbitrary in-toto statement with invalid ECDSA signature.
   - *Mitigation*: ECDSA signature verification failure (`SIGNATURE_INVALID` -> `DENY`).

3. **Untrusted Release Key**:
   - *Attack*: Attacker signs statement with valid ECDSA key not registered in release trust store.
   - *Mitigation*: Public key trust store check (`UNTRUSTED_KEY` -> `DENY`).

4. **Missing / Forged Transparency Log Entry**:
   - *Attack*: Attacker bypasses Rekor log submission to avoid auditability.
   - *Mitigation*: Mandatory Signed Entry Timestamp (SET) and Merkle proof check (`MISSING_INCLUSION_PROOF` -> `DENY`).

5. **Transparency Log Outage / Transport Failure**:
   - *Attack*: Network partition or Rekor service outage (`Connection Refused`).
   - *Mitigation*: PEP fail-closed conversion (`TRANSPORT_PDP_UNAVAILABLE` -> `DENY`).
