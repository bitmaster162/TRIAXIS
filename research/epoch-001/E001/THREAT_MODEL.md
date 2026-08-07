# THREAT MODEL — E001 WORKLOAD IDENTITY

## Evaluated Attack Vectors
1. **Process Impersonation / Credential Theft**: Adversary attempts to steal long-lived API tokens or present forged identity tokens.
   - *Mitigation*: SPIFFE SVIDs are short-lived (e.g. 1 hour) and issued dynamically without disk persistence.
2. **Attestation Spoofing**: Adversary process attempts to query Workload API claiming to be TRIAXIS engine.
   - *Mitigation*: SPIRE agent verifies process caller UID, binary path, and environment hash via platform OS kernel.
3. **Cross-Trust-Domain Impersonation**: Malicious workload from external domain presents forged identity certificate.
   - *Mitigation*: Trust bundle verification enforces strict CA signature validation across trust domain boundaries.
