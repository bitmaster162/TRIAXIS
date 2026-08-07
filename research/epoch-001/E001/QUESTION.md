# RESEARCH QUESTION — E001

Can workload identity (SPIFFE/SPIRE) materially strengthen TRIAXIS principal identity compared with application-generated/local identity alone?

## Context & Claim Classification
* `SOURCE_BACKED_CLAIM`: Application-generated local identities rely on static bearer tokens or local configuration files vulnerable to credential theft or process impersonation.
* `HYPOTHESIS`: Binding TRIAXIS principal identity to cryptographic SVIDs (SPIFFE Verifiable Identity Documents) issued via kernel/platform attestation eliminates hardcoded secrets and enforces dynamic, short-lived identity verification.
