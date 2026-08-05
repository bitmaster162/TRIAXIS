# TRIAXIS v3.6-RC1 Operator Card

Use `authorize_authenticated_action`, not the legacy digest-only `authorize_action`, for the v3.6 boundary.

Required inputs:

- out-of-band `TrustKeyRegistry`;
- signed assurance attestation;
- signed state witness;
- signed exact policy bundle;
- one signed envelope per approval;
- gate Ed25519 private key provisioned outside the repository.

Fail closed on unknown key, wrong purpose, signer/domain mismatch, invalid signature, expiry or revocation.

Never store production private keys in repository files, fixtures, reports or release archives.
