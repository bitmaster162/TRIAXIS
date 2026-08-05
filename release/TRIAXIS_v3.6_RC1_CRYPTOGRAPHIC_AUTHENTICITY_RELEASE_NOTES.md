# TRIAXIS v3.6-RC1 Release Notes

v3.6 closes the cryptographic issuer-authenticity defect found after v3.5-RC2.

Added:

- Ed25519 key records and signed contract envelopes;
- purpose-constrained keys;
- signer/trust-domain binding;
- validity and revocation checks;
- authenticated action authorization;
- authenticated SQLite execution preparation;
- schemas, tests and a closure trigger.

The release does not claim secure key custody, registry anti-rollback, distributed trust or production complete mediation.
