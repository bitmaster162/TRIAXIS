# PI-002 execution identity provenance finding — concise summary

Current ledger PREPARED path trusts caller-supplied `VerifiedWorkloadIdentity` unless both registry and provider instance are supplied.

That object is a normal Python dataclass, not a signed proof.

Therefore the current contract has an implicit trusted-caller assumption at execution time.

Decision required before PR #15 merge:

- either explicitly declare that caller as part of the trusted computing base;
- or require trusted provider provenance before PREPARED for `spiffe_workload` tokens.

Preferred RHE direction: fail closed and require provider provenance.
