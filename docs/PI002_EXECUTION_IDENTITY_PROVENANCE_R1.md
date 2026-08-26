# PI-002 execution identity provenance R1

Status: `CANDIDATE / NO MERGE / NO DEPLOY`

This candidate adds `TrustedWorkloadExecutionBoundary`, a strict RHE PREPARED path that:

- requires a trusted workload identity provider registry;
- requires the exact trusted provider instance;
- fetches current workload identity from that provider immediately before PREPARED;
- rejects non-VERIFIED identity;
- delegates stable SPIFFE/agent/trust-domain correlation and nonce/idempotency to the existing SQLite ledger;
- deliberately allows certificate fingerprint rotation when stable workload identity is unchanged;
- exposes no caller parameter for injecting a preconstructed current identity.

The legacy ledger API is unchanged for compatibility. RHE should use the strict boundary.

Safety:
- external execution: false
- AWS: 0
- trading: false
- capital: DENY
- deploy: DENY
