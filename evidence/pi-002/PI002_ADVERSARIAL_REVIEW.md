# TRIAXIS PI-002 Adversarial Security Review & Residual Limitations

## 1. Adversarial Attack Surface Evaluation

| Attack Scenario | Vector | Mitigation Mechanism | Result |
| :--- | :--- | :--- | :--- |
| **Caller Impersonation** | Claiming `agent_instance_id` of another agent | Strict correlation against verified SVID mapping in `authorize_action` | **DENY** (`WORKLOAD_IDENTITY_MISMATCH`), PEP bypassed |
| **SPIFFE ID Spoofing** | Claiming `spiffe_id` of admin workload | Correlation against SAN URI in X509-SVID | **DENY** (`WORKLOAD_IDENTITY_MISMATCH`), PEP bypassed |
| **Receipt Replay** | Replaying Cedar ALLOW receipt under different workload | Principal SPIFFE identity bound in `CompoundPrincipal` and Cedar decision hash | **PASSED** (Decision digests differ) |
| **Token Reuse** | Presenting Workload A token for Workload B | Single-use SQLite Execution Ledger state transition constraint | **REJECTED** (`sqlite3.IntegrityError`) |
| **Mode Downgrade** | Invoking with invalid `identity_mode` | Mandatory verification mode enum enforcement | **DENY** (`CONFIG_ERROR`), PEP bypassed |

## 2. Residual Security Limitations

> [!WARNING]
> **Residual Limitation 1: OS-Level Workload Attestation Confinement**
> SPIRE Agent Unix Workload Attestor relies on Linux kernel process credentials (`SO_PEERCRED` / `/proc`). On shared multi-tenant hosts without container or PID namespace isolation, processes running under the same Linux OS UID share identical attestation selectors (`unix:uid`). Production deployments MUST enforce container boundary isolation (e.g. Kubernetes pod attestor or cgroups).

> [!WARNING]
> **Residual Limitation 2: Static SVID-to-Agent Mapping Integrity**
> The current `SpiffeAgentMapping` maps static SPIFFE IDs to `agent_instance_id` strings. Changes to workload identity topology require controlled updating and cryptographic re-sealing of `identity_mapping_sha256`. Dynamic attribute-based authorization claims (e.g. JWT-SVID claims or OIDC tokens) require future PI-003 extension.
