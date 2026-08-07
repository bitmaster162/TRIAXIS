# PI-001 — TRIAXIS RUNTIME ARCHITECTURE MAP

**Work Order ID**: `TRIAXIS-WO-PRODUCT-PI-001`  
**Product Baseline**: `main @ a5d46712aaed3304dd2c3089ae79567ef3e12dba`  
**`src` Tree**: `aa675acd75f8d93cb8695b11db5d70467116f63f`

---

## 1. Product Source Architecture Survey

| Architectural Dimension | Existing TRIAXIS Implementation | PI-001 Integration |
|:---|:---|:---|
| **Canonical Request/Decision Path** | `action_assurance.py` (`authorize_action`) -> `policy_lifecycle.py` (`evaluate_policy`) -> `SQLiteExecutionLedger` | `triaxis.authorization.pep` (`PolicyEnforcementPoint`) integrated into `authorize_action` |
| **Principal / Actor Representation** | Opaque strings (`subject_id`, `issuer_id`) | Typed `CompoundPrincipal` (`human_id` × `agent_instance_id` × `delegation_grant_id` × `task_id`) |
| **Task Representation** | `action_id`, `capability`, `execution_target` | Explicitly bound in `CompoundPrincipal.task_id` & AuthZEN context |
| **Delegation / Grant Concepts** | `TRIAXIS_ACTION_APPROVAL_v1` | `delegation_grant_id` reference in `CompoundPrincipal` |
| **Policy Engine / PDP** | In-Python `evaluate_policy` | `CedarLocalReferencePDP` (invoking `cedar` CLI via safe argument arrays) |
| **PEP / Effect Boundary** | `SQLiteExecutionLedger.prepare` & `record_complete` | `PolicyEnforcementPoint` gating `authorize_action` when `authorization_mode="cedar_reference"` |
| **Compatibility Mode** | Single inline evaluation | Dual mode: `legacy` (default) & `cedar_reference` |

---

## 2. Insertion Point Selection

The smallest real insertion point that routes actual TRIAXIS execution requests through the new authorization boundary is **`action_assurance.authorize_action`**.

When `authorization_mode="cedar_reference"` is provided:
1. `authorize_action` constructs a typed `CompoundPrincipal` and `AuthorizationRequest`.
2. Passes request to the `PolicyEnforcementPoint` (PEP).
3. PEP invokes `CedarLocalReferencePDP`.
4. If decision is `ALLOW`, authorization token is issued and `SQLiteExecutionLedger` prepares execution.
5. If decision is `DENY` or `ERROR`, PEP enforces fail-closed `NO EFFECT`, returning structured denial/error receipt.
