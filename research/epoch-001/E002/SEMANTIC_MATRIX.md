# SEMANTIC MATRIX — E002

## Semantic Fit & Feature Support Matrix

| Feature / Dimension | Cedar (AWS) | OPA (CNCF) | OpenFGA (CNCF) | AuthZEN (OIDF) |
|:---|:---|:---|:---|:---|
| **Primary Category** | Policy Language + PDP | General PDP / Engine | ReBAC Engine | Authorization API Spec |
| **Default Deny** | `NATIVE` (Explicit permit/forbid) | `MODELED` (`default allow = false`) | `NATIVE` (No tuple = no access) | `NATIVE` (Spec default = deny) |
| **Explicit Forbid / Deny** | `NATIVE` (`forbid` overrides) | `MODELED` (`deny` rule overriding `allow`) | `MODELED` (via exclusion tuples) | `MODELED` |
| **Contextual Conditions** | `NATIVE` (`when { context.x == y }`) | `NATIVE` (`input.context.x == y`) | `NOT_EXPRESSIBLE` (requires contextual tuples) | `NATIVE` (`context` payload) |
| **Compound Principal** (`HUMAN × AGENT × GRANT × TASK`) | `MODELED` (schema + context) | `MODELED` (nested input JSON) | `AWKWARD` (requires multiple tuple relations) | `NATIVE` (`subject` payload) |
| **Relationship Navigation** (ReBAC) | `MODELED` (`principal in Group::"x"`) | `MODELED` (data map iteration) | `NATIVE` (`user:X -> member -> group`) | `MODELED` (behind PDP) |
| **Policy Lifecycle** | `EXTERNAL` (metadata layer) | `EXTERNAL` (bundle metadata) | `EXTERNAL` (model IDs) | `EXTERNAL` (PDP capability) |
| **Decision Explainability** | `NATIVE` (determining policies returned) | `MODELED` (decision log trace) | `NATIVE` (tuple trace) | `MODELED` (`reasons` field) |
| **Fail-Closed Behavior** | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |

## Legend
- `NATIVE`: Built directly into the core language or specification.
- `MODELED`: Achieved via idiomatic policy code or input structure.
- `AWKWARD`: Requires complex workarounds or loses semantic clarity.
- `NOT_EXPRESSIBLE`: Cannot be represented natively in candidate paradigm.
- `EXTERNAL`: Handled by surrounding management/lifecycle orchestration.
