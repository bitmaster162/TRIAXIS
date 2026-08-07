# SEMANTIC MATRIX — E002-R1

## Category Distinction & Semantic Fit Matrix

Per Section 3 of Work Order `E002-R1`, the four candidates occupy distinct architectural roles and are NOT interchangeable engines:

| Candidate | Primary Category Taxonomy | Executed Version | License | Primary Role |
|:---|:---|:---|:---|:---|
| **Cedar** (AWS) | `POLICY_LANGUAGE + AUTHORIZATION_ENGINE` | `v4.12.0` (CLI `v4.12.0` / crate `v4.12.0`) | Apache-2.0 | Fine-grained, fast, verifiable policy evaluation with permit/forbid semantics |
| **OPA** (CNCF) | `GENERAL-PURPOSE POLICY ENGINE / PDP` | `v1.17.0` (Rego v1 enabled) | Apache-2.0 | Domain-agnostic policy decision point evaluating Rego queries |
| **OpenFGA** (CNCF) | `RELATIONSHIP-BASED AUTHORIZATION SYSTEM / ReBAC PDP` | `v1.18.1` (Server `v1.18.1`, CLI `fga v0.6.5`) | Apache-2.0 | Relationship-based graph authorization (Zanzibar-inspired) |
| **AuthZEN** (OIDF) | `PEP-PDP AUTHORIZATION API / INTEROPERABILITY SPECIFICATION` | `Authorization API 1.0 Final` | OpenID IPR | Standardized PEP-to-PDP REST interaction profile |

---

## Semantic Feature Expressiveness Matrix

| Feature / Dimension | Cedar (AWS) | OPA (CNCF) | OpenFGA (CNCF) | AuthZEN (OIDF) PEP Adapter |
|:---|:---|:---|:---|:---|
| **Default Deny** | `NATIVE` (Explicit permit/forbid) | `MODELED` (`default allow = false`) | `NATIVE` (No tuple = no access) | `NATIVE` (Spec default = false) |
| **Explicit Forbid / Deny** | `NATIVE` (`forbid` overrides) | `MODELED` (`deny` rule overriding `allow`) | `MODELED` (via exclusion tuples) | `MODELED` |
| **Contextual Conditions** | `NATIVE` (`when { context.x == y }`) | `NATIVE` (`input.context.x == y`) | `NOT_EXPRESSIBLE` (requires contextual tuples) | `NATIVE` (`context` payload) |
| **Compound Principal** (`HUMAN × AGENT × GRANT × TASK`) | `MODELED` (schema + context) | `MODELED` (nested input JSON) | `AWKWARD` (requires multiple tuple relations) | `NATIVE` (`subject` payload) |
| **Relationship Navigation** (ReBAC) | `MODELED` (`principal in Group::"x"`) | `MODELED` (data map iteration) | `NATIVE` (`user:X -> member -> group`) | `MODELED` (behind PDP) |
| **Policy Lifecycle** | `EXTERNAL` (metadata layer) | `EXTERNAL` (bundle metadata) | `EXTERNAL` (model IDs) | `EXTERNAL` (PDP capability) |
| **Decision Explainability** | `NATIVE` (determining policies returned) | `MODELED` (decision log trace) | `NATIVE` (tuple trace) | `MODELED` (`reasons` field) |
| **Fail-Closed Behavior** | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |

## Legend
- `NATIVE`: Built directly into core language or specification.
- `MODELED`: Achieved via idiomatic policy code or input structure.
- `AWKWARD`: Requires complex workarounds or loses semantic clarity.
- `NOT_EXPRESSIBLE`: Cannot be represented natively in candidate paradigm.
- `EXTERNAL`: Handled by surrounding management/lifecycle PEP orchestration.
