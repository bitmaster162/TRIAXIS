# PRIOR ART & CATEGORY CLASSIFICATION — E002

## Category Distinction
Per Work Order Section 6, the four candidates are NOT interchangeable monolithic engines. They occupy distinct architectural layers:

| Candidate | Primary Category | Official Primary Source | Executed Version | License | Primary Role |
|:---|:---|:---|:---|:---|:---|
| **Cedar** | Policy Language & PDP | AWS (`github.com/cedar-policy/cedar`) | `v4.12.0` (CLI `4.1.0`) | Apache-2.0 | Fine-grained, fast, verifiable policy evaluation with permit/forbid semantics |
| **OPA** | General Policy Engine (PDP) | CNCF (`github.com/open-policy-agent/opa`) | `v1.0.0` / `v1.19.0` | Apache-2.0 | Domain-agnostic policy decision point evaluating Rego queries |
| **OpenFGA** | ReBAC System | CNCF (`github.com/openfga/openfga`) | `v1.8.3` (CLI `fga v0.6.3`) | Apache-2.0 | Relationship-based graph authorization (Zanzibar-inspired) |
| **AuthZEN** | Authorization API Spec | OpenID Foundation (`github.com/openid/authzen`) | `1.0` Final Spec | OpenID IPR | Standardized PEP-to-PDP REST interaction profile |

## Architectural Roles Analysis

### 1. Cedar (AWS)
- **Strengths**: Expressive permit/forbid semantics, default deny, formal verification support, strong typing, fast Rust-native execution, native context support.
- **Role in TRIAXIS**: Candidate for internal fine-grained contextual Policy Decision Point (PDP).

### 2. OPA (Open Policy Agent)
- **Strengths**: Industry-standard cloud-native policy engine, rich built-in functions, Rego v1 query capability, decision logging, wide ecosystem.
- **Role in TRIAXIS**: Candidate for general-purpose policy evaluation and structured decision logging.

### 3. OpenFGA (Auth0 / Okta / CNCF)
- **Strengths**: Excellent graph-based relationship navigation (group membership, folder hierarchy, organization trees), tuple-based access control.
- **Limitations**: Not designed for complex contextual attribute checks (time of day, CIDR, policy lifecycle state).
- **Role in TRIAXIS**: Specialized relationship/membership sub-decision engine (ReBAC component).

### 4. AuthZEN (OpenID Foundation)
- **Strengths**: Standardized HTTP REST API payload for authorization checks (`subject`, `action`, `resource`, `context`), PEP-PDP interoperability.
- **Classification**: **API Specification**, not a standalone policy engine.
- **Role in TRIAXIS**: Unified PEP-facing authorization request/response boundary wrapper around Cedar, OPA, or OpenFGA.
