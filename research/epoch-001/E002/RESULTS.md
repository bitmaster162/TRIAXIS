# EXPERIMENT RESULTS — E002 Policy Engine Shootout

## Executed Environment & Primary Versions
* **Execution Environment**: WSL2 Linux (Ubuntu 24.04), x86_64
* **Date**: 2026-08-08
* **Product Integration**: `PRODUCT_INTEGRATION=false`
* **`src/` Tree Integrity**: `aa675acd75f8d93cb8695b11db5d70467116f63f` (UNTOUCHED)

### Candidate Versions
- **Cedar**: `v4.12.0` (`cedar-policy-cli 4.1.0` / Rust `cedar-policy 4.12.0`)
- **OPA**: `v1.0.0` (Rego v1 enabled)
- **OpenFGA**: `v1.8.3` (CLI `v0.6.3`)
- **AuthZEN**: `Authorization API 1.0` (OpenID Foundation Final Specification)

---

## Benchmark Results across 20 Test Cases

| Test Case ID | Test Case Name | Cedar | OPA | OpenFGA | AuthZEN | Expected |
|:---|:---|:---|:---|:---|:---|:---|
| **TC01** | Explicit Allow | `ALLOW` | `ALLOW` | `ALLOW` (Modeled) | `ALLOW` (Spec) | `ALLOW` |
| **TC02** | Explicit Deny | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC03** | No Matching Policy | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC04** | Revoked Delegation Grant | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC05** | Expired Delegation Grant | `DENY` | `DENY` | `DENY` (Not Expressible) | `DENY` (Spec) | `DENY` |
| **TC06** | Wrong Resource | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC07** | Wrong Action | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC08** | Wrong Human | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC09** | Wrong Agent Instance | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC10** | Wrong Task Scope | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC11** | Context Condition True | `ALLOW` | `ALLOW` | `DENY` (Not Expressible) | `ALLOW` (Spec) | `ALLOW` |
| **TC12** | Context Condition False | `DENY` | `DENY` | `DENY` (Not Expressible) | `DENY` (Spec) | `DENY` |
| **TC13** | ReBAC Direct Membership | `ALLOW` | `ALLOW` | `ALLOW` (Native) | `ALLOW` (Spec) | `ALLOW` |
| **TC14** | ReBAC Nested Membership | `ALLOW` | `ALLOW` | `ALLOW` (Native) | `ALLOW` (Spec) | `ALLOW` |
| **TC15** | ReBAC Relationship Removed | `DENY` | `DENY` | `DENY` (Native) | `DENY` (Spec) | `DENY` |
| **TC16** | Stale Policy Version | `DENY` | `DENY` | `DENY` (Not Expressible) | `DENY` (Spec) | `DENY` |
| **TC17** | Policy Superseded | `DENY` | `DENY` | `DENY` (Not Expressible) | `DENY` (Spec) | `DENY` |
| **TC18** | Emergency Lockdown | `DENY` | `DENY` | `DENY` (Not Expressible) | `DENY` (Spec) | `DENY` |
| **TC19** | Malformed Request Payload | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |
| **TC20** | Unavailable PDP Service | `DENY` | `DENY` | `DENY` (Modeled) | `DENY` (Spec) | `DENY` |

---

## Detailed Observations per Candidate

### 1. Cedar (AWS) — 20/20 Match (with PEP Governance Wrapper)
- **Verdict**: Excellent ABAC and fine-grained permit/forbid policy evaluation.
- **Fail-Closed**: 100% fail-closed when context or required permissions are missing.
- **ReBAC**: Group hierarchy supported via `principal in Group::"x"` entity hierarchy.

### 2. OPA (CNCF) — 20/20 Match (with Rego v1)
- **Verdict**: Flexible general-purpose PDP. Rego v1 provides strong expressive capability.
- **Fail-Closed**: 100% fail-closed with `default allow = false` and explicit `deny` rules.

### 3. OpenFGA (CNCF) — ReBAC Native
- **Verdict**: Exceptional relationship-based graph authorization (TC13, TC14, TC15).
- **Limitation**: Pure contextual conditions (TC11, TC12) and policy lifecycle states (TC16, TC17) are `NOT_EXPRESSIBLE` natively without converting attributes into relationship tuples.

### 4. AuthZEN (OpenID Foundation) — API Specification Layer
- **Verdict**: Provides standard PEP-PDP REST protocol mapping (`subject`, `action`, `resource`, `context`).
- **Classification**: `SPEC_EVIDENCE`. Acts as the unifying PEP-facing request interface.
