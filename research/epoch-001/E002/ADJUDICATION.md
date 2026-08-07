# E002-R1 ADJUDICATION RECEIPT

Work Order: `TRIAXIS-WO-AGY-GH-002-E002-R1`  
Timestamp (UTC): `2026-08-08T01:36:30Z`  
Product Integration: `PRODUCT_INTEGRATION=false`  
Frozen Product Tree: `src = aa675acd75f8d93cb8695b11db5d70467116f63f` (UNTOUCHED)

---

## 1. Candidate Mechanism Taxonomy Re-Adjudication

Per Section 11 of Work Order `E002-R1`:

| Candidate | Revised Taxonomy Verdict | Role in TRIAXIS Architecture | Justification |
|:---|:---|:---|:---|
| **Cedar** (AWS) | **`INTEGRATE`** | Primary In-Memory ABAC PDP | High-performance, strongly typed, Rust-native policy engine providing contextual permit/forbid policy decisions. |
| **OPA** (CNCF) | **`ADAPTER`** | Secondary / General PDP | Optional secondary policy engine adapter for general-purpose Rego rules where legacy policy bundles exist. |
| **OpenFGA** (CNCF) | **`BORROW_PATTERN`** | ReBAC Relationship Sub-Model | Borrow Zanzibar tuple graph pattern for relationship sub-decisions behind Cedar rather than running a separate OpenFGA server daemon by default. |
| **AuthZEN** (OIDF) | **`ADAPTER`** | PEP-PDP REST API Specification Profile | Interface adapter standardizing authorization query requests (`subject`, `action`, `resource`, `context`) and response schemas. |

---

## 2. Architectural Minimality Test Result

Per Section 12, five architectures were evaluated against TRIAXIS authorization requirements:

- **Architecture A**: `PEP -> Cedar only`
- **Architecture B**: `PEP -> OPA only`
- **Architecture C**: `PEP -> Cedar + OpenFGA (STRICT_AND)`
- **Architecture D**: `PEP -> AuthZEN Adapter -> Cedar`
- **Architecture E**: `PEP -> AuthZEN Adapter -> Cedar + OpenFGA (STRICT_AND)`

### Minimality Finding
OpenFGA relationship traversal (group membership, entity hierarchy) can be natively represented in Cedar using entity hierarchies (`principal in Group::"x"`). Running OpenFGA as a separate daemon PDP introduces multi-PDP operational complexity and split-brain risks without providing capabilities that Cedar cannot represent.

**Selected Minimal Architecture**: **Architecture D** (`PEP -> AuthZEN Adapter -> Cedar`) with optional `BORROW_PATTERN` tuple graph helper inside Cedar entity data.

---

## 3. Evidence Status & Project Status

* **Evidence Status**: **`PASS`**
  - **Version Provenance**: Official stable releases verified (`opa_v1.17.0`, `openfga_v1.18.1`, `fga_v0.6.5`, `cedar-policy-cli v4.12.0`, `AuthZEN 1.0 Final`).
  - **Real Runtime Execution**: 100% real binary execution receipts recorded for Cedar, OPA, and OpenFGA.
  - **AuthZEN Reclassification**: Reclassified as `AUTHZEN_INTERFACE_CONFORMANCE_MODEL` / `LOCAL_ADAPTER_MODEL_ONLY`.
  - **Fail-Closed Boundary Testing**: Real failure modes evaluated; PEP-level conversion distinguished from PDP engine denials.
  - **Multi-PDP Composition**: 8 composition scenarios (A–H) executed; `STRICT_AND` rule proven mandatory.
  - **Split-Brain Provenance**: Full auditability trace verified.
  - **Product Source**: `src/` tree `aa675acd75f8d93cb8695b11db5d70467116f63f` strictly unmodified.

* **Project Status**: **`EVIDENCE_READY`** (`PRODUCT_INTEGRATION=false`)

---

## 4. Next Steps

PR #2 updated on GitHub (`research/e002-policy-engine-shootout`).  
**Do NOT merge PR #2. Do NOT start E003.**  
Await operator adjudication.
