# E002-R3 EVIDENCE CONSISTENCY ADJUDICATION RECEIPT

WORK ORDER ID: `TRIAXIS-WO-AGY-GH-002-E002-R3`  
TIMESTAMP (UTC+7): `2026-08-08T02:20:50+07:00` (UTC `2026-08-07T19:20:50Z`)  
MODE: `MICRO-CORRECTION / EVIDENCE-INTEGRITY / FAIL-CLOSED`  
PREDECESSOR: `TRIAXIS-WO-AGY-GH-002-E002-R2` (CORE ACCEPTED / REVISE)

---

## 1. Executive Summary & Final Status

* **Evidence Status**: **`PASS_WITH_CONDITIONS`**
* **Project Status**: **`EVIDENCE_READY`** (`PRODUCT_INTEGRATION=false`)
* **Product `src` Tree**: `aa675acd75f8d93cb8695b11db5d70467116f63f` (UNTOUCHED)
* **PR #2 State**: OPEN (Target: `research/physical-evidence-epoch-001`)
* **Explicit Condition**: `Lifecycle/revocation assurance deferred to E009.`

---

## 2. Granular Evidence Classification

### A. VERIFIED REAL-RUNTIME
- **Cedar Authorization Execution**: Evaluated 12 test cases against live Cedar CLI (`cedar-policy-cli 4.12.0`). Positive controls (TC01, TC11, TC13, TC14) returned `Decision: Allow` (exit code 0); negative controls returned `Decision: Deny` (exit code 2). (`CEDAR_REAL_RUNTIME_RECEIPT_R2.json`)
- **OPA Authorization Execution**: Evaluated 20 test cases against live OPA binary (`v1.19.0 eval`). Positive controls returned `value: true` (ALLOW); negative controls returned `value: false` (DENY). (`OPA_REAL_RUNTIME_RECEIPT_R2.json`)
- **OpenFGA Relationship Checks**: Executed live HTTP server operations (`v1.18.1`). Created store, model, wrote tuples, executed Check for TC13 (ALLOW), deleted tuple, executed post-deletion Check (DENY). (`OPENFGA_REAL_RUNTIME_RECEIPT_R2.json`)
- **OpenFGA TC14 Exact Corpus Check**: Executed exact TC14 corpus check (`user:julia` -> `devops` -> `engineers` -> `viewer` `folder:engineering_docs`). Returned `{"allowed": true}` (ALLOW). (`OPENFGA_TC14_CORPUS_CORRECTION_RECEIPT.json`)
- **Real PDP Transport Failure Control**: Attempted connection to closed port 127.0.0.1:8089, caught `<urlopen error [Errno 111] Connection refused>`, classified as `TRANSPORT/PDP_UNAVAILABLE`, and verified PEP fail-closed conversion to `NO_VERIFIED_ALLOW / DENY`. (`REAL_PDP_UNAVAILABLE_RECEIPT_R3.json`)
- **Binary Provenance**: Verified SHA-256 hashes for `opa_v1.19.0`, `openfga_v1.18.1`, `fga_v0.6.5`, `cedar-policy-cli v4.12.0`. (`BINARY_HASHES.txt`)
- **Canonical Policy Hashes**: Verified Cedar policy SHA-256 (`527e1ec62303dd35fce58efae35a4e578ebd44cec5a7b710410f966da32909f1`) and OPA Rego policy SHA-256 (`9fd4e839b3476d5284c4e0f3b142f4f04a999ed5a82c0434260364a4bd3852f2`). Removed stale OPA hash `557aef92...`. (`SPLIT_BRAIN_PROVENANCE_RECEIPT_R3.json`)

### B. EXECUTABLE LOCAL MODEL
- **Multi-PDP Combiner Model**: Scenarios A–H executable combiner (`LOCAL_EXECUTABLE_COMBINER_MODEL_ONLY`). Validates mathematical safety of combining multiple signals (`STRICT_AND`). (`MULTI_PDP_COMPOSITION_RECEIPT_R3.md`)
- **AuthZEN Interface Adapter**: REST API request/response mapping profile (`AUTHZEN_INTERFACE_CONFORMANCE_MODEL`). (`AUTHZEN_EVIDENCE_CLASSIFICATION.md`)

### C. PARTIAL / DEFERRED
- **Full Policy Lifecycle Semantics**: Defer complete lifecycle state machine and causal revocation isolation to E009 (`PARTIAL / DEFER_TO_E009`).
- **Full Multi-PDP Network Chaining**: Deferred (not required for single-PDP target architecture).

---

## 3. Mechanism Taxonomy & Candidate Dispositions

| Candidate | Category Taxonomy | Mechanism Disposition | Rationale |
|:---|:---|:---|:---|
| **Cedar** (AWS / LF) | `POLICY_LANGUAGE + AUTHORIZATION_ENGINE` | **`INTEGRATE`** | Primary ABAC policy engine & PDP. Ergonomic syntax, native entity hierarchy, default-deny safety. |
| **OPA** (CNCF) | `GENERAL-PURPOSE POLICY ENGINE / PDP` | **`ADAPTER`** | Secondary PDP adapter. General-purpose Rego query engine. |
| **OpenFGA** (CNCF) | `RELATIONSHIP-BASED AUTHORIZATION / ReBAC PDP` | **`BORROW_PATTERN`** | Zanzibar relationship model pattern. Borrow tuple graph modeling pattern inside Cedar entities. |
| **AuthZEN** (OIDF) | `PEP-PDP AUTHORIZATION API / INTEROPERABILITY SPEC` | **`ADAPTER`** | PEP-facing REST API profile spec. Adapter contract mapping AuthZEN JSON requests to PDP engines. |

---

## 4. Overall Recommended Architecture

**Selected Architecture**: **`PEP -> AuthZEN-compatible Adapter -> Cedar PDP`** (with optional `BORROW_PATTERN` tuple graph helper inside Cedar entity data).

---

## 5. Next Steps & Boundaries

* **`PRODUCT_INTEGRATION`**: `false`
* **`SOURCE_MODIFICATION`**: `DENY`
* **PR #2 State**: OPEN (Updated on GitHub, NOT merged)
* **`E003`**: `BLOCKED`

**STOP for operator adjudication.**
