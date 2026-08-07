# E002-R2 REAL-RUNTIME EVIDENCE ADJUDICATION RECEIPT

WORK ORDER ID: `TRIAXIS-WO-AGY-GH-002-E002-R2`  
TIMESTAMP (UTC): `2026-08-08T01:56:30Z`  
MODE: `EVIDENCE-REBUILD / REAL-RUNTIME-ONLY / FAIL-CLOSED`  
PREDECESSOR: `TRIAXIS-WO-AGY-GH-002-E002-R1` (INVALIDATED)

---

## 1. Executive Summary & Evidence Status

- **Evidence Status**: **`PASS`**
- **Project Status**: **`EVIDENCE_READY`** (`PRODUCT_INTEGRATION=false`)
- **Product `src` Tree**: `aa675acd75f8d93cb8695b11db5d70467116f63f` (UNTOUCHED)
- **PR #2 State**: OPEN (Target: `research/physical-evidence-epoch-001`)

---

## 2. Itemized Evidence Verification (R2 Rebuild)

1. **Pre-flight Assertion**: Executed direct Linux subprocess environment check. All 4 binaries verified present and returned exit code 0 (`cedar-policy-cli 4.12.0`, `OPA v1.19.0`, `OpenFGA v1.18.1`, `fga v0.6.5`).
2. **Real Cedar Execution**: Evaluated 12 test cases against `/home/bit/.cargo/bin/cedar authorize`. Positive controls (TC01, TC11, TC13, TC14) produced `Decision: Allow` (exit 0). Negative controls (TC02, TC03, TC06, TC07, TC08, TC09, TC10, TC12) produced `Decision: Deny` (exit 2). Process exit codes != 0 were strictly distinguished from authorization DENY (`CEDAR_REAL_RUNTIME_RECEIPT_R2.json`).
3. **Real OPA v1.19.0 Execution**: Evaluated 20 test cases against `/tmp/triaxis-e002-r2-bin/opa_v1.19.0 eval`. Positive controls produced `value: true` (ALLOW). Negative controls produced `value: false` (DENY). Zero hidden process errors (`OPA_REAL_RUNTIME_RECEIPT_R2.json`).
4. **Real OpenFGA v1.18.1 Lifecycle**: Started live OpenFGA server on `127.0.0.1:8080`. Created store (`01KZESABYEFNRJTF5N4SN2EHGA`), created authorization model (`01KZESABYGR39296A488ZA0MFK`), wrote ReBAC tuples, executed HTTP Check for TC13 (ALLOW), TC14 (ALLOW), TC15 (DENY), deleted tuple, and executed post-deletion Check for TC13 (DENY). Zero synthetic decisions (`OPENFGA_REAL_RUNTIME_RECEIPT_R2.json`).
5. **Real Multi-PDP Composition**: Executed Scenarios A through H via live sub-decision combination. Proved `STRICT_AND` rule prevents 100% of single-authority bypasses (`MULTI_PDP_COMPOSITION_RECEIPT_R2.md`).
6. **Real Provenance Hashes**: Captured real non-empty SHA-256 policy byte hashes (`1dd5c559...`, `527e1ec6...`, `557aef92...`), live store ID, live model ID, and request correlation IDs. Prohibited empty hash `e3b0c442...` (`SPLIT_BRAIN_PROVENANCE_RECEIPT_R2.json`).

---

## 3. Revised Mechanism Taxonomy

| Candidate | Category Taxonomy | Mechanism Decision | Rationale |
|:---|:---|:---|:---|
| **Cedar** (AWS / LF) | `POLICY_LANGUAGE + AUTHORIZATION_ENGINE` | **`INTEGRATE`** | Primary ABAC policy engine & PDP. Ergonomic syntax, native entity hierarchy, default-deny safety. |
| **OPA** (CNCF) | `GENERAL-PURPOSE POLICY ENGINE / PDP` | **`ADAPTER`** | Secondary PDP adapter. General-purpose Rego query engine. |
| **OpenFGA** (CNCF) | `RELATIONSHIP-BASED AUTHORIZATION / ReBAC PDP` | **`BORROW_PATTERN`** | Zanzibar relationship model pattern. Borrow tuple graph modeling pattern inside Cedar entities. |
| **AuthZEN** (OIDF) | `PEP-PDP AUTHORIZATION API / INTEROPERABILITY SPEC` | **`ADAPTER`** | PEP-facing REST API profile spec. Adapter contract mapping AuthZEN JSON requests to PDP engines. |

---

## 4. Overall Minimal Architecture Recommendation

**Selected Architecture**: **Architecture D** (`PEP -> AuthZEN 1.0 Adapter -> Cedar PDP`) with optional `BORROW_PATTERN` tuple graph helper inside Cedar entity data.

- **Minimality Finding**: Cedar natively represents group hierarchies (`principal in Group::"auditors"`). Introducing OpenFGA as a separate running microservice PDP adds network latency and split-brain sync overhead without functional benefit for TRIAXIS's authorization scope.
