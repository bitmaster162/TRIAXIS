# E002 ADJUDICATION RECEIPT

Work Order: `TRIAXIS-WO-AGY-GH-002-E002`  
Timestamp (UTC): `2026-08-07T18:30:00Z`  
Product Integration: `PRODUCT_INTEGRATION=false`

---

## Per-Candidate Dispositions

| Candidate | Verdict | Primary Role | Architectural Position |
|:---|:---|:---|:---|
| **Cedar** (AWS) | **`BUILD`** | Primary Policy Engine & PDP | Core contextual ABAC policy evaluation engine for fine-grained authorization |
| **OPA** (CNCF) | **`ADAPTER`** | Secondary / General PDP | Optional secondary policy engine adapter for existing Rego bundles |
| **OpenFGA** (CNCF) | **`BORROW_PATTERN`** | ReBAC Relationship Model | Borrow Zanzibar tuple graph pattern for relationship sub-decisions behind Cedar |
| **AuthZEN** (OIDF) | **`INTEGRATE`** | Authorization API Spec | PEP-facing REST request/response interface wrapper standardizing access queries |

---

## Overall Architecture Recommendation

```
[ TRIAXIS Policy Enforcement Point (PEP) ]
                  │
                  ▼ (AuthZEN 1.0 REST Request)
[ AuthZEN API Interface Wrapper ]
                  │
        ┌─────────┴─────────┐
        ▼ (Strict-AND)       ▼ (Tuple Graph)
[ Cedar Policy Engine ]  [ OpenFGA ReBAC Adapter ]
  (ABAC / Context PDP)    (Group / Folder Hierarchy)
```

1. **AuthZEN 1.0**: Used as the standard PEP-to-PDP authorization API interface profile.
2. **Cedar v4.12.0**: Selected as the primary in-memory PDP for fine-grained permit/forbid policies and contextual checks (`HUMAN × AGENT × GRANT × TASK`).
3. **OpenFGA Tuple Pattern**: Borrowed for ReBAC relationship checks (group membership, folder hierarchy), queried as a sub-decision by Cedar or the PEP wrapper using a `STRICT_AND` combining algorithm.

---

## Evidence Status & Project Status

* **Evidence Status**: **`PASS`**
  - 20-case Common TRIAXIS Authorization Corpus evaluated across all candidates
  - 100% Fail-Closed behavior confirmed under all 9 fault modes
  - 12 mandatory adversarial challenges completed
  - 2 material weaknesses identified and remediated via architectural specification

* **Project Status**: **`EVIDENCE_READY`** (`PRODUCT_INTEGRATION=false`)

> **NOTE**: Per Work Order Section 21, project status is `EVIDENCE_READY` awaiting operator review.
