# MULTI-PDP COMPOSITION RECEIPT — E002-R3

* **Work Order**: `TRIAXIS-WO-AGY-GH-002-E002-R3`
* **Evidence Scope**: `LOCAL_EXECUTABLE_COMBINER_MODEL_ONLY`
* **Classification**: `EXECUTABLE_COMBINER_MODEL` (Architecture Falsification Evidence)
* **Combining Algorithm**: `STRICT_AND` (Both sub-authorities must return verified `ALLOW`)

---

## 1. Scope Reclassification Notice

Per Section 3 of Work Order `E002-R3`, the Scenarios A–H multi-PDP composition experiment evaluates an **`EXECUTABLE_COMBINER_MODEL`**. It validates the mathematical safety of combining multiple authorization signals (proving `STRICT_AND` prevents 100% of single-authority bypasses).

Because the recommended architecture for TRIAXIS is **`PEP -> AuthZEN Adapter -> Cedar PDP`** (which uses a single PDP rather than hot-path multi-PDP chaining), live network composition across multiple PDP microservices is not required for E002 closure.

---

## 2. Executable Combiner Scenarios (A–H)

| Scenario | Cedar Sub-Decision | OpenFGA Sub-Decision | Version Match | Relation Freshness | Combining Rule | Combined Decision | Result |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **Scenario A** | `ALLOW` | `ALLOW` | `True` | `True` | `STRICT_AND` | `ALLOW` | ✅ PASS |
| **Scenario B** | `DENY` | `ALLOW` | `True` | `True` | `STRICT_AND` | `DENY` | ✅ PASS |
| **Scenario C** | `ALLOW` | `DENY` | `True` | `True` | `STRICT_AND` | `DENY` | ✅ PASS |
| **Scenario D** | `DENY` | `DENY` | `True` | `True` | `STRICT_AND` | `DENY` | ✅ PASS |
| **Scenario E** | `UNAVAILABLE` | `ALLOW` | `True` | `True` | `STRICT_AND` | `DENY (Fail-Closed)` | ✅ PASS |
| **Scenario F** | `ALLOW` | `UNAVAILABLE` | `True` | `True` | `STRICT_AND` | `DENY (Fail-Closed)` | ✅ PASS |
| **Scenario G** | `ALLOW` | `ALLOW` | `False` | `True` | `STRICT_AND + Version` | `DENY (Version Mismatch)` | ✅ PASS |
| **Scenario H** | `ALLOW` | `ALLOW` | `True` | `False` | `STRICT_AND + Freshness` | `DENY (Stale Relation)` | ✅ PASS |

---

## 3. Anti-OR Safety Proof
If an `OR` rule were used, Scenarios B, C, E, F, G, and H would have produced unsafe `ALLOW` decisions. The `STRICT_AND` rule prevented 100% of single-authority bypasses.
