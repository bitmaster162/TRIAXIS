# MULTI-PDP COMPOSITION RECEIPT — E002-R1

* **Architecture Under Test**: `PEP -> AuthZEN 1.0 Interface -> Cedar (ABAC PDP) + OpenFGA (ReBAC PDP)`
* **Combining Algorithm**: `STRICT_AND` (Both PDPs must return verified `ALLOW`)
* **Fail-Closed Rule**: `NO VERIFIED ALLOW FROM BOTH AUTHORITIES => DENY`

## Composition Matrix (Scenarios A–H)

| Scenario | Cedar ABAC Decision | OpenFGA ReBAC Decision | Combining Rule | Combined Decision | Result |
|:---|:---|:---|:---|:---|:---|
| **Scenario A** | `ALLOW` | `ALLOW` | `STRICT_AND` | `ALLOW` | ✅ PASS |
| **Scenario B** | `DENY` | `ALLOW` | `STRICT_AND` | `DENY` | ✅ PASS |
| **Scenario C** | `ALLOW` | `DENY` | `STRICT_AND` | `DENY` | ✅ PASS |
| **Scenario D** | `DENY` | `DENY` | `STRICT_AND` | `DENY` | ✅ PASS |
| **Scenario E** | `UNAVAILABLE` | `ALLOW` | `STRICT_AND` | `DENY` (Fail-Closed at PEP) | ✅ PASS |
| **Scenario F** | `ALLOW` | `UNAVAILABLE` | `STRICT_AND` | `DENY` (Fail-Closed at PEP) | ✅ PASS |
| **Scenario G** | `ALLOW (v0 Stale)` | `ALLOW` | `STRICT_AND + Version Check` | `DENY` (Version Mismatch) | ✅ PASS |
| **Scenario H** | `ALLOW` | `ALLOW (Stale Tuple)` | `STRICT_AND + Freshness Check` | `DENY` (Stale Relationship) | ✅ PASS |

## Proof of Anti-OR Safety
The composition test proves that an accidental `OR` combining rule would have incorrectly granted access in Scenarios B, C, E, F, G, and H. The enforced `STRICT_AND` rule prevented all unsafe single-authority bypasses.
