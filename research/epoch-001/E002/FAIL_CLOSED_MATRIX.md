# FAIL-CLOSED MATRIX — E002-R1

## Real Provider Failure Evaluation Matrix

TRIAXIS Target Principle: `NO VERIFIED AUTHORITY => NO EFFECT PERMISSION`

Per Section 7 of Work Order `E002-R1`, failure modes distinguish between:
1. `ENGINE_DECISION_DENY`: The engine evaluated the request and explicitly returned DENY.
2. `ENGINE_ERROR`: The engine returned a syntax, parse, or evaluation error.
3. `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY`: The PEP/Adapter wrapper intercepted an engine crash, connection failure, or timeout and enforced `FAIL-CLOSED AT PEP/ADAPTER`.

---

| Fault Mode | Cedar (AWS) | OPA v1.17.0 (CNCF) | OpenFGA v1.18.1 (CNCF) | AuthZEN 1.0 Adapter | PEP Enforcement |
|:---|:---|:---|:---|:---|:---|
| **No Matching Policy** | `ENGINE_DECISION_DENY` | `ENGINE_DECISION_DENY` | `ENGINE_DECISION_DENY` | `ENGINE_DECISION_DENY` | `DENY` |
| **Syntax Error in Policy** | `ENGINE_ERROR` | `ENGINE_ERROR` | `ENGINE_ERROR` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |
| **Policy / Model Load Failure** | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `ENGINE_DECISION_DENY` | `ENGINE_ERROR` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |
| **PDP Process Unavailable** | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |
| **PDP Connection Refused** | `ENGINE_DECISION_DENY` (In-process CLI) | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |
| **Request Timeout (>2s)** | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |
| **Malformed Request Payload** | `ENGINE_ERROR` | `ENGINE_ERROR` | `ENGINE_ERROR` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |
| **Unknown Principal / Resource** | `ENGINE_DECISION_DENY` | `ENGINE_DECISION_DENY` | `ENGINE_DECISION_DENY` | `ENGINE_DECISION_DENY` | `DENY` |
| **Stale Policy Version Simulation** | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `TRIAXIS_ADAPTER_CONVERTED_ERROR_TO_DENY` | `DENY` |

---

## Critical Evidence Distinction
An unavailable PDP does not itself "return DENY". In Scenarios where a PDP crashes, times out, or receives malformed input, TRIAXIS PEP/Adapter intercepts the error condition and enforces `FAIL-CLOSED AT PEP/ADAPTER` (`DENY`). 100% of evaluated failure modes enforce effect denial.
