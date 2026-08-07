# FAIL-CLOSED MATRIX — E002

## Fault Mode Evaluation Matrix

TRIAXIS Principle: `NO VERIFIED AUTHORITY => NO EFFECT PERMISSION`

| Fault Mode | Cedar (AWS) | OPA (CNCF) | OpenFGA (CNCF) | AuthZEN (OIDF) PEP Wrapper |
|:---|:---|:---|:---|:---|
| **No Matching Policy** | `DENY` (Default) | `DENY` (`default allow = false`) | `DENY` (No tuple) | `DENY` |
| **Syntax Error in Policy** | `DENY` (CLI error -> PEP DENY) | `DENY` (Eval error -> PEP DENY) | `DENY` (Validation error) | `DENY` |
| **Policy Load Failure** | `DENY` | `DENY` | `DENY` | `DENY` |
| **PDP Unreachable / Timeout** | `DENY` (PEP default) | `DENY` (PEP default) | `DENY` (PEP default) | `DENY` (PEP default) |
| **Malformed Request Payload** | `DENY` | `DENY` | `DENY` | `DENY` |
| **Unknown Principal ID** | `DENY` | `DENY` | `DENY` | `DENY` |
| **Unknown Resource ID** | `DENY` | `DENY` | `DENY` | `DENY` |
| **Missing Context Variables** | `DENY` (Condition fails) | `DENY` (Condition fails) | `DENY` | `DENY` |
| **Stale Cached Decision** | `DENY` (Cache TTL expiry) | `DENY` (Cache TTL expiry) | `DENY` (Tuple cache expiry) | `DENY` |

## Summary
All four candidates achieve **100% Fail-Closed Behavior** when wrapped in a compliant TRIAXIS Policy Enforcement Point (PEP) adapter. No fault mode results in accidental authority grant (`ALLOW`).
