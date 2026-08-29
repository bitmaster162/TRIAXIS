# Active Verifier Router v0.3

Research-only control-plane candidate. No production/runtime change.

## State machine

```text
TASK / STATE
    ↓
BIND target / scope / exactness / freshness / side effects
    ↓
DECISION STATE
DIRECT | TOOL_CALL | REQUEST_FOR_INFO | CANNOT_ANSWER | HOLD
    ↓ (if TOOL_CALL)
CAPABILITY ROUTE
    ↓
INSTRUMENT / CONTRACT CHECK
    ↓
EXECUTE
    ↓
OBSERVATION CLASS
├─ transient execution error → retry once if idempotent → fallback once if needed
├─ invocation/schema mismatch → rebind to current schema; never invent missing values
├─ specification/unit/shape drift → deterministic normalization only if independently checkable
├─ output/invariant failure → BLOCK FINISH → independent recompute/cross-check
├─ cross-source conflict → provenance/scope/freshness discriminator; no majority vote
└─ valid + applicable → VERIFIED COMMITMENT
    ↓
BOUNDED CORRECTION
    ↓
REOPEN / STOP
```

## Recovery budget

- same-tool retry: max 1
- independent fallback: max 1
- independent cross-check: max 1
- repeated adversarial debate: forbidden
- one countermodel: default OFF

## Finish gate

Commit only when:
1. required answer fields exist;
2. no load-bearing contradiction remains unresolved;
3. instrument contract/scope/freshness is adequate for the target;
4. canonical answer surface is satisfied.

Core principle: **tool output is evidence, not truth**.

## Evidence status

### External blind When2Tool slice
Official deterministic generators, 45 frozen cases across Calculator / Statistics / Hash:
- always-tool: 45/45, 45 calls
- AVR: 45/45, 33 calls
- tool-call reduction: 26.7%
- accuracy loss: 0 pp

### When2Call-derived four-state mechanism test
Uses NVIDIA When2Call category-construction semantics, not official evaluation rows:
- naive binary tool-centric: 16/32
- AVR state gate: 32/32
- +50 pp

### ToolBench-X taxonomy-derived recovery
Recovery rules preregistered before concrete cases. Thirty derived hazard cases: six each for Specification, Invocation, Execution, Output, and Cross-Source uncertainty.
- targeted-recovery positive control: 30/30
- AVR v0.3 without hazard labels: 30/30
- clean controls: 10/10 with 0 unnecessary recovery calls

This is **not a native ToolBench-X benchmark score**. The hazard set was generated in-session from the published taxonomy and injection/recovery contract. Native ToolBench-X remains the next falsifier.

## Current decision

`DEVIL_DEFAULT = OFF`

Candidate core:

`decision state -> capability route -> instrument validity -> execute -> classify observed failure -> bounded recovery -> verified commitment -> reopen/stop`

Governance:
- TRIAXIS_IS_CONTESTANT=true
- TRIAXIS_IS_ORACLE=false
- PRODUCTION_CHANGE=false
- AUTO_MERGE=false
- MERGE_PERMISSION=DENY
