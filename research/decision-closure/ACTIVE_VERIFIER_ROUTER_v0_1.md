# AVR — Active Verifier Router v0.1

## Objective

Select the cheapest evidence-producing path that can reliably change or close the current commitment.

AVR is not a reasoning persona. It is a control plane.

```text
TASK / CURRENT STATE
       ↓
1. BIND
   target, scope, exactness, freshness, side effects
       ↓
2. DIRECT-SUFFICIENCY GATE
   can current model evidence support the bounded answer/action?
       ├─ YES → COMMIT → STOP
       └─ NO
       ↓
3. CAPABILITY ROUTE
   choose one capability whose output can change the commitment
       ↓
4. INSTRUMENT VALIDITY
   validate contract / scope / control / freshness where material
       ↓
5. EXECUTE
       ↓
6. RESULT CHECK
   valid + semantically applicable?
       ├─ YES → COMMIT
       └─ NO  → diagnose hazard → retry / fallback / cross-check
       ↓
7. BOUNDED CORRECTION
   correct only demonstrated defect
       ↓
8. REOPEN / STOP
```

## Router decision record

```json
{
  "decision_object": "...",
  "required_evidence_class": "NONE | COMPUTE | RETRIEVE | EXECUTE | VERIFY | CROSSCHECK",
  "direct_sufficiency": "YES | NO | UNCERTAIN",
  "selected_capability": "tool-or-null",
  "selection_reason": "action-changing reason",
  "instrument_check": "SKIP | REQUIRED",
  "fallback": "tool-or-null",
  "reopen_trigger": "material future evidence",
  "stop": true
}
```

## v0.1 routing rules

### Direct
Use no tool when:
- all load-bearing information is already present;
- computation/state depth is within reliable mental execution;
- exactness is not beyond reliable reproduction;
- no freshness/external side effect is required.

### Tool
Use a tool when at least one is true:
- exact computation exceeds reliable direct execution;
- answer depends on external/current/private state;
- execution must cause or inspect a real side effect;
- a deterministic verifier can falsify a candidate;
- state transitions are too long for reliable mental replay.

### Instrument check
Validate before commitment when:
- tool contract may not match target semantics;
- source freshness/scope matters;
- tool has failed or drifted previously;
- multiple providers disagree;
- the output is rejection-only or high-impact.

### Countermodel
Default OFF.
Invoke exactly one only when:
- a material applicability/identification assumption remains unresolved;
- a concrete alternative would change the action;
- no direct discriminator already settles it.

## Cost objective

Minimize:

`expected_error_cost + tool_cost + latency_cost + verification_cost`

subject to bounded risk/accuracy constraints.

Do not minimize tool calls by suppressing calls needed for correctness.
