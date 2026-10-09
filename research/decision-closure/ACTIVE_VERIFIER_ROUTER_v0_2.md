# AVR — Active Verifier Router v0.2

## Core change from v0.1

AVR is no longer a binary `DIRECT vs TOOL` router.
It first resolves the **decision state**:

```text
TASK / CURRENT STATE
       ↓
1. BIND
   target, scope, exactness, freshness, side effects
       ↓
2. INTERNAL SUFFICIENCY
   current evidence already supports answer/action?
       ├─ YES → DIRECT / COMMIT / STOP
       └─ NO
       ↓
3. CAPABILITY AVAILABILITY
   is there a semantically matching external capability?
       ├─ NO → CANNOT_ANSWER / HOLD
       └─ YES
       ↓
4. INPUT SUFFICIENCY
   are all material required inputs present?
       ├─ NO → REQUEST_FOR_INFO
       └─ YES
       ↓
5. CAPABILITY ROUTE
   choose COMPUTE / RETRIEVE / EXECUTE / VERIFY / CROSSCHECK
       ↓
6. INSTRUMENT VALIDITY
   contract, scope, freshness, known-good control where material
       ↓
7. EXECUTE
       ↓
8. RESULT APPLICABILITY
   result valid and semantically bound to target?
       ├─ YES → VERIFIED COMMITMENT
       └─ NO → diagnose hazard → retry/fallback/cross-check
       ↓
9. BOUNDED CORRECTION
       ↓
10. REOPEN / STOP
```

## Decision states

```json
{
  "decision_state": "DIRECT | TOOL_CALL | REQUEST_FOR_INFO | CANNOT_ANSWER | HOLD",
  "decision_object": "...",
  "required_evidence_class": "NONE | COMPUTE | RETRIEVE | EXECUTE | VERIFY | CROSSCHECK",
  "matching_capability": "tool-or-null",
  "missing_required_inputs": [],
  "selected_capability": "tool-or-null",
  "instrument_check": "SKIP | REQUIRED",
  "fallback": "tool-or-null",
  "reopen_trigger": "material condition",
  "stop": true
}
```

## Routing invariants

1. Do not call a tool merely because a relevant-looking tool exists.
2. Do not invent missing required parameters.
3. Do not return `cannot_answer` when the user can supply one bounded missing input.
4. Do not ask for information that is optional or already inferable without material ambiguity.
5. Do not use external execution when current evidence is already sufficient and direct execution is reliable.
6. Tool output is evidence, not truth: validate instrument and semantic applicability where material.
7. Correct only demonstrated defects.
8. Stop when no affordable observation can change the commitment.

## Countermodel policy

`DEVIL_DEFAULT = OFF`.

Invoke exactly one action-changing countermodel only if:
- a material applicability/identification assumption remains unresolved;
- a concrete alternative changes the action;
- it has positive evidence-specific affordance;
- no direct discriminator already settles the choice.

No persona theatre, majority vote, or repeated adversarial rounds.

## Evidence motivating v0.2

- external blind When2Tool slice: 45/45 exact with 33 calls vs 45 always-tool calls (-26.7%, 0 pp accuracy loss);
- When2Call-derived State-32: naive tool-centric 16/32 vs AVR four-state gate 32/32 (+50 pp, derived not official score);
- Tool Trust Routing-12: raw tool 8/12 -> validated 12/12; active routing reduced calls 24 -> 16;
- CorrectBench-derived published-mutant subset: 16/28 -> 28/28 after one verifier-driven correction round.

Current hypothesis: amplification comes from **state-aware capability control plus executable falsification**, not from mandatory same-model debate.
