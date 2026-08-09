# WMX / EBRC-Orchestrator v0.1

## Hypothesis

There is no credible universal "10x reasoning prompt." The largest gains for weak models appear when the scaffold externalizes the part the weak model is bad at.

The proposed weak-model exoskeleton is:

1. **Compact state/evidence ledger**
   - prune irrelevant history;
   - preserve only decision-relevant observations, provenance and unresolved variables.

2. **Orchestrator-only deliberate reasoning**
   - the coordinator owns decomposition, epistemic state, commitment and tool selection;
   - cheap executors do bounded tasks and need not simulate a full deliberative agent.

3. **EBRC decision record**
   - epistemic state;
   - bounded commitment now;
   - minimal witness;
   - one action-changing countermodel;
   - material reopen trigger.

4. **Selective external discriminator**
   - use calculator, simulator, search, code execution, database/readback, verifier or other tool only when it can change the commitment;
   - do not retrieve merely because retrieval is available.

5. **Verifier-driven correction**
   - external deterministic/environmental feedback dominates generic self-critique when available;
   - one correction loop by default, more only if the verifier exposes a new actionable defect.

6. **Zero-VOI stop**
   - stop when the bounded action is closed and no remaining affordable observation can change it.

## Why this targets weak models

Weak models have less spare capacity for:
- long history;
- state tracking;
- multi-agent role play;
- distinguishing correlated evidence;
- detecting their own reasoning defects.

The exoskeleton therefore moves those burdens into:
- compact structured state,
- externally checkable tools,
- explicit gating,
- deterministic or environment-grounded feedback.

## Falsification

Collapse WMX if:
- a plain CoT / direct-tools baseline matches it at lower cost;
- pruning loses material state more often than it prevents distraction;
- the orchestrator tool gate blocks useful tools or invokes harmful retrieval;
- verifier loops add tokens without producing verified corrections.
