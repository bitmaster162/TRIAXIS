# ToolBench-X Adapter for AVR v0.1

External benchmark: `Foreverskyou/ToolBench-X`

ToolBench-X evaluates recoverable tool-environment unreliability with five hazard families:
1. Specification Drift
2. Invocation Error
3. Execution Failure
4. Output Drift
5. Cross-source Conflict

## Arms

### X0 Native no-hint
Use exception tools without recovery hints.

### X1 Native targeted hint
Use ToolBench-X `deferred_on_first_error` recovery hints as the positive recovery control.

### X2 AVR
No benchmark hint text.
AVR must infer:
- whether the tool result is still valid;
- hazard class;
- retry vs fallback vs verify vs cross-check;
- when evidence is sufficient to commit.

### X3 AVR + one countermodel
Same as X2, except one action-changing countermodel may run only for Cross-source Conflict or Specification Drift when two materially different interpretations remain after normal instrument checks.

## Preserve native evaluation

Do not replace ToolBench-X canonical final-answer scoring.
Additional diagnostics only:
- final task success;
- hazard diagnosis;
- recovery path;
- tool calls;
- failed calls;
- retries;
- fallbacks;
- cross-checks;
- time/tokens where available.

## Survival criteria

AVR survives if, under matched base model/task subset:
- X2 materially improves no-hint task success;
- X2 approaches targeted-hint recovery without receiving hazard labels;
- added calls are concentrated on hazard cases rather than clean/direct cases.

Countermodel remains optional unless X3 beats X2 on conflict/drift hazards without net harm or material cost inflation.
