# CorrectBench-derived Mutation Rescue v0.1

## Status

`DERIVED_PYTHON_ORACLE_NOT_NATIVE_CORRECTBENCH`

This experiment uses published HDLBits mutant records from `AutoBench/CorrectBench`, but does **not** claim a native CorrectBench score because Icarus Verilog was unavailable in the active runtime.

The Python oracle is restricted to selected combinational mutants whose behavior is unambiguous under 2-state semantics.

## Frozen design

Selected tasks:
- `thermostat`
- `kmap4`
- `mux9to1v`

Baseline test vectors were frozen before the selected mutant records were inspected.

### Frozen baseline

`thermostat` — 4 tests

`kmap4` — 4 tests

`mux9to1v` — selectors `0,1,4,8,9,15`, with distinct fixed input words frozen before mutant inspection.

## Mutant adjudication

Scoreable mutants:
- thermostat: 9
- kmap4: 10
- mux9to1v: 9
- total: 28

Excluded from ordinary Python mutation score:

1. one thermostat mutant adds a second continuous driver to `heater`; correct behavior depends on native Verilog 4-state/multiple-driver semantics and is marked `NATIVE_SIM_REQUIRED`;
2. one mux9to1v mutant only adds an explicit `default: out = 16'hFFFF`, which is behaviorally equivalent to the reference default `'1` and is quarantined as an equivalent/no-op mutant.

## Result

Frozen baseline:

- **16/28 = 57.1% mutation kill**
- survivors: 12

One verifier-driven correction round:

- add only test vectors that distinguish escaped mutants from the specification;
- 11 tests added total;
- **28/28 = 100% mutation kill**
- **12/12 frozen survivors rescued**
- absolute lift: **+42.9 percentage points**

By task:

- thermostat: `8/9 -> 9/9`
- kmap4: `4/10 -> 10/10`
- mux9to1v: `4/9 -> 9/9`

## Mechanism

The correction loop is not generic self-reflection.

It is:

`candidate tests -> executable/behavioral falsifier -> escaped mutant -> smallest distinguishing vector -> rerun -> stop`

This is strongly aligned with the system-level amplification hypothesis already supported by the blind exact quarry and Tool Trust Routing experiments.

## External consistency

CorrectBench itself uses functional simulation and self-validation/correction. Its paper reports a 70.13% overall pass ratio versus 52.18% for the previous LLM-based framework and 33.33% for direct LLM generation, with especially large improvement on sequential tasks.

This local derived experiment is not a reproduction of those paper-level numbers; it isolates the same mechanism on a small published-mutant subset.

## Current architectural implication

The strongest supported amplification path remains:

`state/context -> evidence/provenance -> semantic applicability -> valid executable verifier -> bounded correction -> verified commitment -> reopen/stop`

Default ANGEL/DEVIL debate is not required for this rescue path.

Governance unchanged:

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
