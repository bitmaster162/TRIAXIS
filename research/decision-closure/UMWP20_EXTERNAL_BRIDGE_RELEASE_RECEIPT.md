# UMWP20 External Bridge — Release Receipt v0.1.2

Status: `FROZEN_BEFORE_EXTERNAL_SOLVER_EXPOSURE`

Source benchmark semantics: UMWP answerable/unanswerable paired math problems as loaded by AbstentionBench.

Public bridge:
- 20 cases
- 10 answerable source items: UMWP ids 410–419
- 10 corresponding unanswerable mutations: UMWP ids 2910–2919
- output: ANSWER vs ABSTAIN plus RESOLVED vs UNRESOLVED
- three prompt arms: Ordinary, EBRC/Dual-State, Trialectic EBRC
- native ids hidden from public subject
- answerability labels hidden
- opaque letter-only case ids

Preflight:
- perfect fixture: 100% on all correctness metrics
- always-answer fixture: 0% abstention on unanswerable items and 100% overanswer rate
- leakage scan: PASS
- overall preflight: PASS

Subject kit SHA-256:
`4134986c2583be76f0b89434245bf62a3b2fece038899aaa3c397b96e549e567`

Private evaluator SHA-256:
`c0276ca71e1c1b7b350ecf7c579bc3fa929eb441b968a3190fdf6d441053fbf3`

The private answerability/reference-answer oracle is not committed.

Scoring preserves the source benchmark's native distinction:
- answerable item -> numeric reference answer
- unanswerable item -> abstain

Additional EBRC diagnostic fields do not replace native correctness.

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
