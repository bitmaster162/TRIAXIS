# UMWP20 External Bridge — Release Receipt

Status: frozen external-benchmark bridge

Source benchmark semantics: UMWP answerable/unanswerable paired math problems as loaded by AbstentionBench.

Public bridge:
- 20 cases
- 10 answerable source items: UMWP ids 410–419
- 10 corresponding unanswerable mutations: UMWP ids 2910–2919
- output: ANSWER vs ABSTAIN plus RESOLVED vs UNRESOLVED
- three prompt arms: Ordinary, EBRC/Dual-State, Trialectic EBRC

Subject kit SHA-256:
`05ec6f0a017c3cc4ef472467003c81058f87d031c59c5a9867c4131d060dd048`

Private evaluator SHA-256:
`cde98dbef66acb2dd3adef83a70462909dd857df19dacfab0a4e4c8d417183bb`

The private answerability/reference-answer oracle is not committed.

Scoring preserves the source benchmark's native distinction:
- answerable item -> numeric reference answer
- unanswerable item -> abstain

Additional EBRC diagnostic fields do not replace native correctness.

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
