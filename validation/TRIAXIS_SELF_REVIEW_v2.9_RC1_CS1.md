# TRIAXIS Self-Review — v2.9-RC1 against Composition/State CS1

- Candidate logic commit: `a8d07b121b51a17af2a7060a3c95cdf9f8ffc435`
- Protocol commit: `4bc66dd4614017544023d67316cefec7efab726b`
- Result: **12 PASS / 9 FAIL / 21 total**
- Decision: **REVISE**
- Successor: **v2.10-RC1**

## Material defects

- graph outcome depended on JSON node order;
- quoted/external actions contaminated user control surface;
- lexical noun ambiguity produced false action obligations;
- open-position trade intent was mapped to READ.

## Patch boundary

No policy, authority, budget, verification or structured input semantics were relaxed. The patch is limited to semantic scanner ruleset selection and order-invariant task-graph resolution.
