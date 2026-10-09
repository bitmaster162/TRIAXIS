# When2Tool External Blind-45 Result v0.1

## Source

Official `Trustworthy-ML-Lab/when2tool` deterministic generators at commit `66f100089d1f3f7e7f2acee279c4dbf6e7ae5e2c`.

Slice:
- Calculator / Statistics / Hash
- easy / medium / hard
- 5 cases per cell
- 45 total
- selected from tail test positions `[25,31,37,43,49]` within each 50-item test split

The selected answers were hidden until all AVR routes and outputs were frozen.
The router did not receive benchmark `difficulty` labels or expected answers.

## Arms

| Arm | Exact accuracy | Tool calls |
|---|---:|---:|
| Always Tool | 45/45 = 100% | 45 |
| AVR Conservative | 45/45 = 100% | 33 |

Effect:
- accuracy delta: `0 pp`
- calls saved: `12`
- tool-call reduction: `26.7%`

## Router policy

Direct only when the answer is reproducible without long state/exact computation.
Tool when exact computation exceeds reliable direct execution, the requested result is an unfamiliar hash, or statistical execution is long/error-prone.

Observed direct routes:
- 5 trivial calculator items
- 5 easy statistics items
- 2 medium median items

All remaining 33 items were routed to the benchmark-matching deterministic capability.

## Interpretation

This is the first external blind evidence in the project for the `IS A TOOL NEEDED?` layer.
It shows that conservative instruction-only routing can reduce unnecessary tool use while preserving exact accuracy on this slice.

It is not a reproduction of When2Tool's hidden-state Probe&Prefill method and not the full 2,250-item single-hop test set.

## Claim boundary

Do not claim:
- full-benchmark When2Tool performance;
- learned tool-necessity calibration;
- 26.7% general savings across environments;
- superiority to Probe&Prefill.

Current supported claim:

> On a frozen 45-item external When2Tool slice spanning three environments and three difficulty levels, AVR preserved 45/45 exact accuracy while reducing tool calls from 45 to 33.
