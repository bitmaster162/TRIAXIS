# TRIAXIS Metamorphic and Fault-Injection Protocol v1.0

## Purpose

Test relations between decisions rather than replaying isolated case templates. The candidate is frozen before the exact property instances are emitted.

## Core properties

1. **Hard-blocker dominance:** adding a hard blocker cannot yield `ALLOW` or `ALLOW_WITH_LIMITS`.
2. **Restriction monotonicity:** adding risk or removing a required control cannot make a decision less restrictive.
3. **Material-contradiction coverage:** a contradiction material to the decision blocks or holds the decision regardless of X level.
4. **Cross-axis integrity:** integrity gates apply when their evidence/state/tool output is relied upon, even if direct execution is X0.
5. **Irrelevant-mutation invariance:** nonce, aliases and unrelated presentation metadata do not change the decision.
6. **Positive liveness:** when the only blocker is repaired and all other conditions remain valid, a bounded action can proceed.

## Limitation

The candidate and validation framework are produced in one environment. This is not independent assurance. The protocol is useful because the candidate commit is immutable before exact instances and because assertions concern cross-case relations not covered by the prior isolated case bank.
