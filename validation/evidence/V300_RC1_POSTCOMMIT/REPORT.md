# TRIAXIS v3.0-RC1 Post-commit Research Trigger

Candidate commit: `5cafd19d9264e53331235c82847638dbee6d6e80`

Result: 1/8 conformant; 7/8 failures.

Material defects:

1. Heterogeneous reviewer could reuse the Primary evidence monoculture.
2. Falsification contract was not bound to test evidence.
3. Devil/reviewer context isolation was not enforced.
4. Gate payload digest syntax was not validated.
5. Stale evidence could support a current decision.
6. Load-bearing unverified assumptions could close as PASS.
7. Correlated evidence groups could satisfy high-risk review.

The failure bank was created after the v3.0-RC1 product commit and is preserved before the v3.1 patch.
