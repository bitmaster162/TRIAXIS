# TRIAXIS Research Integration Protocol v1.0

The protocol tests the research-derived invariants against the v3.0 Decision Assurance Case validator.

Required positive control:

- A2 case with a Primary, heterogeneous Devil, executable Falsifier, evidence-backed load-bearing claims, resolved material defeater and narrowed authority request must PASS.

Required negative oracles:

1. Same-model/same-context role is classified `I0_ROLE_PLAY_ONLY`.
2. Synthesis authority expansion blocks.
3. Synthesis self-authorization blocks.
4. Decorative falsifier blocks.
5. Open decision-blocking defeater escalates.
6. Resolved defeater without evidence blocks.
7. Unsupported load-bearing claim blocks unless labelled `UNVERIFIED_ASSUMPTION`.
8. A3 without external verifier blocks.
9. R3 without heterogeneous review blocks.
10. R4 without human approval blocks.
11. Gate request cannot contain its own outcome.
12. Honest unverified assumption remains structurally valid without becoming verified.

This is a structural protocol. It does not establish empirical superiority, source truth or production safety.
