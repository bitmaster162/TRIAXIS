# PI-002 execution identity provenance decision R1

Decision: `HARDEN`

Rationale: the RHE execution boundary should not rely on an implicit caller assertion that an in-memory identity object is authentic.

For SPIFFE-bound tokens, PREPARED must require trusted provider provenance in addition to field correlation.

Implementation is to occur on a separate branch from main and receive independent review before any merge.

No effectful runtime permission is granted by this decision.
