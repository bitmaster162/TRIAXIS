# TRIAXIS Semantic Ingress Protocol v1.0

## Purpose

Test the boundary between natural-language control text and the already strict
structured scenario contract. The protocol targets a new failure class:
**syntactically valid but semantically unsupported structured state**.

The protocol is deliberately asymmetric. A deterministic surface scanner and
an extraction receipt may block, narrow, or request clarification. They may not
create authority merely because an action word was detected.

## Frozen boundary

A semantic-ingress record binds:

- exact source text and SHA-256;
- exact source spans and span digests;
- task/action nodes;
- structured scenarios;
- field-level provenance bindings;
- target, condition, modality, and authority basis;
- unresolved material fields;
- node dependencies and completion mode.

## Failure families

1. source or span integrity;
2. closed-schema/type/enum errors;
3. field-provenance gaps or value mismatch;
4. quoted/external content treated as authority;
5. prohibitions, questions, hypotheticals, and unsatisfied conditions promoted
   to active permission;
6. ambiguous target or unresolved critical field;
7. high-impact action under-classified or omitted from the task graph;
8. sensitive-data exfiltration omitted from the Data Gate;
9. broken dependency graph or receipt lineage;
10. safe positive controls.

## Validation discipline

The fault bank and generator are committed before product logic changes. R1 is
patch-triggering evidence against the frozen v2.8-RC2 candidate. A logic patch
must then pass:

- the full existing H/P/Q regression;
- all unit tests;
- R1;
- a fresh R2 batch generated only after the new candidate commit.

R1/R2 are commit-sealed tests produced by the same development process. They
are not independent reproduction and do not establish general natural-language
understanding.
