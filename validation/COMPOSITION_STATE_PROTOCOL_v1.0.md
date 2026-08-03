# TRIAXIS Composition and State Protocol v1.0

Status: **Frozen before evaluation of TRIAXIS v2.9-RC1**

## Purpose

Test safety properties that are not established by isolated structured-input,
routing, or semantic-ingress examples:

1. task-graph outcome is invariant to serialization order;
2. dependencies propagate blockers without depending on list position;
3. completion mode is respected after every node decision is known;
4. quoted and external data do not become user-authorized action surfaces;
5. lexical ambiguity in a bounded scanner does not create obvious false action
   nodes for `message`, `email`, `order`, or `open position`;
6. direct imperative action surfaces remain detected;
7. hard blockers dominate accumulated limits;
8. source/span/provenance and downstream governance remain compositional.

## Oracle

Each case fixes an exact `(status, primary_reason)` pair. The oracle is based on
normative role/modality separation, dependency semantics, action-risk floors,
and the decision-severity lattice. It is not derived from candidate output.

## Commit binding

The generator binds:

- protocol commit;
- candidate logic commit;
- candidate version;
- batch id;
- generated payload SHA-256.

## Scope limitation

This protocol tests a bounded deterministic projection and explicit English
control surfaces. It does not establish general natural-language understanding,
independent validation, or live execution safety.
