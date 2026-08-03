# TRIAXIS Routing Semantics Protocol v1.0

## Purpose

This protocol tests whether a structured TRIAXIS candidate preserves the
semantic relationship between declared action type, execution-risk routing and
decision gates that remain material at X0.

It is a deterministic development validation protocol. It is not independent
assurance and does not validate natural-language extraction.

## Candidate binding

Each generated batch is bound to:

```text
PROTOCOL_ID
FRAMEWORK_COMMIT
CANDIDATE_SOURCE_COMMIT
CANDIDATE_VERSION
BATCH_ID
```

The generator derives its seed from those values and emits exact JSONL cases
plus a SHA-256 manifest before candidate evaluation.

## Property families

### 1. Action-effect lower bounds

`X0` means no external state change. Therefore a declared action that inherently
changes state cannot be routed as X0. The protocol uses conservative lower
bounds rather than universal final classifications:

```text
ANALYZE, READ                         minimum X0
WRITE, EXECUTE, DELETE                minimum X1
SEND, PUBLISH, DEPLOY                 minimum X2
SPEND, TRADE, MODIFY_ACCESS,
HANDLE_SECRETS                        minimum X3
```

The lower bound does not claim that the listed minimum is sufficient in every
context. Higher X levels remain valid where scope, privilege or blast radius
requires them.

Underclassification must fail at the input contract before downstream gates.

### 2. X0 decision-gate coverage

Absence of tool execution must not bypass an explicitly activated decision gate.
The protocol checks failing and passing forms of:

- target binding;
- object binding;
- preconditions;
- verification;
- budget;
- policy limits.

### 3. Severity preservation

A material restrictive finding must not be lost because the node is X0.
`ALLOW_WITH_LIMITS` is not equivalent to unrestricted `ALLOW`, and a hard
blocker must dominate a limited allowance.

## Outcomes

Each case specifies an exact expected status and primary reason. A case passes
only when both match.

## Scope limitations

The protocol does not prove that natural-language intent was classified into the
correct action type. It verifies only the supplied structured node. It also does
not establish production safety, independent review or generative control
quality.
