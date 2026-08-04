# TRIAXIS v2.34-RC1 Recovery — Pre-Commit Validation Report

```text
BASELINE / ATOMICITY TRIGGER EVIDENCE COMMIT:
5f61a55a542f2305c9375d8880499ddfbf844c5a

TARGET:
Uncommitted TRIAXIS v2.34-RC1 Recovery candidate

RESULT:
PASS

UNIT + HISTORICAL TESTS:
117 / 117 PASS

FROZEN PROTOCOL CLOSURES:
86 / 86 PASS
positive controls: 32 / 32 PASS
protocol summaries SHA-256:
284d08f72861a2cadc9d6ea93250a195b67395336b8d504ec3682962ec001d15
```

## Closure matrix

```text
SUBJECT / CONTEXT BINDING:
17 / 17 PASS
rows SHA-256:
79681026d02877d3a95195aae55288bb24b7a646971eb3d0ef030a41abff0115

REVOCATION:
10 / 10 PASS
rows SHA-256:
602d4c608d3a3b0751cfd093ca541872da95b24acf912ce4cd2a2f38675c0d84

SNAPSHOT AUTHENTICATION / ROLLBACK:
15 / 15 PASS
rows SHA-256:
b8b3af1ab941af64d63edccbf8181b1fc9c673179bddd5bf87901defcd0f5cf9

AUTHORITY ANALYSIS INGRESS:
9 / 9 PASS
rows SHA-256:
15ea4402dae1990ece47cd0a9f0df64e04a3ab5533821bb4475e5695429461c8

HOST TIME ANCHOR:
8 / 8 PASS
rows SHA-256:
0c6e66f8d953a224a7b10d2b19f9256f95f50f89576b2e35206e4808c9525310

AUTHORITY / KEY TRANSITION:
9 / 9 PASS
rows SHA-256:
05f96ac2dd7279809526eeb8d14f79f4729f8c47714855e9cacce44e8ac545f4

EXACT ROOT CONTINUITY:
9 / 9 PASS
rows SHA-256:
121d0d54fe7569ae811e4b4e68f7229705af4a066c74b7a56b89e4399609823f

AUTHORITY ANALYSIS ATOMICITY:
9 / 9 PASS
positive controls: 4 / 4 PASS
rows SHA-256:
05c12354d1142896875be5435b4c2e6a8b9ef5be436b138e8e998660c4241b82
```

## Closed trigger

The exact v2.33 product accepted a signed envelope into monotonic local state
before validating the associated Analysis Bundle. Every tested analysis reject
returned `BLOCK`, but fresh failures consumed sequence 1 and a rejected
successor advanced sequence 1 to 2.

v2.34 freezes the exact bundle and envelope, performs non-mutating envelope
authentication and host-time checks, validates Bundle v5 against the parsed
snapshot, and calls the mutating guard only after analytical `PASS`.

The final `guard.accept` still re-authenticates and rechecks root, expiry,
sequence, parent, rollback/fork, root continuity and explicit handoff under its
lock. A state change between preparation and commit therefore blocks rather
than silently committing stale preparation.

## State invariant

```text
analysis_or_trust_result != PASS
=> checkpoint_after == checkpoint_before
```

The frozen v2.7 bank verifies both fresh and successor rejection paths, plus
valid genesis/successor advancement and pre-analysis failure controls.

## Compatibility boundary

- AuthorityAnalysisSession v1 and v2 identifiers remain exported.
- AuthorityAnalysisSession v3 is the active prepare-before-commit contract.
- Bundle v5, Registry v2, Trust Snapshot v2, Envelope v1, Transition v1 and
  Checkpoint v2 wire contracts remain unchanged.
- Explicit low-level Bundle v5 validation remains available for historical
  reproduction; generic authority ingress remains blocked.

## Static checks

```text
COMPILEALL: PASS
TARGET PY_COMPILE: PASS
GIT DIFF CHECK: PASS
```

## Scope

This establishes deterministic same-lineage pre-commit conformance for
in-process prepare-before-commit authority analysis. It does not establish a
durable transactional store, cross-process compare-and-swap, distributed
consensus, exactly-once external execution, independent certification, live
external tool safety or Production qualification.
