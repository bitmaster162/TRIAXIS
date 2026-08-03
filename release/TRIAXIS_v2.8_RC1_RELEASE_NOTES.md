# TRIAXIS v2.8-RC1 — Release Notes

## Evidence trigger

Frozen v2.7-RC2 failed all 28 cases in commit-bound Q1 input-contract fault injection. Failures included parser crashes, unsafe truthy-string coercion, unknown-field bypass, invalid enums/ranges, missing required fields and semantic inconsistencies reaching downstream gates.

## Root cause

The deterministic projection had governance gates but no strict fail-closed contract in front of them. Safety-critical fields could be omitted, coerced or ignored before policy, authority and integrity logic executed.

## Changes

1. Added `INPUT_CONTRACT_GATE` before Router and every downstream control.
2. Added closed field set, exact primitive types, enum/range validation and conditional dependencies.
3. Added semantic consistency checks for gate activation and material results.
4. Added deterministic `BLOCKED_BY_INPUT_CONTRACT` receipt with structured errors.
5. Added machine-readable JSON Schema synchronized with the executable validator.
6. Added full 39-template unit regression plus frozen Q1 regression.
7. Preserved v2.7 decision semantics for valid H1–H4 and P1/P2 scenarios.

## Scope limitation

The gate validates already-structured scenarios. It does not prove that a natural-language extractor included every material fact or selected the correct E/X level.
