# TRIAXIS v2.10-RC2 — Release Index

## Primary operator files

- `spec/TRIAXIS_CONTROL_STACK_v2.10_RC2.md` — complete normative specification.
- `release/TRIAXIS_v2.10_RC2_SYSTEM_PROMPT.md` — operational prompt.
- `release/TRIAXIS_v2.10_RC2_OPERATOR_CARD.md` — compact control card.
- `release/TRIAXIS_v2.10_RC2_RELEASE_NOTES.md` — trigger and patch history.
- `release/TRIAXIS_v2.10_RC2_VALIDATION_RECEIPT.md` — commits, trees and validation hashes.

## Executable projection

- `src/triaxis/input_contract.py`
- `src/triaxis/semantic_ingress.py`
- `src/triaxis/projection.py`
- `tests/`

## Validation

- frozen routing, semantic-ingress and composition/state protocols;
- trigger evidence for v2.9;
- RC1 and fresh RC2 commit-bound evidence;
- machine-readable schemas.

## Integrity

The distributed bundle includes a normative payload manifest, evidence manifest, full Git bundle and an external archive SHA-256 sidecar. Archive hash is packaging evidence, not a substitute for the normative payload manifest.
