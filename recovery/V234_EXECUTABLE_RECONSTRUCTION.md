# TRIAXIS v2.34-RC1 — Executable Recovery Boundary

```text
RECOVERY_BASELINE_COMMIT: 924ab55d054e58d2daf25fed6a81a8edd6226302
VERIFIED_ANCESTOR:        f107f75c3d0972cc6790bcda03de57c83f06fff0
VERIFIED_ANCESTOR_TREE:   9d4db0aadef0e9f5942c26849d1b5b603e39e962
HISTORICAL_V2.34_OBJECTS: unavailable
RECOVERY_CLASS:           new recovery-lineage implementation
```

## Purpose

The uploaded v2.34 artifacts contained the authority-analysis ingress, frozen
atomicity tests, protocols and reports, but not the complete Git repository or
all imported Python modules.  This recovery commit reconstructs the minimum
executable dependency surface required to run the physically available v2.34
atomicity tests and the post-product snapshot-freshness trigger.

It does **not** claim byte identity with the unavailable historical v2.34
product commit.  Historical commit and tree identifiers embedded in imported
artifacts remain source-backed claims only.

## Reconstructed modules

- canonical JSON materialization and SHA-256 sealing;
- bounded Analysis Bundle v5 validation;
- authenticated Ed25519 trust-snapshot envelopes;
- process-local monotonic trust checkpoint;
- Analysis Bundle v5 fixtures;
- trust snapshot and envelope fixtures;
- recovered v2.7 atomicity oracle harness;
- focused recovery regression tests.

## Cryptographic fixture boundary

The validation signer is generated from a public, domain-separated test label.
It is intentionally reproducible and is not a secret or operational credential.
No PEM, environment secret, API credential or deployable private-key file is
stored in the repository.

## Validation scope

```text
ORIGINAL V2.10 TESTS:       47 / 47 PASS
IMPORTED/RECOVERED TESTS:    9 / 9 PASS
TOTAL:                      56 / 56 PASS
COMPILEALL:                 PASS
GIT DIFF CHECK:             PASS
```

The recovered v2.7 harness preserves the historical rows digest only after all
recovered exact oracles pass.  It also emits a separate
`recovered_rows_sha256`; therefore the preserved historical digest is not
misrepresented as byte-for-byte reproduction of the unavailable original
serializer.

## Known intentional defect

This recovered v2.34 behavior intentionally does not require:

```text
snapshot.evaluation_tick == host trusted_evaluation_tick
```

That omission is the target of frozen post-product protocol v2.8.  The defect
must be captured against this committed recovery baseline before any v2.35
repair.

## Non-claims

- no reconstruction of unavailable v2.11-v2.34 Git history;
- no independent certification;
- no durable or distributed checkpoint storage;
- no production key custody;
- no trusted external clock;
- no live external-action permission;
- no Production qualification.
