# TRIAXIS v2.41-RC2 Recovery — Validation Receipt

```text
LOGIC COMMIT:                  9ef3a3850278a45eddfc15361f0e9955cb746d70
LOGIC TREE:                    f487f5bec1185077f447e092be389a6d7ea93a59
SRC TREE:                      7aac55268992d113d2477f33b5bec06ac0d93211
POST-PRODUCT EVIDENCE COMMIT:  54372437bb2eed08614e7f9fdc871c31ab592955
UNIT/HISTORICAL:               88 / 88 PASS
FROZEN PROTOCOL CASES:         48 / 48 PASS
POSITIVE CONTROLS:             20 / 20 PASS
```

The exact RC2 closure commit is the target of annotated tag
`TRIAXIS-v2.41-RC2-RECOVERED`. It is intentionally not embedded as a self-referential
value in this payload. Verify it with:

```bash
git rev-parse TRIAXIS-v2.41-RC2-RECOVERED^{commit}
git rev-parse TRIAXIS-v2.41-RC2-RECOVERED:src
```

The second command must return the SRC TREE above.

This receipt is same-lineage evidence, not independent certification.
