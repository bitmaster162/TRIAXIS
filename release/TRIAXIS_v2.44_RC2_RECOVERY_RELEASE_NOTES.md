# TRIAXIS v2.44-RC2 Recovery — Validation-only Release Notes

RC2 does not change the v2.44-RC1 product source. It closes the release-candidate
cycle after a fresh post-product scope-atomicity protocol passed all cases.

## Logic identity

```text
RC1 logic commit: fe465aabde921b6c0b94d449114cf202cc0b24da
RC1 tree: 03a396c877e03be87a56ea2442f9e9a15a37d7f7
RC1 src tree: d941c4032c8e00ca71816f0f1f56cafa043d329a
```

The RC2 commit may add only tests, validation evidence and release metadata.
Its `src` tree must remain byte-identical to RC1.

## Post-product evidence

```text
Protocol: TRIAXIS_AUTHORITY_CHECKPOINT_SCOPE_ATOMICITY_TRIGGER_v3.9_RECOVERY
Result: 9 / 9 PASS
Positive controls: 4 / 4 PASS
Rows SHA-256: 8842d77fe7b61e28a86763dee89f4237eab662bc27fc461efd63493d6558b569
Evidence commit: 1d8c289216ce27020208a458109f4a4295571187
```

The result is same-lineage validation, not independent certification.
