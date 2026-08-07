# TRIAXIS v3.32-RC2 Operator Card

## Classification

- Release: `TRIAXIS-v3.32-RC2-PROVIDER-NATIVE-COMPLETION-TRANSPARENCY`
- Product source: unchanged from v3.32-RC1
- Validation classification: `PASS_WITH_CONDITIONS`
- `LOCAL_REFERENCE_COMPLETE=true`
- `PRODUCTION_QUALIFIED=false`
- `EXACTLY_ONCE_ESTABLISHED=false`
- `REAL_PROVIDER_INTEGRATION=false`
- `PHYSICAL_INDEPENDENCE=false`
- `PHYSICAL_WORM_ESTABLISHED=false`
- `HARDWARE_MONOTONICITY=false`
- `deploy_permission=DENY`
- `can_trade=false`
- `capital_permission=DENY`

## Frozen evidence

- Full suite: `533/533 PASS`
- v3.32 closure: `27/27 PASS`
- v3.32 closure rows SHA-256: `019dd873658ad6226abd0a85ef678cab55d8bd59a534cd0305b8401142605b8a`
- Service smoke: `5/5 PASS`
- Service smoke rows SHA-256: `a5b9615329b3f0bfd0c50b495b41c343c3566079983a9648f64c922316f391b7`
- Terminal local rollback boundary: `BOUNDARY_CONFIRMED`
- Boundary rows SHA-256: `39543b34fe2bd025a5317112f4a7fb2f9f6a959068ffb04be77bbd68434f66e1`

## Operator rule

Do not open v3.33 or claim stronger durability from another same-host file,
SQLite database, process, key, or loopback service. The next stronger release
is gated by `TRIAXIS_PHYSICAL_EVIDENCE_GATE_v1.md`.
