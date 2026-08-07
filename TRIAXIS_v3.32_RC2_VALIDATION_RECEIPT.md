# TRIAXIS v3.32-RC2 Validation Receipt

## Subject

- RC1 product commit: `cc02b0a17a2b9edbe83d3d0d970baec533a5c17a`
- RC1 product tree: `3e6f06b385c13435045cf935303cfcccb28b82fe`
- RC1 source tree: `aa675acd75f8d93cb8695b11db5d70467116f63f`
- RC1 tag object: `0e3bd9c591d81582b0ba35dff2617ef5f295c71d`
- Post-product evidence commit: `38ef64f663e4bc4d2d83c70ba1a1ffd7dd2cb507`

## Exact RC1 validation

- Full suite: `533/533 PASS`
- v3.32 closure: `27/27 PASS`
- Closure rows SHA-256: `019dd873658ad6226abd0a85ef678cab55d8bd59a534cd0305b8401142605b8a`
- Service process smoke: `5/5 PASS`
- Service rows SHA-256: `a5b9615329b3f0bfd0c50b495b41c343c3566079983a9648f64c922316f391b7`

## Post-commit adversarial boundary

- Status: `BOUNDARY_CONFIRMED`
- Rows SHA-256: `39543b34fe2bd025a5317112f4a7fb2f9f6a959068ffb04be77bbd68434f66e1`
- Subject commit: exact RC1 product commit.

The boundary proves that no additional same-host process or database can
legitimately upgrade this release into a physical exactly-once claim. A fully
coordinated rollback of all local evidence domains restores an old permissive
view.

## Classification

`PASS_WITH_CONDITIONS`

Conditions are the explicit external evidence gates G1-G5. RC2 does not grant
deployment, trading, capital, or production authority.
