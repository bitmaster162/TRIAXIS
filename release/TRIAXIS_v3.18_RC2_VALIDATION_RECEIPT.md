# TRIAXIS v3.18-RC2 Validation Receipt

## Product identity

- RC1 product commit: `cfd376bdf40006e2958304f30c5617cb23e5f524`
- RC1 product tree: `6d0a4a37786c03985f2cd95748e1ae541577ab43`
- RC1 source tree: `1c5e4d0d3767add8c7b57a1d8975aab5cb553ddf`
- RC1 tag: `TRIAXIS-v3.18-RC1-SINGLE-HOST-MULTIPROCESS-CONFORMANCE`

## Exact-product validation

The annotated RC1 tag was checked out into a detached worktree.

- Unit/historical tests: `315 / 315 PASS`
- Multi-process conformance: `9 / 9 PASS`
- Worktree: clean

## Post-commit boundary test

The exact RC1 product was started as three authority processes on one host.
The validation process confirmed, without recording secret values, that:

- all authority processes shared one OS UID;
- the shared host user could observe the names of all private-key and admin-token environment variables;
- the shared user could write every authority state directory;
- the shared user could signal every authority process.

Result:

```text
BOUNDARY_CONFIRMED
```

This does not invalidate the v3.18 claim. It confirms the claim boundary:
single-host process separation is not physical or administrative independence.

## RC2 decision

No product-logic patch is justified. RC2 is validation-only and adds:

- post-commit boundary evidence;
- reproducible boundary script;
- release declaration and index;
- final validation receipt.

## Permissions

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
production_qualified=false
physical_multi_admin_conformance=false
```
