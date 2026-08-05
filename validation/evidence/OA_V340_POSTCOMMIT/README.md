# TRIAXIS v3.4-RC1 post-commit effective-expiry failure

Exact product commit `1ec7eafbdfff5a25bd7256c49d90917be673a922`
passed 187/187 tests and both prior closure triggers.

Fresh temporal trigger: **FAIL (1/4 PASS, 3/4 FAIL)**.

The authorization token inherited only the action-envelope expiry. It remained
valid after the exact policy bundle, assurance PASS attestation or authenticated
state witness had expired.

Required correction: token expiry must be the minimum of every authority and
freshness source used to issue it, including action, policy, assurance, state and
all approvals.
