# TRIAXIS v3.5-RC1 Operator Card

An authorization token is usable only before the earliest expiry among:

- action envelope;
- exact policy bundle;
- assurance PASS attestation;
- authenticated state witness;
- every approval.

Validate at the execution preparation tick. A timeout, stale source, state
drift, revoked policy or unknown effect is not permission.

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
```
