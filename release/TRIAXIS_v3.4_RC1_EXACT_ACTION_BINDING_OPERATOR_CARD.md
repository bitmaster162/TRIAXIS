# TRIAXIS v3.4-RC1 Operator Card

Before an action reaches policy evaluation, verify:

1. exact Decision Assurance Case digest;
2. exact Evidence Report digest;
3. exact assured-action request digest;
4. PASS attestation from the configured issuer and trust domain;
5. fresh policy and state witness;
6. exact payload/tool/target binding;
7. required independent approvals;
8. single-use nonce and durable execution ledger.

Any mismatch, registry type other than issuer-to-domain mapping, stale object or
unknown outcome produces `DENY`/`ESCALATE`.

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
```
