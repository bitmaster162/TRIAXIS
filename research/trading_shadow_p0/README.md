# TRIAXIS Trading Shadow P0

Status: DRAFT CANDIDATE / OFFLINE ONLY / NO ACTION

Baseline lineage:

- `main = ae280d905c63e4ba0bcadb4633f01a1fb9657920`
- research parent `research/decision-closure-ebd-v0.3 = 73832f9cd03657388191211998723b83a6b37eec`

This adapter consumes `triaxis.trade_audit_request.v1` from the TradingOS P0 shadow federation and emits `triaxis.trade_adjudication.v1` from explicitly supplied audit work.

## Important research-bound correction

Current TRIAXIS evidence does **not** support mandatory persona debate or a default DEVIL/countermodel stage.

Therefore the trading adapter uses:

```text
strongest evidence-bound support
→ direct falsification first
→ optional countermodel only after an explicit trigger
→ survivor/trialectic closure
→ evidence audit
```

`COUNTERMODEL_DEFAULT=false`.

The legacy ANGEL/DEVIL vocabulary may appear in the transport request for compatibility, but the P0 implementation does not pretend to instantiate independent personas or agents. The direct falsifier is the normal adversarial path.

TRIAXIS remains:

```text
TRIAXIS_IS_CONTESTANT=true
TRIAXIS_IS_ORACLE=false
execution_authority=NONE
can_execute=false
can_trade=false
capital_permission=DENY
```

No model call, tool call, runtime registration, signal, order, exchange interaction, merge, deploy or capital effect belongs to this adapter.
