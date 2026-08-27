# TRIAXIS RHE — Authenticated SPIFFE Composition R1

Status: `CANDIDATE / STACKED ON PR #17 / NO MERGE / NO DEPLOY`

Parent reviewed head:
`9ddea3edfc1b3b5aded9739369eb3b5af3e1c733`

## Purpose

Compose two existing controls instead of creating another evidence system:

1. existing TRIAXIS v3.6 Ed25519 authentication for authorization tokens and state witnesses;
2. PR #17 strict execution-time SPIFFE/provider/mapping provenance immediately before `PREPARED`.

## Boundary

```text
signed authorization token
-> verify Ed25519 / purpose / trust registry / validity
-> require configured gate signer + trust domain
-> signed observed state
-> verify Ed25519 / purpose / trust registry / validity
-> require state signer == state adapter
-> strict SPIFFE workload boundary
-> re-check exact trusted provider + registry mapping/trust config
-> fresh VERIFIED workload identity fetch
-> stable identity/provenance correlation
-> SQLite PREPARED
-> STOP
```

## Non-goals

R1 does not:
- execute an external effect;
- deploy a service;
- call AWS;
- add RFC3161 or Object Lock;
- add a new signing primitive;
- retrieve a signing secret from Secrets Manager;
- enable trading or capital actions.

The signing primitive and trust registry already exist in TRIAXIS. This lane only composes them with the strict workload boundary.

## Tests

Focused tests require:
- valid signed SPIFFE token + signed state -> exactly `PREPARED`;
- raw unsigned token -> reject before workload fetch;
- forged token signature -> reject before workload fetch;
- valid token signed by wrong configured gate authority -> reject;
- unsigned state -> reject before workload fetch;
- signed state from non-adapter signer -> reject;
- signed path still rejects workload mapping drift;
- certificate rotation remains allowed for unchanged stable workload identity;
- same signed token + same workload remains idempotent.

## Gate

`MERGE=DENY`

until independent review and focused/regression runtime evidence are supplied for the exact candidate head.

`external_execution=false`
`can_trade=false`
`capital_permission=DENY`
`deploy_permission=DENY`
