# TRIAXIS Physical Evidence Gate v1

## Gate purpose

This gate prevents semantic version inflation after the local reference has
exhausted what same-host simulation can prove.

No successor to v3.32 may be labelled a stronger execution-safety release until
at least one external evidence tranche is attached and independently
reproducible.

## Required external evidence tranches

### G1 — Real provider-native idempotency

- named provider and API operation;
- provider documentation or contractual guarantee for the idempotency key;
- captured request/response binding the exact stable `effect_id`;
- replay test proving the provider does not repeat the effect;
- explicit UNKNOWN/reconciliation behavior;
- retention and namespace limits;
- redacted but verifiable receipt hashes.

### G2 — Independent transparency checkpoint domains

- at least three separately administered authorities;
- at least two physical hosts and two failure domains;
- distinct credentials and key custody;
- authenticated transport;
- evidence that one operator cannot silently restore the threshold majority;
- fault tests for stale member, split view, unavailable member and restart.

### G3 — Physical immutable completion storage

- object-lock/WORM configuration from an external storage provider;
- retention mode and retention-until evidence;
- deletion/overwrite denial test;
- legal-hold behavior where applicable;
- independent account or administrative boundary;
- external audit or provider receipt.

### G4 — Protected monotonic state

At least one of:

- HSM/KMS-backed monotonic counter;
- TPM/TEE-backed anti-rollback state;
- public transparency log checkpoint;
- independently administered external timestamp/notary service.

### G5 — Independent validation

- validator not sharing the product repository write authority;
- exact release digest and source commit;
- complete test protocol and raw results;
- disclosed conflicts of interest;
- explicit certification scope and exclusions.

## Minimum successor rule

A successor implementation may be opened only when:

- G1 is complete; and
- either G2+G3 or G2+G4 is complete; and
- the evidence is bound to an exact Git commit and immutable artifact digest.

Until then, the canonical state is:

- `LOCAL_REFERENCE_COMPLETE=true`
- `PRODUCTION_QUALIFIED=false`
- `EXACTLY_ONCE_ESTABLISHED=false`
- `DEPLOY_PERMISSION=DENY`
- `CAN_TRADE=false`
- `CAPITAL_PERMISSION=DENY`
