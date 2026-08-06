# TRIAXIS v3.24-RC1 — Cross-Harness Governance

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Vendor-neutral clean-room adaptation: yes
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.24 imports high-value runtime contracts from several mature agent harnesses without importing their vendor transports or weakening TRIAXIS authority invariants.

## Adopted mechanisms

1. **Tiered policy evaluation** — `DEFAULT < EXTENSION < PROJECT < USER < ADMIN`; highest tier/priority wins and `DENY > ASK_USER > ALLOW` on ties.
2. **Extension non-grant rule** — an extension may narrow or request review but cannot create `ALLOW`.
3. **Headless fail-closed** — `ASK_USER` becomes `DENY` when no human approval channel exists.
4. **Model visibility minimization** — a global deny can hide a tool from model discovery.
5. **Per-segment shell checks** — simple pipeline/control segments are authorized independently; complex shell syntax requires exact one-shot approval.
6. **One-shot permission delta** — exact request + exact approval + nonce + expiry, consumed once in SQLite.
7. **Guardrail lifecycle** — pre-approval, post-approval/pre-execution, and post-execution checks. Mutating actions must be rechecked after approval.
8. **Filtered handoff** — only explicit artifacts and summary cross the boundary; context and authority never inherit implicitly.
9. **Durable interrupts** — checkpointed WAITING/RESUMED state, compare-and-swap resume, single-use transition, persistent reopen and explicit fork ancestry.
10. **Typed traces** — parented and digest-chained spans with declared redactions.
11. **Action/observation stream** — every observation references an exact prior action and matches run/correlation identity.

## Authority invariants

- Configuration and plugins cannot mint authority.
- Approval deltas are scoped to one exact request and one exact approval.
- Handoffs transfer evidence, not credentials.
- Resume is a state transition, not a replay of authority.
- Traces are audit evidence, not permission.
- Action/observation correlation does not prove semantic truth.

## Deliberately excluded

- Vendor auth/billing and telemetry dependencies.
- Broad approvals for arbitrary shell programs.
- Permission bypass modes.
- Implicit full-session handoffs.
- Unbounded recursive agent spawning.

## Known next boundary

Policy target matching in RC1 uses literal prefix comparison. Ambiguous URL/path encodings, traversal forms, backslashes and encoded separators must be treated as a separate post-product adversarial class. A v3.24 PASS does not claim canonical-target security.
