# TRIAXIS R6-A / R6-B — INTERNAL CONTROLLER VALIDATION

Date: 2026-08-13 (Asia/Bangkok)

## Scope

This stage validates controller behavior imported during R6 before any Deep Research result is allowed to influence TRIAXIS. It is not a model-intelligence benchmark and not evidence that a donor improves frontier task performance.

## Result

`R6AB_INTERNAL_CONTROLS = 18/18 PASS`

Evidence classes:
- historical replay controls: 3
- synthetic adversarial controls: 14
- simulated interface-isolation controls: 1

## Historical replay checks

### R4 + R5-B → automatic complexity deletion

Historical facts:
- R4: full TRIAXIS produced zero incremental task lift over minimal proposer+verifier.
- R5-B: full capability router again produced zero incremental value over targeted repo donor.

With the R6 research rule `null_limit = 2`, the full cognitive router transitions `CONDITIONAL -> REJECTED` with `REPEATED_ZERO_INCREMENTAL_LIFT`.

### R5-D → repo donor survives conditionally

A clean R5-D case where D_REPO_BEHAVIOR rescued a wrong minimal diagnosis admits repo behavior only as CONDITIONAL for the matching repo-scale fingerprint. It is not globally injected.

### R5-D → Long-Horizon V2 remains rejected

Two clean null increments over B2 drive the experimental Long-Horizon V2 donor to REJECTED, matching the original R5-D adjudication.

## Adversarial controls

The controller correctly enforces:

1. training improvement + held-out null -> REJECT;
2. held-out improvement + verified harm -> REJECT;
3. base-model epoch change -> capability STALE;
4. provider missing tools -> QUARANTINE;
5. provider serving wrong model ID -> QUARANTINE;
6. swarm with poor expected verified gain/cost -> DENY;
7. parallel route requires decomposability and gain/cost;
8. conflicting donors -> ABSTAIN;
9. verified regression removes conflicting donor;
10. mid-epoch frontier release -> NEXT EPOCH ONLY;
11. compact trace reopens exact raw evidence;
12. tampered raw evidence fails hash verification;
13. decision-ledger mutation is detectable;
14. executable/formal verifier outranks generic LLM judge on exact tasks;
15. hidden gold is absent from candidate interface.

## Limitation

Gold isolation is an interface simulation, not a proof of secure filesystem/process isolation. Claim-grade ProgramBench/Harbor runs still require native sandbox/container separation.

## Gate to Deep Research

Internal controller mechanics are now sufficiently specified to ingest external research without allowing research reports to directly rewrite active capability memory.

External research must enter:

`EXTERNAL_CLAIM -> SOURCE_BIND -> PRIOR_ART/MECHANISM_NORMALIZE -> DISCOVERY`

Only a subsequent matched experiment can promote a mechanism.

## Governance

Research only. No main write. No merge/deploy/production action. No external model call. No capability-lift claim from these controls.
