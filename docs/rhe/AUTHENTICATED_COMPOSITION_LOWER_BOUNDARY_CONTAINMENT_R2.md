# Authenticated Composition Lower-Boundary Containment R2

## Scope

This change closes one specific authenticated-composition bypass: a caller that retained the exact `TrustedWorkloadExecutionBoundary` instance used by `AuthenticatedTrustedWorkloadExecutionBoundary` could previously call that lower boundary's public `prepare()` directly with an unsigned/raw authorization token and raw state witness, bypassing the outer signed token, authenticated risk-mediation receipt, and signed state checks before reaching `PREPARED`.

## Containment

- A standalone `TrustedWorkloadExecutionBoundary` keeps its legacy public `prepare()` behavior.
- When an exact lower-boundary instance is bound into `AuthenticatedTrustedWorkloadExecutionBoundary`, that instance is monotonically marked as requiring the authenticated outer boundary.
- After binding, public lower-boundary `prepare()` fails closed with `RISK_MEDIATION_AUTHENTICATION_REQUIRED` before workload-provider fetch or ledger mutation.
- Explicit base dispatch with `TrustedWorkloadExecutionBoundary.prepare(bound_instance, ...)` reaches the same guard and fails closed.
- The authenticated outer boundary performs token authentication, authenticated risk mediation, and signed-state validation first, then calls an internal continuation on the bound lower boundary.

## Regression coverage

`tests/test_authenticated_rhe_execution_boundary_r1.py` covers:

1. retained lower-boundary public `prepare()` blocked after authenticated composition;
2. explicit base-class `prepare()` dispatch blocked on the bound instance;
3. both bypass attempts occur before workload-provider fetch and before any ledger row is created;
4. the valid authenticated outer path still reaches `PREPARED`;
5. an independently created standalone legacy workload boundary still reaches `PREPARED` as before.

## Non-goals and residual boundaries

This is not a repository-wide complete-mediation claim. In particular:

- `src/triaxis/action_assurance.py` is unchanged;
- independently created legacy `TrustedWorkloadExecutionBoundary` instances remain supported;
- independently retained/raw `SQLiteExecutionLedger` paths are not changed by this R2;
- Python-private/internal method invocation is not treated as a hostile same-process security boundary;
- no deployment, provider effect, trading, capital, or model execution is introduced or authorized.
