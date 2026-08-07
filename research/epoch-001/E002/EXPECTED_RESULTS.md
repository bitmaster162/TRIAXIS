# EXPECTED RESULTS — E002

## Pre-Execution Hypothesis

1. **Cedar**: Expected to pass all contextual, explicit allow/deny, and delegation test cases cleanly. Expected to require custom tuple mapping for complex nested graph queries (TC14).
2. **OPA**: Expected to pass all policy test cases cleanly using Rego queries. Expected to require manual schema structure for ReBAC graph navigation.
3. **OpenFGA**: Expected to pass relationship-based test cases (TC13, TC14, TC15) natively. Expected to mark non-expressible for pure contextual policy conditions (TC11, TC12, TC17) unless contextual tuples are supplied.
4. **AuthZEN**: Expected to provide a clean, standardized PEP-PDP interface payload mapping for all 20 test cases as a specification layer (`SPEC_EVIDENCE`).

## Expected Failure Mode Summary
- All candidate PEP wrappers are expected to return `DENY` under PDP unavailability, syntax error, or malformed input (100% fail-closed).
