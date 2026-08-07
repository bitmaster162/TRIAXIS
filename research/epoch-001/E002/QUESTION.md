# QUESTION — E002 Policy Engine Shootout

## Primary Thesis
Which authorization architecture best supports bounded, auditable, fail-closed authorization for:
`PRINCIPAL × ACTION × RESOURCE × CONTEXT × DELEGATION × POLICY_LIFECYCLE`
without creating unnecessary authority or coupling?

## Sub-Questions
1. **Semantic Fit**: Can the engine represent fine-grained permit/forbid rules with contextual conditions without requiring complex code glue?
2. **Category Distinction**: How do Cedar (Policy Language + PDP), OPA (General PDP + Rego), OpenFGA (ReBAC), and AuthZEN (API Spec) fit into a coherent architecture rather than an artificial 1-to-1 race?
3. **Compound Principal Support**: How natively can the engine represent `HUMAN × AGENT_INSTANCE × DELEGATION_GRANT × TASK`?
4. **Fail-Closed Behavior**: Does the engine strictly enforce `NO VERIFIED AUTHORITY => NO EFFECT PERMISSION` under input errors, unhandled exceptions, or service timeouts?
5. **Policy Governance & Lifecycle**: Does the engine support policy lifecycle states (`draft`, `active`, `superseded`, `suspended`, `revoked`, `expired`) natively or via clean external metadata binding?
6. **Explainability & Provenance**: Can decision outputs be traced back to exact policy statements, decision logs, and cryptographic provenance?

## Evaluation Criteria
- **Correctness & Fail-Closed Behavior**: 100% adherence to expected decisions across the 20-case Common Corpus.
- **Architectural Cleanliness**: Decoupled PDP/PEP interface without mutating core TRIAXIS state engine (`src/`).
- **No Unintended Authority**: Denial by default when context or relationship tuples are missing or stale.
