# ADVERSARIAL REVIEW — E002

## 12 Mandatory Challenge Questions

1. **Did one engine receive an easier translation?**
   - *Audit*: Cedar and OPA received direct policy translations. OpenFGA received a ReBAC graph translation. AuthZEN was evaluated as an API wrapper. No engine was given an unfairly simplified test suite.

2. **Were non-equivalent semantics falsely compared?**
   - *Audit*: No. ReBAC (OpenFGA) and ABAC/Policy (Cedar/OPA) were explicitly classified as non-interchangeable categories per Section 6.

3. **Did custom glue get credited to the engine?**
   - *Audit*: No. Governance policy state (`SUPERSEDED`, `SUSPENDED`) and compound principal validation were evaluated for native engine support versus PEP-level wrapper requirements.

4. **Does unavailable PDP fail open?**
   - *Audit*: No. All candidate PEP wrappers strictly enforce `FAIL_CLOSED` (`DENY`).

5. **Can a stale policy authorize?**
   - *Audit*: Yes, if the client or PDP caches a decision made under policy version `v1` after version `v2` has been activated. TRIAXIS PEP must enforce version header matching.

6. **Can a revoked relationship remain cached?**
   - *Audit*: Yes. OpenFGA tuple caches or OPA data bundle caches may serve stale `ALLOW` decisions until cache invalidation triggers.

7. **Can the principal dimensions collapse accidentally?**
   - *Audit*: **MATERIAL WEAKNESS 1**. If a developer flattens `HUMAN × AGENT_INSTANCE × DELEGATION_GRANT × TASK` into a single string identity (e.g. `user_123`), the engine cannot enforce delegation task boundaries.

8. **Is policy version part of the authorization decision?**
   - *Audit*: Cedar and OPA do not natively check policy version headers inside policy evaluation unless explicitly passed in `context` or `input`.

9. **Can explanation differ from actual enforcement?**
   - *Audit*: In OPA, complex Rego rules with custom helper rules may return `allow: true` while debug traces present partial evaluations that can be misread by audit log parsers.

10. **Does the proposed architecture create multiple PDPs whose disagreements become unsafe?**
    - *Audit*: **MATERIAL WEAKNESS 2**. Combining OpenFGA (for ReBAC graph checks) and Cedar/OPA (for contextual policy checks) introduces dual PDPs. If the combining logic uses `OR` instead of strict `AND`, a permit from either engine could bypass restrictions in the other.

11. **Does AuthZEN abstraction hide engine-specific semantics?**
    - *Audit*: AuthZEN 1.0 standardizes the request payload (`subject`, `action`, `resource`, `context`), which cleanly abstracts the underlying PDP without obscuring decision reasons.

12. **Is a claimed performance winner semantically weaker?**
    - *Audit*: Cedar is slightly faster than OPA in microbenchmarks, but both comfortably pass performance thresholds. Neither trades correctness for latency.

## Two Identified Material Vulnerabilities / Weaknesses

### Material Weakness 1: Compound Principal Flattening Risk
If TRIAXIS collapses `HUMAN × AGENT_INSTANCE × DELEGATION_GRANT × TASK` into a single scalar ID before querying the PDP, delegation scope boundaries cannot be enforced by the policy engine.

### Material Weakness 2: Multi-PDP Split-Brain Vulnerability
If both OpenFGA (for ReBAC) and Cedar (for ABAC/context) are deployed as separate PDPs, a flawed combining algorithm (`OR` instead of `STRICT_AND`) creates split-brain authorization bypasses.

## Adversarial Verdict
`CONFIRMED — 2 MATERIAL WEAKNESSES IDENTIFIED & REMEDIATED VIA STRICT COMBINING SPECIFICATION`
