# THREAT MODEL — E002 Authorization Engine Shootout

## Primary Threats & Vulnerability Vectors

### 1. Dimension Collapse (Principal Spoofing)
- **Vector**: Collapsing `HUMAN × AGENT_INSTANCE × DELEGATION_GRANT × TASK` into a single string identity (e.g. `user_123`).
- **Impact**: An agent instance executes unauthorized actions outside its delegation scope.
- **Mitigation**: Require multi-dimensional principal verification or structured entity schema.

### 2. Default-Open Failures
- **Vector**: PDP returns `ALLOW` or unhandled exception when context variables are missing, policy files fail to load, or syntax errors occur.
- **Impact**: Unauthorized access during system degradation or configuration error.
- **Mitigation**: Strict fail-closed wrapper at PEP level returning `DENY` on any non-explicit permit.

### 3. Stale Cache / Revocation Lag
- **Vector**: Decision caching or relationship tuple caching serves `ALLOW` after a grant or membership tuple is revoked.
- **Impact**: Authorization granted after explicit administrative revocation.
- **Mitigation**: Bound cache TTLs and mandate explicit cache invalidation channels.

### 4. Policy Version Mismatch
- **Vector**: Client submits requests against a superseded policy version `v1` while system has activated `v2` with tightened restrictions.
- **Impact**: Policy rollback or bypassing governance controls.
- **Mitigation**: Include policy version hash in authorization decision payload and reject mismatched policy versions.

### 5. PDP-PEP Disagreement
- **Vector**: Multiple PDP engines (e.g. Cedar for context + OpenFGA for ReBAC) return conflicting decisions.
- **Impact**: Security decision bypass or unpredictable access enforcement.
- **Mitigation**: Enforce single top-level combining algorithm: ALL PDP sub-decisions must return `ALLOW` for access to be granted (`strict-and`).
