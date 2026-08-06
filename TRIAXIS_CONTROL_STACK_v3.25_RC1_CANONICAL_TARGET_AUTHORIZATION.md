# TRIAXIS v3.25-RC1 — Canonical Target Authorization

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Defect closed

v3.24 compared policy target prefixes with raw string `startswith`. A downstream URL/proxy/runtime could decode or normalize an accepted string into a different resource.

Exact v3.24 post-product evidence showed that encoded traversal, encoded separators, raw backslashes, malformed percent encodings and double encodings were accepted by the policy rule.

## Canonical target identity

v3.25 creates `TRIAXIS_CANONICAL_TOOL_TARGET_v1` before policy matching.

The canonicalizer:

1. validates every percent triplet;
2. rejects encoded slash, backslash, percent and dot bytes;
3. rejects literal `.` and `..` path segments;
4. rejects raw backslashes, control characters and raw whitespace;
5. rejects URL userinfo and fragments;
6. canonicalizes scheme and IDNA host casing;
7. removes default HTTP/HTTPS ports;
8. compares URL scheme, authority and path boundaries separately;
9. applies equivalent boundary matching to opaque targets such as `workspace:`;
10. returns immediate `DENY` when target identity is ambiguous, including interactive mode.

## Contract revisions

- `TRIAXIS_TOOL_POLICY_RULE_v2`
- `TRIAXIS_TOOL_POLICY_DECISION_v2`
- `TRIAXIS_CANONICAL_TOOL_TARGET_v1`

The decision receipt records the raw target digest, canonical target identity digest, validation status and exact validation error codes.

## Boundary

Canonical identity does not prove that a remote proxy, DNS resolver or tool adapter will execute the same resource. Production execution still requires adapter-level binding between canonical target, resolved endpoint, request bytes and execution receipt.
