# TRIAXIS v3.19-RC1 — Governed Harness Adoption

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Upstream inspiration: `xai-org/grok-build`
- Adoption method: clean-room contract adaptation; no upstream code vendored
- Production-qualified: no
- ACP-certified: no
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.19 adopts useful agent-harness mechanics while preserving the TRIAXIS
security model. Skills, plugins, hooks, subagents, session forks, workflows,
headless adapters and MCP discovery are not authorities. They may request or
narrow capabilities, but they cannot mint permission or bypass the existing
Action Assurance boundary.

## New runtime plane

1. **Managed configuration** — ordinary layers have precedence, but managed
   requirements form non-widenable safety ceilings.
2. **Explicit context assembly** — each disclosed artifact requires an exact
   identifier, path, digest, size, data class and explicit grant.
3. **Capability-contract skills** — versioned input/output/tool declarations.
4. **Digest-pinned plugins** — untrusted packages remain quarantined;
   `bypassPermissions` is prohibited.
5. **Lifecycle hooks** — sealed decisions can WARN/HOLD/DENY or narrow
   authority, never widen it.
6. **Bounded subagents** — depth one, bounded fanout, selective MCP inheritance,
   worktree isolation for writes and approved sandbox for execution.
7. **Explicit session forks** — context, memory, policy and evidence references
   are enumerated; execution authority is not inherited implicitly.
8. **Capability Broker** — every tool call is checked against authority, target,
   context, data class, hook receipt and, for side effects, the exact
   authorization token.
9. **Host-owned workflows** — `Plan → Review → Diff → Authorize → Execute →
   Verify`, persisted with CAS transitions and durable events.
10. **Headless/ACP-style boundary** — sequenced digest-bound events and a
    deliberately scoped interoperability adapter.
11. **Bounded recovery** — retry, compaction, HOLD and DENY decisions are owned
    by deterministic host policy.

## Core invariants

```text
Discovery != Authority
Plugin installation != Capability grant
Skill invocation != Tool permission
Subagent spawn != Delegation of unrestricted authority
Plan approval != Execution authorization
Protocol adapter != Resource boundary
Context reference != Permission to read arbitrary bytes
```

## Privacy boundary

Whole-repository bundles, Git history, deleted objects, wildcards, traversal
paths and implicit disclosure are denied by the reference implementation. The
manifest contains references and digests, not an automatic repository upload.

## Claim boundary

A v3.19 PASS establishes only that the governed harness contracts and frozen
regressions pass in the local reference implementation. It does not establish:

- production capacity or availability;
- physical multi-host independence;
- ACP certification;
- safety of an arbitrary third-party plugin;
- truth of model output;
- that a digest reference still matches bytes loaded after manifest creation;
- permission for external execution.

The last item is intentionally left for the first post-product TOCTOU attack.
