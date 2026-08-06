# TRIAXIS v3.22-RC1 — Sandbox Provision Binding

v3.21 accepted operator-approved sandbox/worktree names without evidence that
those isolation boundaries actually existed. The exact-tag post-product trigger
reproduced PASS contracts using invented strings.

v3.22 adopts the useful Grok Build sandbox provision-plan, durable metadata and
repository-manifest concepts as governed TRIAXIS contracts:

- `TRIAXIS_REPOSITORY_MANIFEST_v1` binds child session, exact worktree,
  baseline Git object, cleanliness, writability and freshness;
- `TRIAXIS_SANDBOX_PROVISION_PLAN_v1` binds profile, capabilities, repository
  state, network mode/allowlist, read/write paths, environment allowlist,
  resource budgets and expiry;
- `TRIAXIS_SANDBOX_PROVISION_RECEIPT_v1` records observed backend, durable state
  directory and PID/mount/network namespace identities;
- write subagents require exact repository-manifest binding;
- execute subagents require an exact PASS provision receipt;
- `all` mode requires both objects and cross-binding between them.

The receipt is host-owned reference evidence. It does not yet prove the
cryptographic identity of the provisioner or independently verify that an OS
namespace/container enforces the declared properties.
