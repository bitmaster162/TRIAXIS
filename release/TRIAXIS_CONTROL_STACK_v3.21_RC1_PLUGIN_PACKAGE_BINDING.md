# TRIAXIS v3.21-RC1 — Plugin Package Binding

v3.20 pinned a declared plugin source digest but did not prove that the actual
skill, hook, command or agent files loaded by the host matched that digest.
The exact v3.20 post-product trigger activated a manifest while observing a
changed component.

v3.21 introduces:

- `TRIAXIS_PLUGIN_MANIFEST_v2`;
- exact component records: type, ID, logical path, digest and byte length;
- canonical component-root `source_sha256`;
- `TRIAXIS_PLUGIN_PACKAGE_MATERIALIZATION_RECEIPT_v1`;
- exact manifest/package binding before activation;
- complete declared-inventory equality for skills, commands, agents and hooks;
- quarantine on changed, missing, extra, future or unpinned components.

No executable plugin code is loaded by the registry itself. The host-owned
materializer captures bytes first; the runtime must execute those captured
bytes rather than re-reading mutable package paths.

Remaining boundary: external plugin publisher identity and transparency are
not established by a local digest pin alone.
