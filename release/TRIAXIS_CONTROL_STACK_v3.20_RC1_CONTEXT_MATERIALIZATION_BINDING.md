# TRIAXIS v3.20-RC1 — Context Materialization Binding

## Purpose

v3.19 approved context references and expected digests but did not prove that
the bytes loaded immediately before a tool call still matched those digests.
A post-product trigger reproduced substitution between context assembly and
materialization.

v3.20 adds `TRIAXIS_CONTEXT_MATERIALIZATION_RECEIPT_v1`.

## Contract

The host-owned materializer:

1. receives the sealed Context Disclosure Manifest;
2. loads only explicitly selected artifact IDs;
3. hashes the exact captured bytes;
4. verifies digest and byte length against the manifest;
5. records materializer identity and observation tick;
6. emits a sealed PASS/BLOCK receipt without raw content.

A tool request that references artifacts must bind the exact receipt digest.
The Capability Broker denies dispatch when the receipt is missing, blocked,
belongs to another manifest, is not bound by the request, omits an input
artifact, has mismatching digest/size, or comes from the future.

## Execution invariant

The executor must consume the captured bytes represented by the receipt. It
must not re-read a mutable path after dispatch.

## Remaining boundary

Package-level plugin pinning does not yet prove that every component loaded
from a mutable plugin directory matches the approved package. That boundary is
reserved for the next post-product attack.
