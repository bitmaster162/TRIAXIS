# TRIAXIS v3.29 external-effect control-plane reference

v3.29 separates these logical state domains:

1. durable local dispatch queue;
2. signed external execution ledger;
3. three execution-ledger head authorities under an operator-pinned 2-of-3
   policy;
4. reference provider idempotency state;
5. external completion witness.

The verifier also remains separate from all evidence producers. No component in
this list grants action authority; it only constrains whether an already
separately authorized effect may proceed.

A same-host deployment is a conformance topology only. It does not establish
physical independence, separate administration, immutable completion evidence
or production exactly-once behavior.
