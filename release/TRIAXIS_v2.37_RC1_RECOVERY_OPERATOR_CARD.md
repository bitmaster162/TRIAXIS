# TRIAXIS v2.37-RC1 Recovery — Operator Card

```text
1. Materialize the complete bundle into canonical detached JSON exactly once.
2. Reject unsupported nested types before routing or hashing.
3. Never let malformed data escape as an application exception.
4. Materialize the signed envelope once before authentication.
5. Bind exact host, bundle, snapshot time and subject digests.
6. Repeat commit-critical checks under the mutation lock.
7. Preserve the exact checkpoint on every rejection.
8. Keep live credentials and operational keys outside the repository.
9. Treat validation signatures as non-secret test infrastructure.
10. Analytical PASS never implies external execution permission.
```
