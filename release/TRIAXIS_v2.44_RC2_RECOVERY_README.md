# TRIAXIS v2.44-RC2 Recovery

Validation-only closure of signed cross-database checkpoint scope.

Normative logic remains:

- `spec/TRIAXIS_CONTROL_STACK_v2.44_RC1_RECOVERY.md`
- `src/triaxis/checkpoint_scope.py`
- `src/triaxis/checkpoint_store.py`

Validation additions:

- frozen scope-binding protocol v3.8;
- post-product scope-atomicity protocol v3.9;
- exact RC1 and RC2 regression evidence.

RC2 is not production-qualified and grants no external execution permission.
