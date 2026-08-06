# v3.28 execution-effect control-plane reference

The reference separates three state domains:

1. `execution-ledger`: stable effect state and signed event chain;
2. `execution-ledger-head`: independently remembered monotonic ledger head;
3. `idempotent-provider`: provider-side effect identity and reconciliation.

Running all three containers, processes, databases, credentials, and backups on
one host does **not** establish physical or administrative independence. A
production integration needs separate operators/failure domains, authenticated
transport, KMS/HSM custody, trusted time, monitoring, backup anti-rollback, and
a real provider adapter whose idempotency behavior is independently tested.

The head authority must receive every missing signed ledger event before its
receipt envelope expires. If synchronization continuity is lost, fail closed;
do not reset or replace the external head to restore availability.
