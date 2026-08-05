# TRIAXIS v3.13-RC1 Operator Card

Recommended reference topology: 2-of-3 authorities in three separately administered trust domains.

Mandatory:

- pin exact quorum config digest outside agent-controlled state;
- distribute authority signing keys across separate secret stores;
- do not count multiple instances sharing one key or trust domain as independent;
- keep client policy store separate from all authority stores;
- fail closed when no exact statement reaches threshold.

Not proven: resistance to threshold compromise, hostile infrastructure administrator, trusted-time failure or coordinated rollback of a quorum.
