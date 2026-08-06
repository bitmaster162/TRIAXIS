# TRIAXIS v3.29 execution-ledger head quorum reference

This directory describes a **reference** 2-of-3 deployment of the v3.28
execution-ledger head authority. The verifier accepts only one exact fresh,
challenge-bound ledger-head statement supported by an operator-pinned threshold
of distinct authority, service, signer, key and trust-domain identities.

## Required topology

- Head authority A: independent state, key and trust domain A
- Head authority B: independent state, key and trust domain B
- Head authority C: independent state, key and trust domain C
- Quorum verifier: separate from all three authorities
- Execution ledger: separate signing identity
- Completion witness: separate persistence and signing identity

Running the three instances on one host is useful for executable conformance but
**does not** prove physical or administrative independence. A stronger claim
requires separate administrators, failure domains, authenticated transport,
external key custody, monitoring and independently protected backups.

## systemd reference

Install one environment file and credential directory for each instance, then
start:

```bash
systemctl enable --now triaxis-execution-ledger-head@a
systemctl enable --now triaxis-execution-ledger-head@b
systemctl enable --now triaxis-execution-ledger-head@c
```

The example quorum JSON is illustrative. It must be canonically sealed by
`make_execution_ledger_head_quorum_config`; a literal placeholder digest is not
a valid production or test configuration.

## Fail-closed rules

- one current + one stale + one unavailable is not a quorum;
- duplicate identities or keys do not increase the vote count;
- one signer issuing two statements for the same challenge is equivocation;
- a quorum that disagrees with the local signed ledger head is rollback/fork
  evidence, not permission to continue;
- the quorum witness is evidence only and never grants action authority.
