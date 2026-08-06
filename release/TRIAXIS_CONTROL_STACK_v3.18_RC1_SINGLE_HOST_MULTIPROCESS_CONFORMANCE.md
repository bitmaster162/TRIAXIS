# TRIAXIS v3.18-RC1 — Single-Host Multi-Process Conformance

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Physical multi-host independence: not established
- Administrative independence: not established
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.17 proved the gossip-head quorum as Python contracts and unit tests. v3.18
moves that exact protocol across a process and HTTP boundary without expanding
the cryptographic claim.

The release provides:

1. one HTTP service process per Gossip Head Authority;
2. separate SQLite state per process;
3. separate Ed25519 signing identity per process;
4. authenticated administrative checkpoint installation;
5. fresh challenge-bound head responses;
6. a 2-of-3 verifier using the existing v3.17 quorum implementation;
7. fault injection for process loss, stale state, split view and restart;
8. systemd and Docker deployment references;
9. a frozen machine-readable conformance receipt.

## Protocol endpoints

### `GET /healthz`

Returns public operational identity and current checkpoint metadata. It does not
return private key material or the administrative token.

### `POST /v1/checkpoints/install`

Requires the exact administrative bearer token. The installed checkpoint must
pass the existing purpose-bound Ed25519 checkpoint validation, sequence and
parent checks.

### `POST /v1/head/challenge`

Returns the existing v3.16 signed head response bound to:

- store;
- verifier identity;
- verifier epoch;
- challenge digest;
- request time;
- exact current checkpoint;
- response validity window.

## Frozen conformance cases

| ID | Case | Required result |
|---|---|---|
| MP01 | Three distinct local process boundaries | PASS |
| MP02 | Wrong administrative token | DENY |
| MP03 | Healthy 2-of-3 current quorum | PASS |
| MP04 | One authority unavailable | PASS |
| MP05 | Two authorities unavailable | BLOCK |
| MP06 | One authority stale | current 2-of-3 PASS |
| MP07 | One current + one stale + one unavailable | BLOCK |
| MP08 | Authority restart with same state | current head preserved |
| MP09 | Health response secret minimization | PASS |

## Concurrency decision

The reference HTTP server is deliberately sequential. The underlying SQLite
connection is created and consumed by the same service thread. Throughput is
obtained through independent authorities, not concurrent request threads over
one SQLite connection.

This avoids silently relying on `check_same_thread=False` without a fully
specified transaction/locking model.

## Claim boundary

A v3.18 PASS means only:

> Three separate processes on one OS host interoperated over loopback HTTP and
> satisfied the frozen fault-injection protocol.

It does not establish:

- different physical hosts;
- different cloud providers;
- different administrators;
- KMS/HSM key custody;
- mTLS;
- independent network or power failure domains;
- threshold resistance to compromise of the shared host/user;
- production availability or capacity.

## Next physical evidence

The next material gate requires three independently administered authorities,
a separate verifier, external key custody, authenticated transport and evidence
of separate failure domains. No further same-host version should relabel this
simulation as physical conformance.
