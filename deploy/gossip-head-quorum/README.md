# TRIAXIS Gossip Head Authority quorum deployment reference

This directory packages a **reference** 2-of-3 Gossip Head Authority deployment.
It is intended to move the v3.17 protocol from in-process tests to separately
started services with separate state and keys.

## What this reference proves

A successful conformance run proves that three HTTP processes can:

- keep separate SQLite state and Ed25519 identities;
- accept authenticated checkpoint installation;
- answer fresh verifier challenges;
- retain 2-of-3 availability when one process is unavailable;
- block when two processes are unavailable;
- tolerate one stale authority;
- block a split view that has no threshold;
- retain the installed checkpoint across process restart.

It does **not** prove that the services are physically or administratively
independent. Running all three containers or units on one machine remains one
failure domain.

## Required physical topology for a stronger claim

Use three independently administered hosts or providers:

- Authority A: host/provider/admin/KMS domain A
- Authority B: host/provider/admin/KMS domain B
- Authority C: host/provider/admin/KMS domain C
- Verifier: separate from every authority

Each authority requires:

1. a unique Ed25519 private key held outside the repository;
2. an independent SQLite state volume;
3. a unique authority, service, signer, key, and trust-domain identity;
4. authenticated administrative access to checkpoint installation;
5. mTLS or equivalent authenticated transport;
6. monitoring for process loss, stale heads, and equivocation.

## Service interface

- `GET /healthz`
- `POST /v1/checkpoints/install` — administrative bearer token required
- `POST /v1/head/challenge` — returns a challenge-bound signed head

The standard-library reference server is deliberately sequential. Put one
service process behind a hardened reverse proxy; scale through independent
authorities, not concurrent access to one SQLite connection.

## Secrets

The runner accepts either environment-variable secrets for laboratory use or
credential files through `CREDENTIALS_DIRECTORY` for systemd/Docker-style
secret mounts. Never commit private keys or administrative bearer tokens.

## Local conformance

```bash
PYTHONPATH=src:. python validation/deployment_conformance/run_v318_single_host_conformance.py \
  --output /tmp/triaxis-v318-conformance.json
```

A PASS is explicitly labelled `single-host multi-process loopback conformance`.
