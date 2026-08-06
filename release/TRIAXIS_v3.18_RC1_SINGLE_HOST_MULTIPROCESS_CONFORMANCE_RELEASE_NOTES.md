# TRIAXIS v3.18-RC1 Release Notes

v3.18 does not change the v3.17 quorum cryptography. It adds the first
reproducible process/network deployment surface for the Gossip Head Authority
quorum.

## Added

- `policy_transparency_gossip_head_http.py`;
- credential-aware `run_gossip_head_authority.py`;
- single-host three-process fault-injection harness;
- systemd template;
- Dockerfile and Compose reference;
- conformance receipt JSON Schema;
- frozen 9-case conformance evidence;
- HTTP and receipt-schema regression tests.

## Important limitation

All three authority processes in the frozen receipt ran on one host and one OS
user over loopback HTTP. This is a deployment simulation, not physical or
administrative independence.
