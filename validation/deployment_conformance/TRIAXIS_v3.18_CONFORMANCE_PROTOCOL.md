# TRIAXIS v3.18 Single-Host Multi-Process Conformance Protocol

The harness starts three separate authority subprocesses and validates the
following sequence:

1. verify unique PID, port, database path, authority, key and simulated domain;
2. deny checkpoint installation with the wrong bearer token;
3. install checkpoint sequence 1 then sequence 2 into all authorities;
4. accept current 2-of-3 quorum;
5. terminate one authority and preserve availability;
6. terminate a second authority and fail closed;
7. restore two current authorities and one sequence-1 stale authority;
8. accept the two current authorities;
9. remove one current authority and block the current/stale split;
10. restart a current authority over the same database and preserve sequence 2;
11. confirm health output excludes private-key fields.

The receipt must retain the following negative claims:

```text
conformance_level=SINGLE_HOST_MULTIPROCESS
physical_independence=false
administrative_independence=false
transport_authentication=NONE_LOOPBACK_ONLY
key_custody=PROCESS_ENVIRONMENT_LAB_ONLY
deploy_permission=DENY
```
