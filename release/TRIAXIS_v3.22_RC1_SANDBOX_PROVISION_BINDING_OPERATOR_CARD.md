# TRIAXIS v3.22-RC1 Operator Card

```bash
TERM=xterm PYTHONPATH=src:. python -m unittest discover -s tests -q
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v322_governed_harness_regression.py --output /tmp/v322-harness.json
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v322_sandbox_provision_closure.py --output /tmp/v322-sandbox.json
```

A write-capable child requires an exact fresh Repository Manifest. An
execute-capable child requires an exact PASS Sandbox Provision Receipt bound to
the child, profile and repository manifest. These receipts are reference-host
observations, not external OS/KMS attestations.
