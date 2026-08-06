# TRIAXIS v3.21-RC1 Operator Card

```bash
TERM=xterm PYTHONPATH=src:. python -m unittest discover -s tests -q
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v321_governed_harness_regression.py --output /tmp/v321-harness.json
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v321_plugin_package_closure.py --output /tmp/v321-plugin.json
```

Only exact materialized component bytes represented by a PASS package receipt
may be activated. The runtime must execute those captured bytes and not a
mutable package directory re-read after activation.
