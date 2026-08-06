# TRIAXIS v3.20-RC1 Operator Card

```bash
TERM=xterm PYTHONPATH=src:. python -m unittest discover -s tests -q
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v320_governed_harness_regression.py --output /tmp/v320-harness.json
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v320_context_materialization_closure.py --output /tmp/v320-materialization.json
```

Artifact-consuming tool requests require a PASS Context Materialization Receipt
whose digest is bound into the exact tool request. The executor must use the
captured bytes represented by that receipt and must not re-read a mutable path.
