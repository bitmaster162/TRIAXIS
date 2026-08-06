# TRIAXIS v3.18-RC1 Operator Card

## Run tests

```bash
PYTHONPATH=src:. python -m unittest discover -s tests -q
```

## Run local process conformance

```bash
PYTHONPATH=src:. python validation/deployment_conformance/run_v318_single_host_conformance.py \
  --output /tmp/TRIAXIS_v3.18_SINGLE_HOST_MULTIPROCESS_CONFORMANCE.json
```

## Interpret results

- Unit tests PASS: code regression only.
- Conformance PASS: one-host multi-process interoperability only.
- Neither result authorizes production deployment or external execution.

## Never claim from this package

- physical 2-of-3 independence;
- independent administrators;
- KMS/HSM custody;
- production SLA;
- hostile-host resistance.
