# TRIAXIS clean validation contract

TRIAXIS remains validation-only and not production-qualified.

## Clean environment

From a fresh clone of the exact commit under test:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements-test.txt
PYTHONPATH=src:. python -m unittest discover -s tests -v
```

`requirements-test.txt` includes the runtime requirements and the schema-test
dependency on `jsonschema`.

## Receipt requirements

A clean-suite result is not "green" unless the receipt records:

- repository commit SHA;
- Python and pip versions;
- resolved package versions;
- exact command;
- total tests run;
- failures, errors and skips;
- wall-clock completion or explicit timeout;
- stdout/stderr or a hashed raw log.

A missing dependency, loader error, timeout, or interrupted runner is an
instrument/environment result, not evidence that every TRIAXIS claim is false.

Do not infer production exactly-once execution, physical authority independence,
physical WORM storage, trading safety, or deployment qualification from a local
validation PASS.

## CI

CI must install `requirements-test.txt` before the full unittest command.
Do not dispatch a new GitHub Actions run while the account billing/spending
block remains unresolved. A workflow run is a separate execution decision.
