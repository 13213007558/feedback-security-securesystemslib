# Feedback task starting environment

Upstream: https://github.com/secure-systems-lab/securesystemslib
Upstream commit: `bcb7ef8ce72c1265aebcc26ac4a3b3fa084eb2ad`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_dsse.py tests/test_hash.py tests/test_formats.py tests/test_storage.py tests/test_signer.py -k 'not gpg'
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `53 passed, 1 skipped, 9 deselected, 10 warnings, 11 subtests passed in 3.86s`
Whole-command wall time: 4.189 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
