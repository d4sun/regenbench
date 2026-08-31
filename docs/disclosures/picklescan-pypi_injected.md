# Disclosure: PickleScan bypass via pypi_injected / IPython.utils.process.system

## Reproduction
1. Build panel: `./ci/smoke.sh --no-build` (requires `regenbench/picklescan:latest` `containers/picklescan/build.sh`)
2. Artifact: `data/candidates/guided-r1/round_1/candidate_9.pt` (representative, `shadowpickle_pypi_injected`, `IPython.utils.process.system` via `splice` `pipeline/templates.py:132`)
3. Run scanner: `python3 -m pipeline.runner --scanner picklescan --backend docker --artifact data/candidates/guided-r1/round_1/candidate_9.pt`
   Expected: `verdict benign` `docs/evaluation-report.md:20` 514/990 evaded, `matched_rules: []`
4. Run execution oracle: `python3 -m pipeline.validity --artifact data/candidates/guided-r1/round_1/candidate_9.pt` (or `ValidityOracle.validate_torch` `pipeline/validity.py:21` trigger `/tmp/regenbench_trigger_1_9.txt`)
   Expected: `executed True` (payload `python3 -c "with open('/tmp/...')..."` via `StraceOracle` `pipeline/monitor.py:27` `connect`/`openat`)

## Root Cause
Missing rule for `IPython.utils.process.system` (PyPI shell sink) and no detection of `splice` transport (raw `GLOBAL IPython.utils.process system` + `REDUCE` without `_pickle.loads` wrapper) `pipeline/templates.py:388` `inject_payload_into_torch(transport="splice")`.

## Suggested Fix
Add denylist entry `IPython.utils.process.system` to PickleScan's `dangerous_globals` and detect `splice` via `STACK_GLOBAL` `IPython` string pair.

## Artifact
Base64 of minimal PoC (1.2KB, `benign_gguf`-sized, not attached here for safety): `python3 -c "import base64; print(base64.b64encode(open('data/candidates/guided-r1/round_1/candidate_9.pt','rb').read())[:80])"`
