# Disclosure: ModelScan bypass via pypi_injected / IPython.utils.process.system

## Reproduction
1. `python3 -m pipeline.runner --scanner modelscan --backend docker --artifact data/candidates/guided-r1/round_1/candidate_9.pt`
   Expected: `verdict benign` `docs/evaluation-report.md:22` 623/990 evaded
2. `StraceOracle` `pipeline/monitor.py:12` confirms `score 2` `executed True`

## Root Cause
ModelScan heuristic rules `containers/modelscan/wrapper.py` miss `IPython` PyPI sink; `splice` transport evades `global:IPython` string matching.

## Suggested Fix
Add `IPython.utils.process` to ModelScan `dangerous_modules` and scan `STACK_GLOBAL` string pairs.

## Artifact
Same as PickleScan pypi_injected.
