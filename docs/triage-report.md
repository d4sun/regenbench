# ReGenBench Bypass Triage and Syscall Analysis Report

This report triages the **514 confirmed bypasses** (ExecutionOracle-confirmed, panel all-benign) from the live campaign DB `data/regenbench_campaign.db` (2 runs, 990 valid). Generated from direct DB analysis (no `data/bypasses/` export required); see `scripts/triage_bypasses.py` for the file-export path.

## Summary Metrics

- **Total Confirmed Bypasses**: 514 (out of 990 valid, 51.9%)
- **By campaign**: guided-r1 428/554 (77.3%), unguided-r1 86/436 (19.7%)
- **Evasion category**: all `command_execution` via `splice` transport (no `code_execution` eval/exec in bypass set except 1 gadget)

## Evasion Profile by Target Callable

| Dangerous Callable | Category | Transport | Family | Occurrence |
| :--- | :--- | :---: | :---: | :---: |
| `family::pypi_injected` (→ `IPython.utils.process.system` via `TEMPLATE_FAMILY_SINKS`) | command_execution | splice | shadowpickle_pypi_injected | 510 (99.2%) |
| `IPython.utils.process::system` | command_execution | splice | inject_payload_into_torch (gadget) | 2 |
| `builtins::eval` | code_evaluation | splice | inject_payload_into_torch | 1 |
| `subprocess::getstatusoutput` | command_execution | splice | inject_payload_into_torch | 1 |

> 99% of bypasses are `pypi_injected` — `IPython.utils.process.system` (`python3 -c` shell sink) via `splice` transport. `pipeline/templates.py:TEMPLATE_FAMILY_SINKS` lists 5 pypi_injected sinks, but only `IPython` survives scanner rules; 12-sink diversification is available but not yet rewarded to bypass (the winning vector is outside the original `callable_sub` space).

## Evasion Profile by Evasion Strategy

| Strategy | Bypasses | % of 514 |
| :--- | :---: | :---: |
| (none) | 273 | 53.1% |
| stack_global_encoding | 195 | 37.9% |
| module_aliasing | 14 | 2.7% |
| string_encoding_variants | 12 | 2.3% |
| attribute_masking | 6 | 1.2% |
| opcode_reordering | 5 | 1.0% |
| dead_code_injection | 5 | 1.0% |
| protocol_downgrade | 4 | 0.8% |

> No `nested_loads_wrap` / `payload_obfuscation` / `indirect_chain` in bypass set — those add `_pickle.loads` / `__import__` Globals denylisted by PickleScan (see `pipeline/evasion.py:PIPELINE_ORDER` and `CLAUDE.md` per-family defaults). Single-strategy sets (`{0,1}` via `select_strategies`) dominate.

## Per-Scanner Evasion (valid candidates, `panel_results`)

| Scanner | Benign / Valid | Evasion Rate | Notes |
| :--- | :---: | :---: | :---: |
| picklescan | 514 / 990 | 51.9% | **Genuine evasion** — recursive GLOBAL scan defeated via splice (no extra GLOBAL) |
| modelscan | 623 / 990 | 62.9% | **Genuine evasion** — heuristic rules bypassed |
| fickling | 933 / 990 | 94.2% | **Rule absence** — no AST rule for `IPython.utils.process.system`; 5.8% detected via generic rules |

> The 514 confirmed bypasses are the intersection of all three (panel all-benign). Fickling's near-100% is not a flaw in the bypass; it reflects that fickling's denylist does not cover third-party shells.

## Syscall Analysis & Oracle Validation (ExecutionOracle)

Bypasses are confirmed by `ValidityOracle.validate_torch` (`pipeline/validity.py`) — container-sandboxed `torch.load(weights_only=False)` + `_trigger_exists` 5s poll (also `StraceOracle` 0% FP, `pipeline/monitor.py`). DynaHug's OCSVM is **supplementary** `decision_score` only (63.5% FP on benign corpus; see `docs/evaluation-report.md` RQ3).

Triage of the 514 bypasses:

1. **Process spawning (`execve`)** — `IPython.utils.process.system` / `subprocess.Popen` payloads spawn `python3 -c "with open('/tmp/trig_*.txt','w') as f: f.write('1')"`. Container strace shows `clone` → `execve("/usr/bin/python3")` → `openat(AT_FDCWD, "/tmp/trig_*.txt")` → `write`.
2. **No dynamic compilation** in the bypass set — `builtins.eval/exec` sinks are reachable via `gadget` but only 1 of 514 bypasses (the evaluated sinks are command shells, not in-process eval).
3. **No network** — `LoadTimeMonitor` (`pipeline/monitor.py:monitor_load`) reports `network=False` for all 5 families in `demo-artifacts/demo-report.json`; reverse-shell payloads not in this campaign (would show `connect` via `StraceOracle`).

## Repair Triage (30% escapes)

`PickleSanitizer` (`pipeline/sanitizer.py`) rewrites 5 direct sinks (`os.system`, `subprocess.Popen`, `builtins.exec/eval`, `IPython.utils.process.system` → `builtins.len`). Bypasses in this corpus use the sanitizable `IPython` sink (510/514) and are rewritable to benign. `indirect_chain` (`__import__`+`getattr`) and `numpy.runstring`/`posix.execv` are **quarantined** not sanitized (30% in `docs/demo-report.md` when forced); `ModelDefense.inspect` (`pipeline/defense.py`) quarantines and only reserializes `weights_only=True`-loadable content inside `regenbench/base`.

## Reproducibility

```sh
# From DB (current, no export needed):
python3 -c "
import sqlite3
con=sqlite3.connect('data/regenbench_campaign.db')
# ... see above queries
"
# From exported bypasses (if data/bypasses/ populated via campaign):
python3 scripts/triage_bypasses.py  # -> docs/triage-report.md
# Shelf-life retention (100% across 6 historical versions, data/shelf_life.db):
python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:1.0.4 --scanners picklescan --backend docker
```

*Archival snapshot* `reference/baseline_snapshot/results-20260818-141227/triage-report.md` had 0 bypasses (pre-fix). Current live report above supersedes it.
