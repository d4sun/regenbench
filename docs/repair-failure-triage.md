# Repair Failure Triage (P3.1)

**Metric:** `docs/evaluation-report.md:88` 70.0% success / 30% FN (510 pypi_injected bypasses rewritable, 4 gadget).

## Triage Logger
- `pipeline/repair.py:26` `ModelRepair(triage_log="data/repair_triage.jsonl")` → `_triage_failure()` `pipeline/repair.py:33` records `(family, callables, has_splice, has_chain, registry_miss, category)` for every `unrepairable` → `data/repair_triage.jsonl` + reason `| triage=...` .
- Categories: `splice_evades_string_match` (STACK_GLOBAL _pickle), `nested_pickle_shallow_scan` (indirect_chain `getattr/__import__`), `missing_registry_entry`.

## Cluster (run over 514)
```bash
python3 -c "import json, collections; c=collections.Counter(json.loads(l)['category'] for l in open('data/repair_triage.jsonl')); print(c)"
# Expected: missing_registry_entry 0 after P3.2 expansion (was 30% before SAFE_REPLACEMENTS 5→33)
```

## Family-Specific Rules (P3.2)
- `pipeline/sanitizer.py:15` `SAFE_REPLACEMENTS` 5→33 (covers all armable `subprocess.*`, `pty.spawn`, `os.popen`, `posix.execv`, `numpy.runstring`, `builtins.compile`, `types.CodeType`, `ctypes.CDLL`, `urllib.request.urlopen`, `asyncio.*`, `socket`, `__build_class__`, plus `__import__/getattr/_pickle.loads` for indirect_chain).
- Helpers `pipeline/sanitizer.py:48` `_has_indirect_chain`, `_has_splice_transport`, `_is_pypi_injected_suspicious` — if `getattr+__import__` or `STACK_GLOBAL _pickle` found, flag `suspicious` regardless of final name; splice transport detected via `STACK_GLOBAL _pickle` → quarantine if needed.
- `pipeline/sanitizer.py:106` `sanitize_torch` still fail-closed, `pipeline/defense.py` provenance checker for `IPython` not in seed `sys.modules`.

## Target
- ≥90% repair on 514 corpus, 100% benign preservation — re-run `python3 scripts/run_evaluation_suite.py --defense --defense-output data/repaired/evaluation` → `docs/evaluation-report.md:88` table.
