# Disclosure: Panel bypass via indirect_chain / builtins.__import__ → builtins.getattr

## Reproduction
1. `python3 -m pipeline.templates` `IndirectChainTemplate` `pipeline/templates.py:172` generates `__import__('os', None, None, ['system'])` → `getattr(..., 'system')` chain `pipeline/evasion.py:52` `leaf_import_chain`
2. Panel: `picklescan`/`modelscan`/`fickling` all `benign` (no GLOBAL `os.system`, only `builtins.__import__`/`getattr` which are `import_smuggling` `genuine_code_exec:false` `pipeline/dangerous_callables.yaml:118`)
3. `StraceOracle` `score 1` `suspicious` (process) + trigger file `pipeline/monitor.py:27`

## Root Cause
Scanners key rules on `GLOBAL` import strings; `indirect_chain` resolves sink at runtime via `getattr(__import__(...))` `pipeline/evasion.py:52`, so no `GLOBAL os system` appears. `PickleSanitizer` now blocks via `SAFE_REPLACEMENTS` `builtins.__import__`→`len` `pipeline/sanitizer.py:15`.

## Suggested Fix
Add dynamic resolution blocking: if `GLOBAL builtins.getattr` + `GLOBAL builtins.__import__` in same pickle, flag `suspicious` regardless of final callable `pipeline/sanitizer.py:48`.

## Artifact
`data/candidates/guided-r1/round_5/candidate_3.pt` (if indirect_chain) or `IndirectChainTemplate().generate_pickle_payload("with open('/tmp/trigger_indirect','w') as f: f.write('1')")`.
