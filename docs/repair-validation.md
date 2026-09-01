# Repair Validation — Payload Removal + `weights_only=True` Loadability (Phase A)

**Claim (honest, Phase D framing):** the defense prototype achieves 100% payload-removal on confirmed bypasses. Of these, **≥95% are `sanitized`** (payload removed, file re-serialized and **loadable via `torch.load(..., weights_only=True)`**); any remainder is **destructively `quarantined`**. Benign files preserved.

## Root Cause (A.1/A.2)
The sanitizer replaced dangerous `GLOBAL` with `builtins.len`, but torch's `weights_only` unpickler has a strict opcode pre-scan (`torch/_weights_only_unpickler.py`): it rejects `SHORT_BINUNICODE` (opcode 140), `STACK_GLOBAL`, `BINBYTES8`/`FRAME`, and any non-allowlisted global. Two sources of failure:
1. Evasion head `SHORT_BINUNICODE×2 + STACK_GLOBAL` (stack_global_encoding) left in the stream → `Unsupported operand 140`.
2. Seeds saved at protocol 5 (SHORT_BINUNICODE) are inherently rejected by `weights_only` (torch defaults to proto 2).

PyTorch reconstruction internals discovered from benign checkpoints and allowlisted as `SAFE_PYTORCH_INTERNALS` (`pipeline/sanitizer.py:9`): `torch._utils._rebuild_tensor_v2`, `torch {Float,BFloat16}Storage`, `torch device`, `collections OrderedDict`, transformers/accelerate config enums.

## Fix (A.3)
- `PickleSanitizer._find_payload_offset()` locates the spliced payload head (dangerous `GLOBAL`/`INST` or `SHORT_BINUNICODE×2+STACK_GLOBAL` pair) and `sanitize()` truncates at that offset + appends `STOP` → pristine benign prefix (torch internals only, `weights_only`-compatible).
- `ModelRepair.repair_file(..., reserialize=True)` (`pipeline/repair.py`) re-saves the sanitized file in `regenbench/base` via `torch.load(weights_only=False)` (safe: payload removed) + `torch.save` (proto-2), then validates `torch.load(..., weights_only=True)` → `REPAIR_OK`. Tags `RepairResult.tag` = `sanitized` (loadable) / `quarantined`, plus `loadable`.

## Validation Protocol (A.4)
```bash
python3 /tmp/validate_514.py 514   # -> data/repair_v2_results.json
```
Run on the 514 confirmed bypasses (`data/regenbench_campaign.db`): `python3 -c "from pipeline.repair import ModelRepair; ..."` per file → in-container `torch.load(..., weights_only=True)` check.

## Results
- **Full 514 run:** `tested=514, tags={sanitized: 514}, loadable=514/514 (100.0%)` — `data/repair_v2_results.json`. By template: `inject_payload_into_torch` 4/4 (gadget, proto-5 seed), `shadowpickle_pypi_injected` 510/510. **Exceeds ≥95% target.**
- 50-sample subset across 8 evasion strategies confirmed the same 100% (`stack_global_encoding`, `attribute_masking`, `dead_code_injection`, `module_aliasing`, `opcode_reordering`, `protocol_downgrade`, `string_encoding_variants`, `none`).
- **StraceOracle on repaired:** 0% FP (payload tail removed → no `trigger_`/`corpus_pwned` write, no payload `execve`; verified `verdict benign` `score 0` on repaired vs `malicious` `score 2` on original) `pipeline/monitor.py:12`.
- **Benign preservation:** `sanitize` of a benign checkpoint is identity (`10663 → 10663 bytes`), `weights_only=True` loads OK.

## Tag Semantics (A.5)
| Tag | Condition | Behavior |
|-----|-----------|----------|
| `sanitized` | `loadable=True` (weights_only) + StraceOracle benign | Return repaired file; loads normally |
| `quarantined` | load fails / non-dict / container error | Destroy file; return safe stub or error |

`RepairResult` now carries `tag` + `loadable`; triage continues to `data/repair_triage.jsonl` (`pipeline/repair.py:_triage_failure`).

**Deliverable:** this file + `data/repair_v2_results.json`; RQ4 table updated in `docs/evaluation-report.md`.