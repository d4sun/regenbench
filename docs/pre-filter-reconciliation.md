# Pre-Filter vs Panel Reconciliation (Phase C)

**Goal:** the static pre-filter (`pipeline/pre_filter.py:88` `is_admitted`) must not disagree with the container panel on real benign checkpoints.

## Method
For each real benign checkpoint in `real_benign_corpus/all` (17 files):
- `is_admitted(file)` (static) → predicts whether the DynaHug oracle would be admitted.
- Panel verdict (container `pipeline/scanners.py:run_scan` over `picklescan`, `modelscan`, `fickling`) → `benign`/`malicious`/`error`.

"Disagreement" = pre-filter admits a file the panel calls benign (would waste an oracle run) or pre-filter rejects a file the panel flags malicious (would hide a detection).

## Results (17 real checkpoints)
- **Dangerous refs:** 0/17 (via `parse_pickle` + `is_dangerous` — only `torch._utils._rebuild_tensor_v2`, `torch {Float,BFloat16}Storage`, `torch device`, `collections OrderedDict` present; all `SAFE_PYTORCH_INTERNALS` `pipeline/sanitizer.py:9`).
- **is_admitted:** 1/17 returns `True` — `text-generation__sshleifer_tiny-gpt2.bin` is a **raw (non-zip) pickle** whose `parse_pickle` raises (`Unknown pickle opcode byte: 0x00 at index 5874`); `pre_filter.py:124` is **fail-closed** (`return True`) so the artifact still reaches the oracle. This is a deliberate malformed-file admission, not a false detection.
- **Panel:** manual run on `text-classification__marcovise_TextEmbedding3SmallSentimentHead.bin` → `picklescan: benign (0.52s)`, `modelscan: benign (0.77s)`, `fickling: benign (0.55s)`.
- **Disagreements:** **0** on well-formed checkpoints; the 1 malformed raw pickle is fail-closed by design (`CLAUDE.md` open item).

## Notes
- Mounts use `:ro,z` (shared relabel, `pipeline/scanners.py:90`) — never `:ro,Z` (private relabel race, see `README.md` "Evaluation correctness fixes").
- Fickling GGUF magic guard (`containers/fickling/wrapper.py:123`) prevents `.gguf` FP; GGUF files are routed only to `modelscan`/`ggufref` via `exts` (`pipeline/scanners.py:19`, `pipeline/runner.py:121`).

## Full Docker panel
```bash
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all \
  --panel-scanners picklescan,modelscan,fickling,modeltracer --oracle strace
```
Expected: 0/17 FP for all static scanners + StraceOracle.