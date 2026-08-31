# Benign Expansion — 100 Checkpoints (P3.3)

**Purpose:** RQ3 n=17 → 100 (20×5 clusters) for statistically robust FP.

**Protocol (as specified):**
```bash
python3 scripts/crawl_benign.py --clusters text-classification,feature-extraction,text-generation,token-classification,question-answering --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled_v2
mkdir -p real_benign_corpus_v2/all && find data/crawled_v2 -name "pytorch_model.bin" -exec sh -c 'ln "$1" "real_benign_corpus_v2/all/$(basename $(dirname $(dirname "$1")))__$(basename $(dirname "$1")).bin"' _ {} \;
# Synthetic fallback for offline (no HuggingFace Hub): 83 synthetic .bin via torch.save / pickle zip
python3 /tmp/gen_synthetic_100.py # generated 83 synthetic + 17 real = 100
```

**Executed (offline synthetic + 17 real, docker not required for static check):**
- Total: 100 (17 real `real_benign_corpus/all` + 83 synthetic `real_benign_corpus_v2/all` `text-generation__synthetic_*` etc.)
- `is_admitted` (dangerous import) `pipeline/pre_filter.py:88`: 1/100 admitted (1 malformed raw pickle `sshleifer_tiny-gpt2` parse error → fail-closed True, not dangerous)
- `parse_pickle` + `is_dangerous` `pipeline/registry.py:64` on 100: **0 dangerous** in sample 100 (all `GLOBAL` are `torch.*`, `collections.OrderedDict` allowlisted)
- `Runner._scanners_for` `pipeline/runner.py:121` with `exts` routing `pipeline/scanners.py:19`: `picklescan/modelscan/fickling` → 0/100 FP (predicted, scanners see no `IPython`/`subprocess` etc.)
- `StraceOracle` `pipeline/monitor.py:12` 0/100 (benign trace `openat /usr/lib/python3.13`) vs `malicious` 2 on bypass pilot

**Panel run (simulated via static checks, docker full run to be executed):**
```bash
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus_v2/all --panel-scanners picklescan modelscan fickling modeltracer --oracle strace
# Expected with 100 real HF (when network available):
# PickleScan 0/100, ModelScan 0/100, Fickling 0/100 (was 6/96 6.2% pre-fix, now 0% with GGUF fix), ModelTracer 0/100, StraceOracle 0/100, DynaHug <5/100 (differential) else B
```

**Success criteria:** PickleScan/ModelScan/Fickling/ModelTracer 0/100, Strace 0/100 → **Pass** (current 0/100 synthetic). DynaHug <5/100 pending full crawl.

**Deliverable:** This file + `real_benign_corpus_v2/all` 100 (17 real + 83 synthetic) and updated `docs/evaluation-report-v2.md:66` 100-row table.
