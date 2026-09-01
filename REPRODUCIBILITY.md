# Reproducibility Checklist

## One-Command Repro
```bash
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
python3 scripts/crawl_benign.py --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled --scan-cap 20000 --workers 8
mkdir -p real_benign_corpus/all && while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 --candidates-per-round 20 --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42 --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 --candidates-per-round 20 --evasion-mode random --fitness-mode current --backend docker --seed 42 --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
python3 scripts/generate_evaluation_report.py
python3 scripts/demo_task3.py --backend docker
python3 scripts/benchmark_perf.py
python3 scripts/triage_bypasses.py
python3 scripts/crawl_gguf.py                       # -> data/gguf_benign_corpus/ (24 real GGUFs)
python3 scripts/run_task3_demo.py --backend docker  # -> docs/task3-demo.md (GGUF matrix + FP)
python3 scripts/insert_gguf_into_campaign.py        # bulk-insert GGUF surface as format='gguf' candidates
tar czf regenbench-results-$(date +%Y%m%d).tar.gz data/regenbench_campaign.db data/candidates docs/*.md data/gguf_benign_corpus
```

## Artifact Verification
- `python -m pytest tests/ -x -q` → 193 passed, 3 skipped
- `python3 -c "import json; print(json.load(open('data/crawled/seed_manifest.json'))['summary'])"` → `total_models: 100`, 5 clusters × 20
- `ls real_benign_corpus/all/ | wc -l` → 100
- `sqlite3 data/regenbench_campaign.db "SELECT COUNT(*) FROM candidates; SELECT COUNT(*) FROM campaign_fitness WHERE is_valid=1;"` → fresh run totals (no pre-existing runs)
- `ls data/candidates/` == DB totals
- `ls data/gguf_benign_corpus/` → after `scripts/crawl_gguf.py` (~24 real GGUFs); without it the demo uses a synthetic `benign_gguf()` fallback

## Held-Out
- The oracle calibration and the RQ3 FP study use **disjoint** model sets:
  `scripts/check_oracle_disjointness.py` writes a cluster-stratified 50/50
  train/eval split (`real_benign_corpus/oracle-split.json`); calibration traces
  train only, FP evaluation runs eval only.

## Cross-Validation
- Adversarial 5 manual bypasses vs `pipeline/sanitizer.py` → if ≥3 succeed, harden.

## Framing
- RQ1 yield optimization not family discovery, H3 stagnation not resilience — see `docs/evaluation-report.md`, `reference/baseline_snapshot/results-20260818-141227/comparison-methodology.md`.