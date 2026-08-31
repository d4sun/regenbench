# Reproducibility Checklist

## One-Command Repro
```bash
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
python3 scripts/crawl_benign.py --clusters text-generation --limit-per-cluster 40 --out-dir data/crawled
mkdir -p real_benign_corpus/all && find data/crawled -name "pytorch_model.bin" -exec sh -c 'ln "$1" "real_benign_corpus/all/$(basename $(dirname $(dirname "$1")))__$(basename $(dirname "$1")).bin"' _ {} \;
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 --candidates-per-round 20 --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42 --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 --candidates-per-round 20 --evasion-mode random --fitness-mode current --backend docker --seed 42 --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all
python3 scripts/generate_evaluation_report.py
python3 scripts/demo_task3.py --backend docker
python3 scripts/benchmark_perf.py
python3 scripts/triage_bypasses.py
tar czf regenbench-results-$(date +%Y%m%d).tar.gz data/regenbench_campaign.db data/candidates docs/*.md data/gguf_benign_corpus
```

## Artifact Verification
- `python -m pytest tests/ -x -q` → 171 passed
- `sqlite3 data/regenbench_campaign.db "SELECT COUNT(*) FROM candidates; SELECT COUNT(*) FROM campaign_fitness WHERE is_valid=1;"` → 1025 / 990
- `ls data/gguf_benign_corpus/` → 13 synthetic (offline) or 24 after `scripts/crawl_gguf.py`
- `ls data/candidates/` == DB (1065 with shadow)

## Held-Out
- Reserve 20 HF checkpoints never seen (`real_benign_corpus/all` split via `scripts/organize_corpus.py`) → 0% FP on `pipeline/runner.py` panel.

## Cross-Validation
- Adversarial 5 manual bypasses vs `pipeline/sanitizer.py` → if ≥3 succeed, harden.

## Framing
- RQ1 yield optimization not family discovery, H3 stagnation not resilience — see `docs/evaluation-report.md:32`, `docs/comparison-methodology.md`.
