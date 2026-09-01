# ReGenBench Notebooks

Thin **subprocess wrappers** around the existing CLI scripts in `scripts/` —
each code cell prints the exact command it runs and streams its output, so you
always see progress on the long docker/network steps (crawl, campaigns,
rescans). No pipeline logic lives here; the logic stays in `scripts/` and
`pipeline/`.

## Run order

| # | Notebook | Scripts wrapped | Outputs |
|---|----------|-----------------|---------|
| 00 | `00_environment_check.ipynb` | `verify_host.sh`, `pytest`, `docker images` | host readiness |
| 01 | `01_crawl_corpus.ipynb` | `crawl_benign.py` + corpus link | `data/crawled/seed_manifest.json`, `real_benign_corpus/all/` |
| 02 | `02_organize_oracle.ipynb` | `validate_oracle.py`, `organize_corpus.py`, `check_oracle_disjointness.py` | oracle-validation.json, pos/neg views, oracle-split.json |
| 03 | `03_calibrate_oracle.ipynb` | `calibrate_oracle.py`, `fit_oracle_sweep.py`, `fp_eval_oracle.py` | `oracle-calibrated/<ver>/` |
| 04 | `04_campaigns.ipynb` | `run_shadowpickle_baseline.py`, `run_fuzzing_campaign.py` | shadowpickle + campaign DBs, fuzzing reports |
| 05 | `05_evaluation.ipynb` | `generate_evaluation_report.py`, `run_evaluation_suite.py` | `docs/evaluation-report.md` |
| 06 | `06_triage_shelf_life.ipynb` | `triage_bypasses.py`, `shelf_life_rescan.py` | `docs/triage-report.md`, `data/shelf_life.db` |
| 07 | `07_demo_defense.ipynb` | `demo_task3.py`, `crawl_gguf.py`, `run_task3_demo.py`, `benchmark_perf.py` | demo/perf reports, demo-artifacts |
| 08 | `08_save_results.ipynb` | `save_results.py` + DB queries | `results/<timestamp>/` |

The cells default to **small/pilot sizes** (5 rounds × 20 candidates, sample
50) so a notebook run is fast; the exact reproduction command for the scaled
run lives in `README.md` and `docs/QUICKSTART.md`.

## Setup & execution

```sh
python3 -m pip install --user nbformat jupyter-client ipykernel   # or: pip install -r notebooks/requirements.txt
# headless execute one notebook:
jupyter nbconvert --to notebook --execute --inplace notebooks/04_campaigns.ipynb
# or open the notebooks in Jupyter Lab:
jupyter lab notebooks/
```

## Notes

- Cells that need containers / network are marked `check=False` where a
  failure is informative rather than fatal (e.g. GGUF crawl offline).
- The campaign DB accumulates across notebook re-runs; start from a clean DB
  (delete `data/regenbench_campaign.db`) if you want a from-scratch run.
- Host-only analysis (DB queries, report rendering) needs no docker.