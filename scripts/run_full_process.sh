#!/bin/bash
# ReGenBench — full pipeline runner.
#
# Runs the complete process step by step from a clean checkout, with a verify
# check after every step. The core path is: preconditions -> crawl -> oracle
# validation -> calibration -> campaigns -> evaluation -> GGUF -> shelf-life
# rescans -> snapshot -> charts.
#
# Usage:
#   bash scripts/run_full_process.sh
#
# Opt-outs (comma/space separated step keys from the list below):
#   SKIP_STEPS=containers,gguf bash scripts/run_full_process.sh
#
# Optional extras (default off):
#   RUN_ABLATIONS=1   04d/04e/04f — 5x5 fitness ablation + oracle-dominant
#                     validation + parallel ablation (adds hours of campaigns)
#   RUN_DIFFERENTIAL=1 09 — cross-parser disagreement mutation run (RQ1)
#   RUN_DISCLOSURE=1  10 — coordinated-disclosure drafts
#   RUN_CHECKLIST=1   run scripts/pre_submit_checklist.sh as a final gate
#
# Requires: docker with the regenbench images (or SKIP_STEPS=containers when
# they are already built), python3 with PyYAML/huggingface_hub/matplotlib, and
# sqlite3. Estimated wall time on a docker-equipped host: ~5-7 h (core path).

set -euo pipefail

cd "$(dirname "$0")/.."

LOG_FILE="data/full_process.log"
mkdir -p data
: > "$LOG_FILE"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG_FILE"; }

run_step() {
    local key="$1" label="$2" fn="$3"
    if [[ " ${SKIP_STEPS[*]:-} " == *" $key "* ]]; then
        log "SKIP  [$key] $label"
        return 0
    fi
    log "===== [$key] $label ====="
    "$fn"
    log "OK    [$key] $label"
}

verify() {
    local desc="$1"
    shift
    if ! "$@" > /dev/null 2>&1; then
        log "FAIL  verify: $desc"
        echo "ERROR: verify failed — $desc" >&2
        exit 1
    fi
    log "      verified: $desc"
}

require_opt() {
    if [[ -z "${!1:-}" ]]; then
        echo "ERROR: environment variable $1 must be set" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# 00 — Preconditions (host deps, unit tests, container images, host gate)
# ---------------------------------------------------------------------------
step_preconditions() {
    python3 -m pip install --user PyYAML huggingface_hub matplotlib
    python3 -m pytest tests/ -x -q
    for d in base picklescan modelscan fickling modeltracer dynahug gguf; do
        containers/$d/build.sh
    done
    docker images | grep regenbench
    ./scripts/verify_host.sh
}

# ---------------------------------------------------------------------------
# 01 — Crawl 100 real benign models (5 clusters x 20) + link flat corpus
# ---------------------------------------------------------------------------
step_crawl() {
    python3 scripts/crawl_benign.py \
        --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
        --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled \
        --scan-cap 20000 --workers 8

    mkdir -p real_benign_corpus/all
    while IFS= read -r f; do
        repo=$(basename "$(dirname "$f")")
        cluster=$(basename "$(dirname "$(dirname "$f")")")
        ln -f "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null
    done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
}

verify_crawl() {
    python3 -c "
import json
s = json.load(open('data/crawled/seed_manifest.json'))['summary']
assert s.get('total_models') == 100, s
print('total_models:', s.get('total_models'))
"
    verify "flat corpus has 100 links" bash -c '[ "$(ls real_benign_corpus/all | wc -l)" -eq 100 ]'
}

# ---------------------------------------------------------------------------
# 02 — Oracle validation, seed views, disjoint train/eval split
# ---------------------------------------------------------------------------
step_oracle() {
    python3 scripts/validate_oracle.py real_benign_corpus/all --sample 100 \
        --out real_benign_corpus/oracle-validation.json --backend docker
    python3 scripts/organize_corpus.py --corpus real_benign_corpus/all \
        --report real_benign_corpus/oracle-validation.json --out real_benign_corpus
    python3 scripts/check_oracle_disjointness.py --resplit
}

verify_oracle() {
    verify "oracle-split.json exists" test -f real_benign_corpus/oracle-split.json
}

# ---------------------------------------------------------------------------
# 03 — Recalibrate the oracle (traces on train half, fit, FP on eval half)
# ---------------------------------------------------------------------------
step_calibrate() {
    python3 scripts/calibrate_oracle.py real_benign_corpus/all \
        --split-file real_benign_corpus/oracle-split.json --split-role train \
        --out real_benign_corpus/oracle-calibrated/current \
        --sample 50 --backend docker --seed 1337 --traces-only
    python3 scripts/fit_oracle_sweep.py \
        --traces real_benign_corpus/oracle-calibrated/current/traces.json \
        --export --gamma 0.1 --nu 0.01 \
        --export-dir real_benign_corpus/oracle-calibrated/current --backend docker
    python3 scripts/fp_eval_oracle.py --split real_benign_corpus/oracle-split.json \
        --role eval --out real_benign_corpus/oracle-calibrated/current/fp-eval-eval.json \
        --backend docker
}

verify_calibrate() {
    for f in oneclass_svm_model.pkl vectorizer.pkl scaler.pkl syscalls.txt fp-eval-eval.json; do
        verify "calibrated model file $f exists" \
            test -f "real_benign_corpus/oracle-calibrated/current/$f"
    done
}

# ---------------------------------------------------------------------------
# 04 — Baseline + guided/unguided campaigns
# ---------------------------------------------------------------------------
step_campaigns() {
    python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
    python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 \
        --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
        --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
        --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
        --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42
    python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 \
        --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
        --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
        --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
        --evasion-mode random --fitness-mode current --backend docker --seed 42
}

verify_campaigns() {
    sqlite3 data/regenbench_campaign.db \
        "SELECT run_id, COUNT(*) FROM candidates GROUP BY run_id;" | tee -a "$LOG_FILE"
    verify "two fresh campaign runs present" bash -c \
        '[ "$(sqlite3 data/regenbench_campaign.db "SELECT COUNT(DISTINCT run_id) FROM candidates;")" -ge 2 ]'
}

step_ablations() {
    bash run_fitness_ablation_experiment.sh
    python3 scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db \
        --json results/fitness_ablation_results.json
    bash run_oracle_dominant_validation.sh
    python3 scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db \
        --json results/oracle_dominant_validation.json
    python3 scripts/run_parallel_ablation.py --max-workers 4 --rounds 5 \
        --candidates-per-round 20 --seeds 1337 1338 1339 1340 1341 \
        --fitness-modes current oracle_aware oracle_dominant --backend docker \
        --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
}

# ---------------------------------------------------------------------------
# 05 — Evaluation & reports
# ---------------------------------------------------------------------------
step_evaluate() {
    python3 scripts/generate_evaluation_report.py
    python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
        --corpus-dir real_benign_corpus/all --fp-sample 100 --defense
    python3 scripts/triage_bypasses.py
    python3 scripts/benchmark_perf.py
}

verify_evaluate() {
    verify "evaluation-report.md regenerated" test -f docs/evaluation-report.md
}

# ---------------------------------------------------------------------------
# 07 — GGUF attack surface (format-complexity demo)
# ---------------------------------------------------------------------------
step_gguf() {
    python3 scripts/crawl_gguf.py
    python3 scripts/run_task3_demo.py --backend docker
    python3 scripts/demo_task3.py --backend docker
    python3 scripts/insert_gguf_into_campaign.py
}

verify_gguf() {
    verify "task3-demo.md written" test -f docs/task3-demo.md
    local gguf_count
    gguf_count=$(sqlite3 data/regenbench_campaign.db \
        "SELECT COUNT(*) FROM campaign_runs WHERE run_id LIKE '%gguf%';")
    verify "gguf-demo run inserted" test "$gguf_count" -gt 0
}

# ---------------------------------------------------------------------------
# 08 — Shelf-life rescans (H3): historical scanner versions
# ---------------------------------------------------------------------------
step_shelf_life() {
    python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"
    for ver in 1.0.4 1.0.3; do python3 scripts/shelf_life_rescan.py \
        --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver \
        --scanners picklescan --backend docker; done
    for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py \
        --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver \
        --scanners modelscan --backend docker; done
    for ver in 0.1.11 0.1.10; do python3 scripts/shelf_life_rescan.py \
        --db data/regenbench_campaign.db --image fickling=regenbench/fickling:$ver \
        --scanners fickling --backend docker; done
}

verify_shelf_life() {
    sqlite3 data/shelf_life.db \
        "SELECT new_version, total, retained, printf('%.1f%%', retention_rate*100) FROM (SELECT new_version, COUNT(*) total, SUM(evasion_retained) retained, AVG(evasion_retained) retention_rate FROM rescans GROUP BY new_version);" \
        | tee -a "$LOG_FILE"
    verify "shelf_life.db has rescans" bash -c \
        '[ "$(sqlite3 data/shelf_life.db "SELECT COUNT(*) FROM rescans;")" -gt 0 ]'
}

# ---------------------------------------------------------------------------
# 09 — Differential / cross-parser disagreement (RQ1 optional)
# ---------------------------------------------------------------------------
step_differential() {
    python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 5 \
        --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
        --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
        --attack-families gadget,overwritten,external,indirect_chain,pypi_injected \
        --evasion-mode adaptive --fitness-mode oracle_aware --backend docker \
        --differential-prob 0.1 --seed 42
}

# ---------------------------------------------------------------------------
# 10 — Disclosure report (coordinated-disclosure drafts)
# ---------------------------------------------------------------------------
step_disclosure() {
    python3 scripts/generate_disclosure_report.py --db data/regenbench_campaign.db \
        --output-dir docs/disclosure --embargo-days 90
}

verify_disclosure() {
    verify "docs/disclosure populated" bash -c '[ -n "$(ls docs/disclosure 2>/dev/null)" ]'
}

# ---------------------------------------------------------------------------
# 11 — Snapshot
# ---------------------------------------------------------------------------
step_snapshot() {
    python3 scripts/save_results.py --db data/regenbench_campaign.db \
        --corpus-dir real_benign_corpus/all
}

verify_snapshot() {
    verify "results snapshot exists" bash -c '[ -n "$(ls -d results/2*/ 2>/dev/null | head -1)" ]'
}

# ---------------------------------------------------------------------------
# 12 — Charts (per-step folders)
# ---------------------------------------------------------------------------
step_charts() {
    python3 scripts/generate_charts.py
}

verify_charts() {
    verify "charts dir populated" bash -c '[ -n "$(ls -d charts/*_*/ 2>/dev/null | head -1)" ]'
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    if ! command -v docker > /dev/null 2>&1; then
        echo "ERROR: docker not found (required by container-backed steps)" >&2
        exit 1
    fi
    if ! command -v sqlite3 > /dev/null 2>&1; then
        echo "ERROR: sqlite3 not found" >&2
        exit 1
    fi

    [[ -n "${SKIP_STEPS:-}" ]] && IFS=', ' read -r -a SKIP_STEPS <<< "$SKIP_STEPS"

    log "ReGenBench full-process run starting (log: $LOG_FILE)"
    log "skipped steps: ${SKIP_STEPS[*]:-none}"

    run_step preconditions "Preconditions (deps, tests, images, host gate)" step_preconditions
    run_step crawl         "Crawl 100 real benign models + link flat corpus" step_crawl
    verify_crawl
    run_step oracle        "Oracle validation, seed views, disjoint split" step_oracle
    verify_oracle
    run_step calibrate     "Recalibrate oracle on this corpus" step_calibrate
    verify_calibrate
    run_step campaigns     "ShadowPickle baseline + guided/unguided campaigns" step_campaigns
    verify_campaigns
    if [[ "${RUN_ABLATIONS:-0}" == "1" ]]; then
        run_step ablations "5x5 fitness ablation + oracle-dominant validation + parallel ablation" step_ablations
    fi
    run_step evaluate      "Evaluation reports (RQ1-RQ4, H1-H3)" step_evaluate
    verify_evaluate
    run_step gguf          "GGUF attack surface (format-complexity demo)" step_gguf
    verify_gguf
    run_step shelf_life    "Shelf-life rescans (H3)" step_shelf_life
    verify_shelf_life
    if [[ "${RUN_DIFFERENTIAL:-0}" == "1" ]]; then
        run_step differential "Differential / cross-parser disagreement (RQ1)" step_differential
    fi
    if [[ "${RUN_DISCLOSURE:-0}" == "1" ]]; then
        run_step disclosure "Disclosure report" step_disclosure
        verify_disclosure
    fi
    run_step snapshot      "Snapshot results" step_snapshot
    verify_snapshot
    run_step charts        "Per-step charts" step_charts
    verify_charts

    if [[ "${RUN_CHECKLIST:-0}" == "1" ]]; then
        log "===== [final] pre-submit checklist ====="
        bash scripts/pre_submit_checklist.sh
        log "OK    [final] pre-submit checklist"
    fi

    log "Full process complete."
    echo
    echo "Summary (see $LOG_FILE for full log):"
    echo "  data/crawled/seed_manifest.json           100-model crawl manifest"
    echo "  real_benign_corpus/all/                   100 hard-linked seeds"
    echo "  real_benign_corpus/oracle-split.json      disjoint train/eval halves"
    echo "  real_benign_corpus/oracle-calibrated/current/  calibrated oracle"
    echo "  data/regenbench_shadowpickle.db           ShadowPickle baseline"
    echo "  data/regenbench_campaign.db               campaign + GGUF runs"
    echo "  data/shelf_life.db                        H3 historical rescans"
    echo "  docs/evaluation-report.md, triage-report.md, perf-report.md, task3-demo.md, demo-report.md"
    echo "  charts/<NN>_<step>/*.png                  per-step charts"
    echo "  results/<timestamp>/                      full snapshot"
}

main "$@"
