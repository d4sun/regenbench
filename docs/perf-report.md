# ReGenBench Fuzzer Performance Report

This report compares campaign execution performance and latency costs with vs. without the static pre-filter (T4.6).

## Benchmark Configuration

- **Evaluation suite pre-filter ablation** (live, `scripts/run_evaluation_suite.py` T7.7): 5 distinct benign copies, scanners `picklescan` + `dynahug` (oracle gated), workers 2, backend `docker`, timeout 45s.
- **Full benchmark** (lab host, `scripts/benchmark_perf.py`): 10 candidates (5 benign + 5 malicious), scanners `picklescan` + `dynahug`, workers 4, backend `podman`.

## Live Pre-filter Ablation (T7.7, `data/regenbench_campaign.db` provenance)

Measured by `scripts/run_evaluation_suite.py` — isolates pre-filter contribution by running 5 distinct copies (Runner dedups identical paths) with and without pre-filter; only the "with" path skips `dynahug` containers for benign artifacts.

| Metric | With Pre-Filter | Without Pre-Filter | Speedup |
| :--- | :---: | :---: | :---: |
| **Execution Duration (5 files)** | 1.03s | 17.47s | **16.92×** |
| **DynaHug Runs** | 0 executed (all 5 benign filtered) | 5 executed | **100% reduction** |

> This 16.92× is the figure cited in `docs/evaluation-report.md` RQ4 Ablation 2 and `README.md` Latest results. It measures **oracle gating** (dynahug skipped for benign), not total campaign wall-clock.

## Lab-host Full Benchmark (10 candidates, baseline snapshot `reference/baseline_snapshot/results-20260818-141227/perf-report.md`)

| Metric | With Pre-Filter | Without Pre-Filter | Difference |
| :--- | :---: | :---: | :---: |
| **Total Duration** | 10.19s | 19.45s | **+9.27s** |
| **Throughput** | 0.98 files/s | 0.51 files/s | **1.91× speedup** |
| **DynaHug Runs** | 5 executed / 5 skipped | 10 executed / 0 skipped | **50.0% reduction** |

## Key Findings

1. **Pre-filter necessity**: Running `dynahug` inside a container requires mounting, `strace`, and OCSVM inference. By statically filtering candidates with no registered dangerous callable (`pipeline/pre_filter.py:is_admitted` → `pipeline/runner.py:192`), benign files skip the oracle. Over 5 files this saves **16.44s (16.92×)**; over 10 mixed files it saves **9.27s (1.91×)**.

2. **Fail-closed behavior**: Malformed/unparseable artifacts are admitted (`is_admitted` returns `True`, `pipeline/pre_filter.py:128`) so crafted payloads cannot bypass behavioral analysis. The runner downgrade to synthetic `benign` for non-admitted files is intentional fail-open for malformed bytes (see open question in `CLAUDE.md`).

3. **Reproducibility**: Re-run with `python3 scripts/benchmark_perf.py` (requires `podman` + images `regenbench/base`, `regenbench/picklescan`, `regenbench/dynahug`) or the lightweight ablation via `python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all`.

## How to Re-run

```sh
# lightweight ablation (no extra corpus, uses evaluation suite)
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all
# full benchmark (needs ci/corpus + containers)
python3 scripts/benchmark_perf.py
```
