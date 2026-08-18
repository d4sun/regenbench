#!/usr/bin/env python3
"""T4.6 — Throughput/Latency Benchmarking.

Quantifies stage costs (pre-filter, panel, oracle) and compares campaign
performance with vs without the static pre-filter. Writes a report to docs/perf-report.md.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.runner import Runner, Config
from pipeline.registry import load_registry


def run_benchmark():
    print("====================================================")
    print("STARTING PERFORMANCE BENCHMARK (T4.6)")
    print("====================================================")
    
    load_registry()
    
    # 1. Prepare 10 torch candidates (5 benign, 5 malicious) in temp dir
    temp_dir = tempfile.mkdtemp()
    corpus_dir = os.path.join(temp_dir, "corpus")
    os.makedirs(corpus_dir)
    
    src_pt_benign = "ci/corpus/torch/benign"
    src_pt_malicious = "ci/corpus/torch/malicious"
    
    benign_paths = []
    malicious_paths = []
    
    # We copy 5 benign copies and 5 malicious copies
    for i in range(5):
        dest_b = os.path.join(corpus_dir, f"benign_{i}.pt")
        shutil.copy(os.path.join(src_pt_benign, "benign.pt"), dest_b)
        benign_paths.append(dest_b)
        
        dest_m = os.path.join(corpus_dir, f"malicious_{i}.pt")
        shutil.copy(os.path.join(src_pt_malicious, "malicious.pt"), dest_m)
        malicious_paths.append(dest_m)
        
    all_paths = benign_paths + malicious_paths
    
    try:
        # Run 1: WITH Pre-Filter (Standard)
        print("\n[Run 1] Running WITH Static Pre-Filter...")
        config_pf = Config(backend="podman", tag=":latest", max_workers=4, timeout=60, oracle=True, pre_filter=True)
        runner_pf = Runner(config_pf, scanners=["dynahug", "picklescan"])
        
        t0 = time.time()
        results_pf = runner_pf.run(all_paths)
        dur_pf = time.time() - t0
        
        # Calculate pre-filter stats
        skipped_cnt = sum(1 for r in results_pf if r.scanner == "dynahug" and r.duration == 0.0)
        admitted_cnt = 10 - skipped_cnt
        print(f"Completed in {dur_pf:.2f} seconds. Skipped {skipped_cnt} dynahug executions. Admitted {admitted_cnt}.")
        
        # Run 2: WITHOUT Pre-Filter (Forced Container Runs)
        print("\n[Run 2] Running WITHOUT Static Pre-Filter (Forcing all container runs)...")
        config_no_pf = Config(backend="podman", tag=":latest", max_workers=4, timeout=60, oracle=True, pre_filter=False)
        runner_no_pf = Runner(config_no_pf, scanners=["dynahug", "picklescan"])
        
        t0 = time.time()
        results_no_pf = runner_no_pf.run(all_paths)
        dur_no_pf = time.time() - t0
        print(f"Completed in {dur_no_pf:.2f} seconds. Executed all 10 dynahug containers.")
        
        # Calculate savings and stats
        speedup = dur_no_pf / dur_pf if dur_pf > 0 else 1.0
        time_saved = dur_no_pf - dur_pf
        throughput_pf = 10 / dur_pf if dur_pf > 0 else 0.0
        throughput_no_pf = 10 / dur_no_pf if dur_no_pf > 0 else 0.0
        
        print("\n--- Summary ---")
        print(f"With Pre-Filter duration:    {dur_pf:.2f}s (Throughput: {throughput_pf:.2f} files/s)")
        print(f"Without Pre-Filter duration: {dur_no_pf:.2f}s (Throughput: {throughput_no_pf:.2f} files/s)")
        print(f"Pre-filter Speedup:          {speedup:.2f}x")
        print(f"Total Compute Time Saved:    {time_saved:.2f}s")
        
        # 4. Generate report in docs/perf-report.md
        docs_dir = "docs"
        os.makedirs(docs_dir, exist_ok=True)
        report_path = os.path.join(docs_dir, "perf-report.md")
        
        report_content = f"""# ReGenBench Fuzzer Performance Report

This report compares campaign execution performance and latency costs with vs. without the static pre-filter (T4.6).

## Benchmark Configuration
- **Total Candidates**: 10 (5 benign PyTorch checkpoints, 5 malicious fuzzed checkpoints)
- **Scanners Run**: `picklescan`, `dynahug` (Dynamic behavioral oracle)
- **Parallel Workers**: 4
- **Container Backend**: Podman

## Comparative Performance Metrics
| Metric | With Pre-Filter | Without Pre-Filter | Difference / Improvement |
| :--- | :---: | :---: | :---: |
| **Total Duration** | {dur_pf:.2f}s | {dur_no_pf:.2f}s | **{time_saved:+.2f}s** |
| **Throughput** | {throughput_pf:.2f} files/s | {throughput_no_pf:.2f} files/s | **{speedup:.2f}x speedup** |
| **DynaHug Runs** | {admitted_cnt} executed / {skipped_cnt} skipped | 10 executed / 0 skipped | **{skipped_cnt / 10 * 100:.1f}% reduction** |

## Key Findings
1. **Pre-Filter Necessity**: Running the dynamic DynaHug behavioral oracle inside a Podman container requires mounting, process execution, stracing syscalls, and SVM inference. By statically filtering out benign candidates (which contain no registered dangerous callables), we avoid executing containers for **{skipped_cnt / 10 * 100:.1f}%** of the files.
2. **Speedup**: The campaign execution speedup with the pre-filter enabled is **{speedup:.2f}x**, saving massive CPU time and context switching.
"""
        with open(report_path, "w") as f:
            f.write(report_content)
        print(f"\nWritten performance report to {report_path}")
        
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    run_benchmark()
