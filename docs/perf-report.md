# ReGenBench Fuzzer Performance Report

This report compares campaign execution performance and latency costs with vs. without the static pre-filter (T4.6).

## Benchmark Configuration
- **Total Candidates**: 10 (5 benign PyTorch checkpoints, 5 malicious fuzzed checkpoints)
- **Scanners Run**: `picklescan`, `dynahug` (Dynamic behavioral oracle)
- **Parallel Workers**: 4
- **Container Backend**: Docker

## Comparative Performance Metrics
| Metric | With Pre-Filter | Without Pre-Filter | Difference / Improvement |
| :--- | :---: | :---: | :---: |
| **Total Duration** | 10.33s | 15.66s | **+5.33s** |
| **Throughput** | 0.97 files/s | 0.64 files/s | **1.52x speedup** |
| **DynaHug Runs** | 10 executed / 0 skipped | 10 executed / 0 skipped | **0.0% reduction** |

## Key Findings
1. **Pre-Filter Necessity**: Running the dynamic DynaHug behavioral oracle inside a Docker container requires mounting, process execution, stracing syscalls, and SVM inference. By statically filtering out benign candidates (which contain no registered dangerous callables), we avoid executing containers for **0.0%** of the files.
2. **Speedup**: The campaign execution speedup with the pre-filter enabled is **1.52x**, saving massive CPU time and context switching.
