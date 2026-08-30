#!/usr/bin/env python3
"""Phase 5 — Search Efficiency Benchmark.

Measures wall-clock time for candidate generation with different worker counts
to validate the ≤40% time target for same throughput.
"""

from __future__ import annotations

import argparse
import os
import pickle
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.generator import CandidateGenerator


def _generate_candidate_worker(
    benign_pt_bytes: bytes,
    payload: str,
    chosen_callable: tuple[str, str] | None,
    attack_family: str,
    cand_strategies: list[str],
    cand_transport: str | None,
    mutate_meta: bool,
    mutation_prob: float,
    op_swap_prob: float,
    callable_sub_prob: float,
    arg_fuzz_prob: float,
    stack_prob: float,
    differential_prob: float,
    family_synthesis_prob: float,
) -> bytes:
    """Worker function for parallel candidate generation."""
    generator = CandidateGenerator()
    return generator.generate_candidate_pt(
        benign_pt_bytes=benign_pt_bytes,
        payload_code=payload,
        dangerous_callable=chosen_callable,
        mutate_meta=mutate_meta,
        mutation_prob=mutation_prob,
        op_swap_prob=op_swap_prob,
        callable_sub_prob=callable_sub_prob,
        arg_fuzz_prob=arg_fuzz_prob,
        stack_prob=stack_prob,
        attack_family=attack_family,
        evasion_strategies=cand_strategies,
        injection_transport=cand_transport,
        differential_prob=differential_prob,
        family_synthesis_prob=family_synthesis_prob,
    )


def benchmark_generation(
    num_candidates: int = 50,
    workers_list: list[int] | None = None,
    attack_families: list[str] | None = None,
) -> dict[int, float]:
    """Benchmark candidate generation with different worker counts."""
    if workers_list is None:
        workers_list = [1, 2, 4, 8]
    if attack_families is None:
        attack_families = ["gadget", "overwritten", "pypi_injected", "external", "indirect_chain"]

    # Create a benign torch checkpoint
    base_data = {
        "model": {"transformer.wte.weight": [1.0, 2.0]},
        "model_config": {"vocab_size": 50257, "n_embd": 768, "n_layer": 12},
        "optimizer": {"lr": 1e-5, "beta": 0.9},
        "epoch": 1,
        "random_seed": 42,
    }
    base_pkl = pickle.dumps(base_data, protocol=5)

    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
        with zipfile.ZipFile(f, "w") as z:
            z.writestr("data.pkl", base_pkl)
        temp_path = f.name

    try:
        with open(temp_path, "rb") as f:
            benign_pt_bytes = f.read()
    finally:
        os.remove(temp_path)

    payload = "with open('/tmp/test.txt', 'w') as f: f.write('1')"
    results = {}

    for workers in workers_list:
        print(f"\nBenchmarking with {workers} worker(s)...")
        start = time.time()

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = []
            for i in range(num_candidates):
                attack_family = attack_families[i % len(attack_families)]
                if attack_family == "gadget":
                    chosen_callable = ("os", "system")
                else:
                    chosen_callable = None

                trigger_file = f"/tmp/trigger_{i}.txt"
                cand_strategies = []
                cand_transport = "splice"

                fut = executor.submit(
                    _generate_candidate_worker,
                    benign_pt_bytes,
                    payload,
                    chosen_callable,
                    attack_family,
                    cand_strategies,
                    cand_transport,
                    True, 0.15, 0.15, 0.15, 0.15, 0.05,
                    0.0, 0.0  # differential_prob, family_synthesis_prob
                )
                futures.append(fut)

            # Wait for all to complete
            for fut in as_completed(futures):
                fut.result()

        elapsed = time.time() - start
        results[workers] = elapsed
        print(f"  {workers} workers: {elapsed:.2f}s ({num_candidates/elapsed:.1f} candidates/sec)")

    # Calculate speedups
    baseline = results[1]
    print("\n--- Speedup Summary ---")
    for workers, elapsed in sorted(results.items()):
        speedup = baseline / elapsed
        efficiency = speedup / workers * 100
        print(f"  {workers} workers: {speedup:.2f}x speedup ({efficiency:.1f}% efficiency)")

    # Check if 4+ workers achieve ≤40% of baseline time
    if 4 in results:
        ratio = results[4] / baseline
        print(f"\n  4 workers time ratio: {ratio:.2f} ({'PASS' if ratio <= 0.4 else 'FAIL'} - target ≤0.4)")
    if 8 in results:
        ratio = results[8] / baseline
        print(f"  8 workers time ratio: {ratio:.2f} ({'PASS' if ratio <= 0.4 else 'FAIL'} - target ≤0.4)")

    return results


def main():
    ap = argparse.ArgumentParser(prog="benchmark_phase5", description=__doc__)
    ap.add_argument("--candidates", type=int, default=50, help="number of candidates to generate")
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8], help="worker counts to test")
    ap.add_argument("--output", default=None, help="output JSON file for results")
    args = ap.parse_args()

    results = benchmark_generation(args.candidates, args.workers)

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()