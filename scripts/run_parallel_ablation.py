#!/usr/bin/env python3
"""Parallel campaign runner for ablation studies.

Runs multiple campaign replicates in parallel to speed up evaluation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def run_single_campaign(args: dict) -> dict[str, Any]:
    """Run a single campaign and return summary."""
    cmd = [
        sys.executable, "-u", "scripts/run_fuzzing_campaign.py",
        "--mode", args["mode"],
        "--rounds", str(args["rounds"]),
        "--candidates-per-round", str(args["candidates_per_round"]),
        "--replicate", str(args["replicate"]),
        "--db", args["db"],
        "--backend", args["backend"],
        "--pre-filter",
        "--seed", str(args["seed"]),
        "--evasion-mode", args["evasion_mode"],
        "--fitness-mode", args["fitness_mode"],
        "--seed-corpus-dir", args["seed_corpus_dir"],
        "--seed-cluster", args["seed_cluster"],
        "--attack-families", args["attack_families"],
        "--oracle-model-dir", args["oracle_model_dir"],
    ]
    if args.get("ensemble_oracle"):
        cmd.append("--ensemble-oracle")
    
    print(f"[{time.strftime('%H:%M:%S')}] Starting {args['mode']}-{args['fitness_mode']}-r{args['replicate']} (seed={args['seed']})")
    start = time.time()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
        elapsed = time.time() - start
        return {
            "replicate": args["replicate"],
            "seed": args["seed"],
            "mode": args["mode"],
            "fitness_mode": args["fitness_mode"],
            "elapsed": elapsed,
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-2000:] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {
            "replicate": args["replicate"],
            "seed": args["seed"],
            "mode": args["mode"],
            "fitness_mode": args["fitness_mode"],
            "elapsed": 7200,
            "returncode": -1,
            "stdout": "",
            "stderr": "TIMEOUT",
        }
    except Exception as e:
        return {
            "replicate": args["replicate"],
            "seed": args["seed"],
            "mode": args["mode"],
            "fitness_mode": args["fitness_mode"],
            "elapsed": time.time() - start,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
        }


def run_parallel_ablation(
    max_workers: int = 4,
    guided_fitness_modes: list[str] = None,
    seeds: list[int] = None,
    rounds: int = 5,
    candidates_per_round: int = 20,
    db: str = "data/regenbench_campaign.db",
    backend: str = "podman",
    seed_corpus_dir: str = "real_benign_corpus/all",
    seed_cluster: str = "text-generation",
    attack_families: str = "gadget,overwritten,external,indirect_chain",
    oracle_model_dir: str = "real_benign_corpus/oracle-calibrated/v5-recalibrated",
    evasion_mode: str = "adaptive",
    ensemble_oracle: bool = False,
    unguided: bool = True,
) -> list[dict]:
    """Run ablation experiments in parallel."""
    
    if guided_fitness_modes is None:
        guided_fitness_modes = ["current", "oracle_aware", "oracle_dominant"]
    if seeds is None:
        seeds = [1337, 1338, 1339, 1340, 1341]
    
    # Generate all campaign configs
    configs = []
    
    # Guided campaigns for each fitness mode
    for fitness_mode in guided_fitness_modes:
        for i, seed in enumerate(seeds):
            configs.append({
                "mode": "guided",
                "rounds": rounds,
                "candidates_per_round": candidates_per_round,
                "replicate": i + 1,
                "seed": seed,
                "fitness_mode": fitness_mode,
                "db": db,
                "backend": backend,
                "evasion_mode": evasion_mode,
                "seed_corpus_dir": seed_corpus_dir,
                "seed_cluster": seed_cluster,
                "attack_families": attack_families,
                "oracle_model_dir": oracle_model_dir,
                "ensemble_oracle": ensemble_oracle,
            })
    
    # Unguided baselines
    if unguided:
        for i, seed in enumerate(seeds):
            configs.append({
                "mode": "unguided",
                "rounds": rounds,
                "candidates_per_round": candidates_per_round,
                "replicate": i + 1,
                "seed": seed,
                "fitness_mode": "current",
                "db": db,
                "backend": backend,
                "evasion_mode": evasion_mode,
                "seed_corpus_dir": seed_corpus_dir,
                "seed_cluster": seed_cluster,
                "attack_families": attack_families,
                "oracle_model_dir": oracle_model_dir,
                "ensemble_oracle": ensemble_oracle,
            })
    
    print(f"Total campaigns: {len(configs)}")
    print(f"Max parallel workers: {max_workers}")
    print(f"Candidates per campaign: {rounds * candidates_per_round}")
    print(f"Estimated time per campaign: {rounds * 10} minutes")
    print()
    
    results = []
    completed = 0
    start_time = time.time()
    
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_config = {
            executor.submit(run_single_campaign, config): config 
            for config in configs
        }
        
        for future in concurrent.futures.as_completed(future_to_config):
            config = future_to_config[future]
            try:
                result = future.result()
                results.append(result)
                completed += 1
                elapsed = time.time() - start_time
                status = "OK" if result["returncode"] == 0 else f"FAILED ({result['returncode']})"
                print(f"[{time.strftime('%H:%M:%S')}] {completed}/{len(configs)} "
                      f"{result['mode']}-{result['fitness_mode']}-r{result['replicate']}: "
                      f"{status} in {result['elapsed']:.0f}s")
            except Exception as e:
                print(f"[{time.strftime('%H:%M:%S')}] Campaign failed with exception: {e}")
    
    elapsed_total = time.time() - start_time
    print(f"\nAll {len(configs)} campaigns completed in {elapsed_total/60:.1f} minutes")
    return results


def main():
    ap = argparse.ArgumentParser(description="Run parallel ablation campaigns")
    ap.add_argument("--max-workers", type=int, default=4, help="max parallel campaigns")
    ap.add_argument("--rounds", type=int, default=5, help="rounds per campaign")
    ap.add_argument("--candidates-per-round", type=int, default=20, help="candidates per round")
    ap.add_argument("--seeds", nargs="+", type=int, default=[1337, 1338, 1339, 1340, 1341])
    ap.add_argument("--fitness-modes", nargs="+", default=["current", "oracle_aware", "oracle_dominant"])
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--seed-corpus-dir", default="real_benign_corpus/all")
    ap.add_argument("--seed-cluster", default="text-generation")
    ap.add_argument("--attack-families", default="gadget,overwritten,external,indirect_chain")
    ap.add_argument("--oracle-model-dir", default="real_benign_corpus/oracle-calibrated/v5-recalibrated")
    ap.add_argument("--evasion-mode", default="adaptive", choices=["adaptive", "random", "off"])
    ap.add_argument("--ensemble-oracle", action="store_true")
    ap.add_argument("--no-unguided", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="show configs without running")
    
    args = ap.parse_args()
    
    if args.dry_run:
        configs = []
        for fitness_mode in args.fitness_modes:
            for i, seed in enumerate(args.seeds):
                print(f"  guided {fitness_mode} r{i+1} seed={seed}")
        if not args.no_unguided:
            for i, seed in enumerate(args.seeds):
                print(f"  unguided current r{i+1} seed={seed}")
        print(f"\nTotal: {3 * len(args.seeds) + (0 if args.no_unguided else len(args.seeds))} campaigns")
        return 0
    
    results = run_parallel_ablation(
        max_workers=args.max_workers,
        guided_fitness_modes=args.fitness_modes,
        seeds=args.seeds,
        rounds=args.rounds,
        candidates_per_round=args.candidates_per_round,
        db=args.db,
        backend=args.backend,
        seed_corpus_dir=args.seed_corpus_dir,
        seed_cluster="text-generation",
        attack_families=args.attack_families,
        oracle_model_dir=args.oracle_model_dir,
        evasion_mode=args.evasion_mode,
        ensemble_oracle=args.ensemble_oracle,
        unguided=not args.no_unguided,
    )
    
    # Print summary
    print("\n" + "=" * 80)
    print("PARALLEL ABLATION SUMMARY")
    print("=" * 80)
    for r in results:
        status = "OK" if r["returncode"] == 0 else f"FAIL({r['returncode']})"
        print(f"  {r['mode']}-{r['fitness_mode']}-r{r['replicate']}: {r['elapsed']:.0f}s {r['returncode']} {r['elapsed']:.0f}s")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())