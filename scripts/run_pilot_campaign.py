#!/usr/bin/env python3
"""T6.2 — Pilot Campaign Execution Driver.

Loads config/campaign_config.yaml, executes the E2E directed fuzzing loop,
populates the campaign database, and exports bypasses using the Corpus Manager.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import tempfile
import time
import yaml

from pipeline.generator import CandidateGenerator
from pipeline.runner import Runner, Config
from pipeline.validity import ValidityOracle
from pipeline.db import init_db, log_candidate, log_panel_result, log_oracle_result, log_fitness
from pipeline.comparator import check_bypass
from pipeline.fitness import compute_fitness
from pipeline.feedback import CoverageTracker, FeedbackController
from pipeline.corpus_manager import export_bypasses
from pipeline.registry import load_registry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run directed fuzzing pilot campaign.")
    ap.add_argument("--config", default="config/campaign_config.yaml", help="YAML configuration file path")
    ap.add_argument("--db", default="data/regenbench_campaign.db", help="output SQLite database path")
    ap.add_argument("--quick", action="store_true", help="run a quick campaign validation instead of the full run")
    args = ap.parse_args(argv)

    print("====================================================")
    print("STARTING PILOT FUZZING CAMPAIGN (T6.2)")
    print("====================================================")
    
    load_registry()

    # Load campaign configuration
    if not os.path.exists(args.config):
        print(f"Error: configuration file {args.config} not found.")
        return 1
        
    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f).get("campaign", {})

    name = cfg.get("name", "pilot-campaign")
    time_limit_hours = cfg.get("time_budget_hours", 24)
    task_cluster = cfg.get("task_cluster", "text-generation")
    scanners = cfg.get("scanners", ["picklescan", "dynahug"])
    
    # Adapt campaign scale based on flags
    if args.quick:
        rounds = 3
        candidates_per_round = 10
        print("[Pilot Mode] running in validation mode: 3 rounds of 10 candidates.")
    else:
        rounds = cfg.get("default_rounds", 5)
        candidates_per_round = cfg.get("candidates_per_round", 20)
        print(f"[Pilot Mode] running full campaign: {rounds} rounds of {candidates_per_round} candidates.")

    print(f"Campaign: {name}")
    print(f"Database: {args.db}")
    print(f"Task Cluster: {task_cluster}")
    print(f"Scanners: {scanners}")

    # Ensure output directories exist
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    init_db(args.db)

    # Core fuzzing engines
    generator = CandidateGenerator()
    oracle_val = ValidityOracle(container_backend="podman")
    tracker = CoverageTracker(args.db)
    controller = FeedbackController()

    # Load benign PyTorch model base (text-generation cluster seed representation)
    with open("ci/corpus/torch/benign/benign.pt", "rb") as f:
        benign_pt_bytes = f.read()

    # Temporary directory for intermediate campaign round checkpoints
    temp_dir = tempfile.mkdtemp()
    
    start_time = time.time()
    time_limit = time_limit_hours * 3600 if not args.quick else 1800 # 30 mins limit for quick runs
    
    try:
        for r in range(1, rounds + 1):
            # Check time limit
            elapsed = time.time() - start_time
            if elapsed >= time_limit:
                print(f"\nTime limit reached ({elapsed/3600:.1f} hours elapsed). Ending campaign.")
                break

            print(f"\n--- Campaign Round {r} / {rounds} ---")
            round_dir = os.path.join(temp_dir, f"round_{r}")
            os.makedirs(round_dir)

            # 1. Sample dangerous callables from weights
            callable_weights_map = controller.get_callable_weights()
            population = list(callable_weights_map.keys())
            weights = list(callable_weights_map.values())

            candidates = []
            for i in range(candidates_per_round):
                chosen_callable = random.choices(population, weights=weights, k=1)[0]
                
                trigger_file = os.path.join(temp_dir, f"trigger_{r}_{i}.txt")
                payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"
                
                cand_bytes = generator.generate_candidate_pt(
                    benign_pt_bytes=benign_pt_bytes,
                    payload_code=payload,
                    dangerous_callable=chosen_callable,
                    mutate_meta=True,
                    mutation_prob=controller.op_swap_prob,
                )
                
                cand_path = os.path.join(round_dir, f"candidate_{i}.pt")
                with open(cand_path, "wb") as f:
                    f.write(cand_bytes)
                    
                candidates.append((cand_path, cand_bytes, chosen_callable, trigger_file))

            # 2. Run scanners and dynahug oracle
            config = Config(backend="podman", tag=":latest", max_workers=4, timeout=45, oracle=True, pre_filter=True)
            runner = Runner(config, scanners=scanners)
            
            cand_paths = [c[0] for c in candidates]
            results = runner.run(cand_paths, db_path=args.db)

            # 3. Evaluate results
            results_by_file = {}
            for res in results:
                results_by_file.setdefault(res.artifact, []).append(res)

            round_results = []
            bypasses_cnt = 0
            valid_cnt = 0

            for filepath, cand_bytes, chosen_callable, trigger_file in candidates:
                cand_results = results_by_file.get(filepath, [])
                
                is_valid = oracle_val.validate_torch(cand_bytes, trigger_file)
                
                panel_verdicts = []
                oracle_verdict = "benign"
                decision_score = 0.0
                
                for r_scan in cand_results:
                    if r_scan.scanner == "dynahug":
                        oracle_verdict = r_scan.verdict or "benign"
                        decision_score = r_scan.decision_score or 0.0
                    else:
                        panel_verdicts.append(r_scan.verdict or "benign")

                if is_valid:
                    valid_cnt += 1
                    fit_score = compute_fitness(
                        detected_count=sum(1 for v in panel_verdicts if v == "malicious"),
                        total_scanners=len(panel_verdicts),
                        decision_score=decision_score
                    )
                else:
                    fit_score = 0.0

                is_bypass = is_valid and check_bypass(panel_verdicts, oracle_verdict)
                if is_bypass:
                    bypasses_cnt += 1

                import hashlib
                cand_id = hashlib.md5(filepath.encode("utf-8")).hexdigest()
                log_fitness(args.db, cand_id, fit_score, is_valid)

                round_results.append({
                    "callable": chosen_callable,
                    "fitness": fit_score,
                    "evaded_all": all(v == "benign" for v in panel_verdicts),
                    "valid": is_valid
                })
                tracker.track_candidate(filepath)

            opcode_cov, callable_cov = tracker.log_round(r)
            controller.update(round_results)

            print(f"Round {r} Complete: Valid={valid_cnt}/{candidates_per_round}, "
                  f"Bypasses={bypasses_cnt}, Opcode Coverage={opcode_cov * 100:.1f}%, "
                  f"Callable Coverage={callable_cov * 100:.1f}%")

        # 4. Export Bypasses using Corpus Manager
        print("\nDeduplicating and exporting confirmed bypasses...")
        output_dir = "data/bypasses/v0.1"
        export_count = export_bypasses(args.db, output_dir)
        print(f"Successfully exported {export_count} unique confirmed bypasses to {output_dir}")

        print("\n====================================================")
        print("PILOT FUZZING CAMPAIGN EXECUTED SUCCESSFULLY!")
        print("====================================================")
        return 0

    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    import sys
    sys.exit(main())
