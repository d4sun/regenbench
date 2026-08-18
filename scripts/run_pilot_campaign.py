#!/usr/bin/env python3
"""T6.2 — Pilot Campaign Execution Driver.

Loads config/campaign_config.yaml, executes the E2E directed fuzzing loop,
populates the campaign database, and exports bypasses using the Corpus Manager.
Candidates are persisted under data/candidates/<run_id>/ so the exported
bypasses always reference real files, and progress is checkpointed so a run
can be resumed with --resume <run_id>.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import tempfile
import time
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.generator import CandidateGenerator
from pipeline.runner import Runner, Config
from pipeline.validity import ValidityOracle
from pipeline.db import (init_db, log_candidate, log_fitness, log_campaign_run,
                         complete_campaign_run)
from pipeline.comparator import check_bypass
from pipeline.fitness import compute_fitness
from pipeline.feedback import CoverageTracker, FeedbackController
from pipeline.corpus_manager import export_bypasses
from pipeline.registry import load_registry
from pipeline.templates import FAMILIES, FAMILY_LABELS


def _default_scanners(panel: list[str], oracle: list[str]) -> list[str]:
    return panel + oracle


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run directed fuzzing pilot campaign.")
    ap.add_argument("--config", default="config/campaign_config.yaml", help="YAML configuration file path")
    ap.add_argument("--db", default="data/regenbench_campaign.db", help="output SQLite database path")
    ap.add_argument("--quick", action="store_true", help="run a quick campaign validation instead of the full run")
    ap.add_argument("--resume", default=None, metavar="RUN_ID",
                    help="resume a previously interrupted campaign run_id (skips completed rounds)")
    ap.add_argument("--attack-families", default=",".join(FAMILIES),
                    help="comma-separated seed attack families to sample across "
                         f"(default: {','.join(FAMILIES)})")
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
    rounds = cfg.get("rounds", 5)
    candidates_per_round = cfg.get("candidates_per_round", 20)
    concurrency_limit = cfg.get("concurrency_limit", 2)
    timeout_seconds = cfg.get("timeout_seconds", 120)
    time_budget_hours = cfg.get("time_budget_hours", 24)
    base_checkpoint = cfg.get("base_checkpoint", "ci/corpus/torch/benign/benign.pt")

    # The task cluster is the cluster directory of the seed checkpoint, e.g.
    # real_benign_corpus/all/<cluster>/<model>/<file>. Falls back to the config
    # value or a default when the path is not under the corpus layout.
    task_cluster = cfg.get("task_cluster", "text-generation")
    norm_path = os.path.normpath(base_checkpoint)
    parts = norm_path.split(os.sep)
    if "all" in parts:
        idx = parts.index("all")
        if idx + 1 < len(parts):
            task_cluster = parts[idx + 1]

    panel_scanners = cfg.get("panel_scanners", ["picklescan", "fickling"])
    oracle_scanners = cfg.get("oracle_scanners", ["dynahug"])
    scanners = _default_scanners(panel_scanners, oracle_scanners)

    # Adapt campaign scale based on flags
    if args.quick:
        rounds = min(rounds, 3)
        candidates_per_round = min(candidates_per_round, 10)
        print("[Pilot Mode] running in validation mode (quick).")

    print(f"Campaign: {name}")
    print(f"Database: {args.db}")
    print(f"Task Cluster: {task_cluster}")
    print(f"Base checkpoint: {base_checkpoint}")
    print(f"Scanners: {scanners}")
    print(f"Rounds: {rounds}, Candidates/Round: {candidates_per_round}")
    print(f"Concurrency Limit: {concurrency_limit}")
    print(f"Time Budget: {time_budget_hours} hours")

    # Ensure output directories exist
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    init_db(args.db)

    run_id = args.resume
    if run_id is None:
        run_id = time.strftime("pilot-%Y%m%dT%H%M%SZ", time.gmtime())
    db_dir = os.path.dirname(os.path.abspath(args.db))
    checkpoint_path = os.path.join(db_dir, f"{run_id}.checkpoint.json")
    completed_rounds: set[int] = set()
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as f:
            completed_rounds = set(json.load(f).get("completed_rounds", []))
        print(f"[resume] found checkpoint for {run_id}; skipping {sorted(completed_rounds)}")

    # Core fuzzing engines
    generator = CandidateGenerator()
    oracle_val = ValidityOracle(container_backend="podman")
    tracker = CoverageTracker(args.db, run_id=run_id)
    controller = FeedbackController()

    families = [f.strip() for f in args.attack_families.split(",") if f.strip()]
    unknown = set(families) - set(FAMILIES)
    if unknown:
        print(f"Error: unknown attack families {sorted(unknown)} (valid: {FAMILIES}).")
        return 1

    # Load benign PyTorch model base (task-cluster seed representation)
    if not os.path.exists(base_checkpoint):
        print(f"Error: base checkpoint {base_checkpoint} not found (config/campaign_config.yaml:campaign.base_checkpoint).")
        return 1
    with open(base_checkpoint, "rb") as f:
        benign_pt_bytes = f.read()

    # Candidate files are persisted per-run so the exported bypasses reference
    # files that still exist. Trigger files stay in /tmp (the validity oracle
    # mounts the system temp dir into the container).
    candidates_root = os.path.join("data", "candidates", run_id)
    trigger_temp = tempfile.mkdtemp(prefix="pilot-triggers-")

    log_campaign_run(
        args.db, run_id, "guided", 1, base_checkpoint,
        rounds * candidates_per_round, rounds,
    )

    start_time = time.time()
    time_limit = time_budget_hours * 3600

    try:
        for r in range(1, rounds + 1):
            if r in completed_rounds:
                print(f"\n[resume] round {r} already completed; skipping.")
                continue

            # Check time limit
            elapsed = time.time() - start_time
            if elapsed >= time_limit:
                print(f"\nTime limit reached ({elapsed/3600:.1f} hours elapsed). Ending campaign.")
                break

            print(f"\n--- Campaign Round {r} / {rounds} ---")
            round_dir = os.path.join(candidates_root, f"round_{r}")
            os.makedirs(round_dir, exist_ok=True)

            # 1. Sample dangerous callables from weights
            callable_weights_map = controller.get_callable_weights()
            population = list(callable_weights_map.keys())
            weights = list(callable_weights_map.values())

            candidates = []
            family_counts = {f: 0 for f in families}
            for i in range(candidates_per_round):
                attack_family = random.choice(families)
                family_counts[attack_family] += 1
                if attack_family == "gadget":
                    chosen_callable = random.choices(population, weights=weights, k=1)[0]
                else:
                    chosen_callable = None

                trigger_file = os.path.join(trigger_temp, f"trigger_{r}_{i}.txt")
                payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"

                cand_bytes = None
                for _attempt in range(5):
                    try:
                        cand_bytes = generator.generate_candidate_pt(
                            benign_pt_bytes=benign_pt_bytes,
                            payload_code=payload,
                            dangerous_callable=chosen_callable,
                            mutate_meta=True,
                            mutation_prob=0.15,
                            op_swap_prob=controller.op_swap_prob,
                            callable_sub_prob=controller.callable_sub_prob,
                            arg_fuzz_prob=controller.arg_fuzz_prob,
                            stack_prob=0.05,
                            attack_family=attack_family,
                        )
                        break
                    except ValueError as e:
                        print(f"[warning] candidate generation failed for {chosen_callable}: {e}; resampling")
                        if attack_family == "gadget":
                            chosen_callable = random.choices(population, weights=weights, k=1)[0]
                if cand_bytes is None:
                    continue

                cand_path = os.path.join(round_dir, f"candidate_{i}.pt")
                with open(cand_path, "wb") as f:
                    f.write(cand_bytes)

                candidates.append((cand_path, cand_bytes, chosen_callable, trigger_file, attack_family))

            # 2. Run scanners and dynahug oracle
            config = Config(backend="podman", tag=":latest", max_workers=concurrency_limit,
                            timeout=timeout_seconds, oracle=True, pre_filter=True)
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

            for filepath, cand_bytes, chosen_callable, trigger_file, attack_family in candidates:
                cand_results = results_by_file.get(filepath, [])

                is_valid = oracle_val.validate_torch(cand_bytes, trigger_file)

                panel_verdicts = []
                oracle_verdict = "benign"
                decision_score = 0.0

                for r_scan in cand_results:
                    if r_scan.scanner == "dynahug":
                        # Fail-closed: an errored oracle never counts as benign.
                        oracle_verdict = r_scan.verdict or "error"
                        decision_score = r_scan.decision_score or 0.0
                    else:
                        panel_verdicts.append(r_scan.verdict or "error")

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

                cand_id = hashlib.md5(filepath.encode("utf-8")).hexdigest()
                log_candidate(args.db, cand_id, filepath, source="pilot",
                              round_num=r, seed_model=base_checkpoint,
                              mutation_template=FAMILY_LABELS[attack_family],
                              campaign_type="guided", run_id=run_id)
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

            # Checkpoint this round
            completed_rounds.add(r)
            with open(checkpoint_path, "w") as f:
                json.dump({"run_id": run_id, "completed_rounds": sorted(completed_rounds)}, f)

            print(f"Round {r} Complete: Valid={valid_cnt}/{len(candidates)}, "
                  f"Bypasses={bypasses_cnt}, Opcode Coverage={opcode_cov * 100:.1f}%, "
                  f"Callable Coverage={callable_cov * 100:.1f}%")

        # 4. Export Bypasses using Corpus Manager
        print("\nDeduplicating and exporting confirmed bypasses...")
        output_dir = os.path.join("data", "bypasses", run_id)
        export_count = export_bypasses(args.db, output_dir)
        print(f"Successfully exported {export_count} unique confirmed bypasses to {output_dir}")

        complete_campaign_run(args.db, run_id)

        print("\n====================================================")
        print("PILOT FUZZING CAMPAIGN EXECUTED SUCCESSFULLY!")
        print("====================================================")
        return 0

    finally:
        import shutil
        shutil.rmtree(trigger_temp, ignore_errors=True)


if __name__ == "__main__":
    import sys
    sys.exit(main())
