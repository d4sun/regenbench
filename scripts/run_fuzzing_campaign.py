#!/usr/bin/env python3
"""T5.5 — Fuzzing Campaign Runner (guided / unguided, replicate-aware).

Runs a feedback-directed (guided) or uniform-random (unguided) fuzzing campaign
against a real benign base checkpoint. Logs per-candidate metadata (seed model,
template, mutation depth, callables used, round, campaign type) into the unified
SQLite database, plus per-round coverage and per-candidate fitness.

This is the harness behind the staged experiment:
    pilot:  --mode guided   --rounds 5 --candidates-per-round 20
            --mode unguided --rounds 5 --candidates-per-round 20
    main:   --mode guided   --rounds 25 --candidates-per-round 20  (5 replicates)

Usage:
    PYTHONPATH=.:.pip_deps python3 scripts/run_fuzzing_campaign.py \
        --base-checkpoint real_benign_corpus/all/.../pytorch_model.bin \
        --mode guided --rounds 5 --candidates-per-round 20 \
        --replicate 1 --db data/regenbench_campaign.db \
        --backend podman
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import shutil
import sys
import tempfile
import time

from pipeline.generator import CandidateGenerator
from pipeline.runner import Runner, Config
from pipeline.validity import ValidityOracle
from pipeline.db import (
    complete_campaign_run,
    init_db,
    log_campaign_run,
    log_candidate,
    log_fitness,
)
from pipeline.comparator import check_bypass
from pipeline.fitness import compute_fitness
from pipeline.feedback import CoverageTracker, FeedbackController
from pipeline.registry import load_registry

DEFAULT_BASE = "ci/corpus/torch/benign/benign.pt"
PANEL_SCANNERS = ["picklescan", "fickling", "modelscan", "modeltracer"]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="run_fuzzing_campaign", description=__doc__)
    ap.add_argument("--base-checkpoint", default=DEFAULT_BASE,
                    help="benign torch checkpoint used as the mutation base")
    ap.add_argument("--mode", choices=["guided", "unguided"], default="guided",
                    help="selection strategy (guided = feedback weights, unguided = uniform)")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--candidates-per-round", type=int, default=20)
    ap.add_argument("--replicate", type=int, default=1,
                    help="replicate number (1..N); recorded in campaign_runs")
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-scan container timeout (seconds)")
    ap.add_argument("--validity-timeout", type=int, default=20,
                    help="per-validity-check container timeout (seconds)")
    ap.add_argument("--panel-scanners", nargs="+", default=None,
                    help="override panel scanner list. Default full panel "
                         "(picklescan fickling modelscan modeltracer); for real torch "
                         "checkpoints use 'picklescan modelscan' because fickling and "
                         "modeltracer cannot analyze torch artifacts")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--pre-filter", action="store_true",
                    help="enable the static pre-filter before the DynaHug oracle")
    ap.add_argument("--seed", type=int, default=None,
                    help="random seed for reproducibility")
    return ap.parse_args()


def run_campaign(args: argparse.Namespace) -> int:
    print("=" * 60)
    print(f"STARTING {args.mode.upper()} FUZZING CAMPAIGN (replicate {args.replicate})")
    print("=" * 60)

    if args.seed is not None:
        random.seed(args.seed)
    load_registry()

    base_abs = os.path.abspath(args.base_checkpoint)
    if not os.path.isfile(base_abs):
        print(f"[campaign] error: base checkpoint not found: {base_abs}")
        return 1

    with open(base_abs, "rb") as f:
        benign_pt_bytes = f.read()

    run_id = f"{args.mode}-r{args.replicate}"
    db_path = args.db
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    init_db(db_path)
    total_candidates = args.rounds * args.candidates_per_round
    log_campaign_run(
        db_path, run_id, args.mode, args.replicate,
        base_abs, total_candidates, args.rounds,
    )

    temp_dir = tempfile.mkdtemp(prefix=f"regenbench_{run_id}_")
    try:
        generator = CandidateGenerator()
        oracle_val = ValidityOracle(container_backend=args.backend,
                                    timeout=args.validity_timeout)
        tracker = CoverageTracker(db_path)
        controller = FeedbackController()

        round_summaries = []
        for r in range(1, args.rounds + 1):
            print(f"\n--- Round {r} / {args.rounds} ---")
            round_dir = os.path.join(temp_dir, f"round_{r}")
            os.makedirs(round_dir)

            if args.mode == "guided":
                callable_weights_map = controller.get_callable_weights()
                population = list(callable_weights_map.keys())
                weights = list(callable_weights_map.values())
                print(f"Mutation params: op_swap={controller.op_swap_prob:.2f}, "
                      f"sub={controller.callable_sub_prob:.2f}, fuzz={controller.arg_fuzz_prob:.2f}")
            else:
                population = [e for e in _registry_callables()]
                weights = None
                print("Unguided mode: uniform random callable selection.")

            candidates = []
            for i in range(args.candidates_per_round):
                if weights:
                    chosen_callable = random.choices(population, weights=weights, k=1)[0]
                else:
                    chosen_callable = random.choice(population)

                trigger_file = os.path.join(temp_dir, f"trigger_{r}_{i}.txt")
                payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"

                mut_prob = controller.op_swap_prob if args.mode == "guided" else 0.15
                try:
                    cand_bytes = generator.generate_candidate_pt(
                        benign_pt_bytes=benign_pt_bytes,
                        payload_code=payload,
                        dangerous_callable=chosen_callable,
                        mutate_meta=True,
                        mutation_prob=mut_prob,
                    )
                except ValueError as e:
                    # Unsupported callable (e.g. runpy.run_module cannot execute
                    # inline code). Resample a supported callable for this slot.
                    print(f"  [skip] {chosen_callable}: {e}")
                    supported = [c for c in population if c != chosen_callable] or population
                    chosen_callable = random.choice(supported)
                    cand_bytes = generator.generate_candidate_pt(
                        benign_pt_bytes=benign_pt_bytes,
                        payload_code=payload,
                        dangerous_callable=chosen_callable,
                        mutate_meta=True,
                        mutation_prob=mut_prob,
                    )

                cand_path = os.path.join(round_dir, f"candidate_{i}.pt")
                with open(cand_path, "wb") as f:
                    f.write(cand_bytes)
                candidates.append((cand_path, cand_bytes, chosen_callable, trigger_file))

            print(f"Generated {len(candidates)} candidate checkpoints.")

            config = Config(
                backend=args.backend, tag=args.tag,
                max_workers=args.workers, timeout=args.timeout,
                oracle=True, pre_filter=args.pre_filter,
            )
            panel = args.panel_scanners or PANEL_SCANNERS
            runner = Runner(config, scanners=panel + ["dynahug"])
            cand_paths = [c[0] for c in candidates]
            results = runner.run(cand_paths, db_path=db_path)

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
                        # Fail-closed: a scanner that errors (parse failure, scan
                        # timeout) is recorded as "error", never as "benign", so
                        # an errored scanner cannot count as "evaded".
                        panel_verdicts.append(r_scan.verdict or "error")

                if is_valid:
                    valid_cnt += 1
                    fit_score = compute_fitness(
                        detected_count=sum(1 for v in panel_verdicts if v == "malicious"),
                        total_scanners=len(panel_verdicts),
                        decision_score=decision_score,
                    )
                else:
                    fit_score = 0.0

                is_bypass = is_valid and check_bypass(panel_verdicts, oracle_verdict)
                if is_bypass:
                    bypasses_cnt += 1

                cand_id = hashlib.md5(filepath.encode("utf-8")).hexdigest()
                log_candidate(
                    db_path, cand_id, filepath, args.mode,
                    round_num=r,
                    seed_model=args.base_checkpoint,
                    mutation_template="inject_payload_into_torch",
                    mutation_depth=r,
                    callables_used=f"{chosen_callable[0]}::{chosen_callable[1]}",
                    campaign_type=args.mode,
                )
                log_fitness(db_path, cand_id, fit_score, is_valid)

                round_results.append({
                    "callable": chosen_callable,
                    "fitness": fit_score,
                    "evaded_all": all(v == "benign" for v in panel_verdicts),
                    "valid": is_valid,
                })
                tracker.track_candidate(filepath)

            opcode_cov, callable_cov = tracker.log_round(r)
            if args.mode == "guided":
                controller.update(round_results)

            mean_fitness = sum(x["fitness"] for x in round_results) / len(round_results)
            round_summaries.append({
                "round": r,
                "valid_count": valid_cnt,
                "bypass_count": bypasses_cnt,
                "mean_fitness": mean_fitness,
                "opcode_cov": opcode_cov,
                "callable_cov": callable_cov,
            })

            print(f"Round {r} Complete: Valid={valid_cnt}/{len(candidates)}, "
                  f"Bypasses={bypasses_cnt}, Mean Fitness={mean_fitness:.3f}, "
                  f"Opcode Cov={opcode_cov * 100:.1f}%, Callable Cov={callable_cov * 100:.1f}%")

        complete_campaign_run(db_path, run_id)

        docs_dir = "docs"
        os.makedirs(docs_dir, exist_ok=True)
        report_path = os.path.join(docs_dir, f"fuzzing-report-{run_id}.md")
        report_lines = [
            f"# ReGenBench Fuzzing Report ({args.mode}, replicate {args.replicate})",
            "",
            f"- Mode: **{args.mode}**  ",
            f"- Base checkpoint: `{args.base_checkpoint}`  ",
            f"- Rounds: {args.rounds}, candidates/round: {args.candidates_per_round}",
            f"- DB: `{db_path}`",
            "",
            "| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |",
            "| :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for s in round_summaries:
            report_lines.append(
                f"| {s['round']} | {s['valid_count']} / {args.candidates_per_round} | "
                f"{s['bypass_count']} | {s['mean_fitness']:.3f} | "
                f"{s['opcode_cov'] * 100:.1f}% | {s['callable_cov'] * 100:.1f}% |"
            )
        with open(report_path, "w") as f:
            f.write("\n".join(report_lines))
        print(f"\nWritten fuzzing report to {report_path}")

        total_bypass = sum(s["bypass_count"] for s in round_summaries)
        total_valid = sum(s["valid_count"] for s in round_summaries)
        print("=" * 60)
        print(f"CAMPAIGN COMPLETE ({args.mode}, replicate {args.replicate})")
        print(f"  valid candidates : {total_valid}/{total_candidates}")
        print(f"  confirmed bypasses: {total_bypass}")
        print("=" * 60)
        return 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _registry_callables():
    """Lazily read the dangerous-callable registry entries for unguided selection."""
    from pipeline.registry import get_all_entries
    return [(e.module, e.name) for e in get_all_entries()]


if __name__ == "__main__":
    sys.exit(run_campaign(parse_args()))
