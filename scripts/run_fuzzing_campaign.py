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
from pipeline.templates import FAMILIES, FAMILY_LABELS

DEFAULT_BASE = "ci/corpus/torch/benign/benign.pt"
PANEL_SCANNERS = ["picklescan", "fickling", "modelscan", "modeltracer"]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="run_fuzzing_campaign", description=__doc__)
    ap.add_argument("--base-checkpoint", default=DEFAULT_BASE,
                    help="benign torch checkpoint used as the mutation base")
    ap.add_argument("--seed-corpus-dir", default=None,
                    help="crawl corpus dir (real_benign_corpus/all) to seed the "
                         "campaign from a real task-cluster checkpoint instead of "
                         "the synthetic base; picks the smallest matching checkpoint")
    ap.add_argument("--seed-cluster", default=None,
                    help="task-cluster prefix filter for --seed-corpus-dir "
                         "(e.g. text-generation, text-classification, feature-extraction)")
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
    ap.add_argument("--attack-families", default=",".join(FAMILIES),
                    help="comma-separated seed attack families to sample across "
                         f"(default: {','.join(FAMILIES)})")
    ap.add_argument("--time-budget-hours", type=float, default=24.0,
                    help="bounded-pilot time budget; the campaign stops after this "
                         "elapses even if rounds remain")
    return ap.parse_args()


def _resolve_seed_checkpoint(args: argparse.Namespace) -> str:
    """Resolve the campaign seed: a real corpus checkpoint when --seed-corpus-dir
    is given, otherwise the --base-checkpoint path. The real-corpus layout is
    the flat ``<cluster>__<repo>.bin`` naming produced by the crawl; the
    smallest matching file is chosen so a pilot campaign stays fast."""
    if not args.seed_corpus_dir:
        return os.path.abspath(args.base_checkpoint)

    if not os.path.isdir(args.seed_corpus_dir):
        print(f"[campaign] error: seed corpus dir not found: {args.seed_corpus_dir}")
        raise SystemExit(1)

    candidates = []
    import zipfile
    for name in sorted(os.listdir(args.seed_corpus_dir)):
        if not name.endswith((".bin", ".pt", ".pth")):
            continue
        if args.seed_cluster and not name.startswith(args.seed_cluster + "__"):
            continue
        path = os.path.join(args.seed_corpus_dir, name)
        if os.path.isfile(path) and zipfile.is_zipfile(path):
            candidates.append((os.path.getsize(path), path))
    if not candidates:
        print(f"[campaign] error: no seed checkpoints matched in {args.seed_corpus_dir} "
              f"(cluster={args.seed_cluster})")
        raise SystemExit(1)

    _, path = min(candidates)
    print(f"[campaign] seeded from real corpus checkpoint: {path} "
          f"({os.path.getsize(path) / 1e6:.1f} MB)")
    return os.path.abspath(path)


def run_campaign(args: argparse.Namespace) -> int:
    print("=" * 60)
    print(f"STARTING {args.mode.upper()} FUZZING CAMPAIGN (replicate {args.replicate})")
    print("=" * 60)

    if args.seed is not None:
        random.seed(args.seed)
    load_registry()

    base_abs = _resolve_seed_checkpoint(args)
    if not os.path.isfile(base_abs):
        print(f"[campaign] error: base checkpoint not found: {base_abs}")
        return 1

    with open(base_abs, "rb") as f:
        benign_pt_bytes = f.read()

    families = [f.strip() for f in args.attack_families.split(",") if f.strip()]
    unknown = set(families) - set(FAMILIES)
    if unknown:
        print(f"[campaign] error: unknown attack families {sorted(unknown)} "
              f"(valid: {FAMILIES})")
        return 1

    run_id = f"{args.mode}-r{args.replicate}"
    db_path = args.db
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    init_db(db_path)
    total_candidates = args.rounds * args.candidates_per_round
    log_campaign_run(
        db_path, run_id, args.mode, args.replicate,
        base_abs, total_candidates, args.rounds,
    )

    # Candidates are persisted per-run so the DB filepaths never dangle and
    # export_bypasses can copy real artifacts. Only the trigger files (used by
    # the validity oracle, which mounts the system temp dir) are ephemeral.
    candidates_root = os.path.join("data", "candidates", run_id)
    temp_dir = tempfile.mkdtemp(prefix=f"regenbench_{run_id}_triggers_")
    started_at = time.time()
    time_limit = args.time_budget_hours * 3600.0
    try:
        generator = CandidateGenerator()
        oracle_val = ValidityOracle(container_backend=args.backend,
                                    timeout=args.validity_timeout)
        tracker = CoverageTracker(db_path, run_id=run_id)
        controller = FeedbackController()

        round_summaries = []
        budget_exhausted = False
        for r in range(1, args.rounds + 1):
            if budget_exhausted:
                break
            print(f"\n--- Round {r} / {args.rounds} ---")
            round_dir = os.path.join(candidates_root, f"round_{r}")
            os.makedirs(round_dir, exist_ok=True)

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
            family_counts = {f: 0 for f in families}
            for i in range(args.candidates_per_round):
                elapsed = time.time() - started_at
                if elapsed >= time_limit:
                    print(f"\n[budget] time limit reached after {elapsed / 3600:.2f}h; "
                          f"ending campaign early.")
                    budget_exhausted = True
                    break

                attack_family = random.choice(families)
                family_counts[attack_family] += 1
                if attack_family == "gadget":
                    if weights:
                        chosen_callable = random.choices(population, weights=weights, k=1)[0]
                    else:
                        chosen_callable = random.choice(population)
                else:
                    chosen_callable = None

                trigger_file = os.path.join(temp_dir, f"trigger_{r}_{i}.txt")
                payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"

                # Feedback-controlled mutation parameters. In guided mode the
                # controller's probs (from the previous round's fitness) drive
                # the operators; in unguided mode they stay at fixed baselines.
                if args.mode == "guided":
                    op_swap_prob = controller.op_swap_prob
                    callable_sub_prob = controller.callable_sub_prob
                    arg_fuzz_prob = controller.arg_fuzz_prob
                else:
                    op_swap_prob = 0.15
                    callable_sub_prob = 0.15
                    arg_fuzz_prob = 0.15
                try:
                    cand_bytes = generator.generate_candidate_pt(
                        benign_pt_bytes=benign_pt_bytes,
                        payload_code=payload,
                        dangerous_callable=chosen_callable,
                        mutate_meta=True,
                        mutation_prob=0.15,
                        op_swap_prob=op_swap_prob,
                        callable_sub_prob=callable_sub_prob,
                        arg_fuzz_prob=arg_fuzz_prob,
                        stack_prob=0.05,
                        attack_family=attack_family,
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
                        mutation_prob=0.15,
                        op_swap_prob=op_swap_prob,
                        callable_sub_prob=callable_sub_prob,
                        arg_fuzz_prob=arg_fuzz_prob,
                        stack_prob=0.05,
                        attack_family=attack_family,
                    )

                cand_path = os.path.join(round_dir, f"candidate_{i}.pt")
                with open(cand_path, "wb") as f:
                    f.write(cand_bytes)
                candidates.append((cand_path, cand_bytes, chosen_callable,
                                   trigger_file, attack_family))

            print(f"Generated {len(candidates)} candidate checkpoints "
                  f"(families: {family_counts}).")
            if not candidates:
                break

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

            for filepath, cand_bytes, chosen_callable, trigger_file, attack_family in candidates:
                cand_results = results_by_file.get(filepath, [])
                is_valid = oracle_val.validate_torch(cand_bytes, trigger_file)

                panel_verdicts = []
                oracle_verdict = "benign"
                decision_score = 0.0
                for r_scan in cand_results:
                    if r_scan.scanner == "dynahug":
                        # Fail-closed: an errored oracle is never "benign".
                        oracle_verdict = r_scan.verdict or "error"
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
                    seed_model=base_abs,
                    mutation_template=FAMILY_LABELS[attack_family],
                    mutation_depth=r,
                    callables_used=(
                        f"{chosen_callable[0]}::{chosen_callable[1]}"
                        if chosen_callable else f"family::{attack_family}"
                    ),
                    campaign_type=args.mode,
                    run_id=run_id,
                )
                log_fitness(db_path, cand_id, fit_score, is_valid)

                round_results.append({
                    "callable": chosen_callable,
                    "family": attack_family,
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
                "generated_count": len(candidates),
                "valid_count": valid_cnt,
                "bypass_count": bypasses_cnt,
                "mean_fitness": mean_fitness,
                "opcode_cov": opcode_cov,
                "callable_cov": callable_cov,
                "families": family_counts,
            })

            print(f"Round {r} Complete: Valid={valid_cnt}/{len(candidates)}, "
                  f"Bypasses={bypasses_cnt}, Mean Fitness={mean_fitness:.3f}, "
                  f"Opcode Cov={opcode_cov * 100:.1f}%, Callable Cov={callable_cov * 100:.1f}%")

        # If the time budget cut the campaign short, correct the recorded
        # total so RQ2 censoring and completeness stats use the true count.
        actual_total = sum(s["generated_count"] for s in round_summaries)
        if actual_total != total_candidates:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE campaign_runs SET total_candidates = ? WHERE run_id = ?",
                         (actual_total, run_id))
            conn.commit()
            conn.close()
            print(f"[campaign] budget stop: updated total_candidates "
                  f"{total_candidates} -> {actual_total}")

        complete_campaign_run(db_path, run_id)

        docs_dir = "docs"
        os.makedirs(docs_dir, exist_ok=True)
        report_path = os.path.join(docs_dir, f"fuzzing-report-{run_id}.md")
        family_totals = {f: sum(s.get("families", {}).get(f, 0)
                                for s in round_summaries) for f in families}
        report_lines = [
            f"# ReGenBench Fuzzing Report ({args.mode}, replicate {args.replicate})",
            "",
            f"- Mode: **{args.mode}**  ",
            f"- Base checkpoint: `{base_abs}`  ",
            f"- Attack families: {', '.join(families)}  ",
            f"- Rounds: {args.rounds}, candidates/round: {args.candidates_per_round}",
            f"- Time budget: {args.time_budget_hours}h",
            f"- DB: `{db_path}`",
            "",
            "| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |",
            "| :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for s in round_summaries:
            report_lines.append(
                f"| {s['round']} | {s['valid_count']} / {s['generated_count']} | "
                f"{s['bypass_count']} | {s['mean_fitness']:.3f} | "
                f"{s['opcode_cov'] * 100:.1f}% | {s['callable_cov'] * 100:.1f}% |"
            )
        report_lines += [
            "",
            "## Attack-family distribution",
            "",
            "| Family | Candidates |",
            "| :--- | :---: |",
        ]
        report_lines += [f"| {f} | {family_totals[f]} |" for f in families]
        with open(report_path, "w") as f:
            f.write("\n".join(report_lines))
        print(f"\nWritten fuzzing report to {report_path}")

        total_bypass = sum(s["bypass_count"] for s in round_summaries)
        total_valid = sum(s["valid_count"] for s in round_summaries)
        print("=" * 60)
        print(f"CAMPAIGN COMPLETE ({args.mode}, replicate {args.replicate})")
        print(f"  valid candidates : {total_valid}/{actual_total}")
        print(f"  confirmed bypasses: {total_bypass}")
        print("=" * 60)
        return 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _registry_callables():
    """Lazily read the dangerous-callable registry entries for unguided selection.

    Uses the armable subset so unguided candidates never pick a callable that
    cannot carry the inline payload (runpy.run_module, pandas.eval,
    sympy.sympify, yaml.unsafe_load).
    """
    from pipeline.registry import get_armable_entries
    return [(e.module, e.name) for e in get_armable_entries()]


if __name__ == "__main__":
    sys.exit(run_campaign(parse_args()))
