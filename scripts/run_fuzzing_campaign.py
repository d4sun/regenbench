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
        --backend docker
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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.opcodes import parse_pickle
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
from pipeline.comparator import check_bypass, check_bypass_tier
from pipeline.fitness import compute_fitness, compute_fitness_multi, compute_fitness_oracle_aware, compute_fitness_lexicographic, compute_fitness_continuous, compute_fitness_coverage_guided, FitnessMode
from pipeline.feedback import CoverageTracker, FeedbackController, NoveltyTracker
from pipeline.registry import load_registry
from pipeline.templates import FAMILIES, FAMILY_LABELS
from pipeline.shelf_life import register_confirmed_bypass
from pipeline.plausibility import PlausibilityOracle

import concurrent.futures

DEFAULT_BASE = "ci/corpus/torch/benign/benign.pt"
# Static panel capable of analyzing torch-zip artifacts. ModelTracer is
# dynamic (strace) and excluded from RQ1 static-evasion measurement; add it
# explicitly via --panel-scanners when behavioral tracing is wanted.
PANEL_SCANNERS = ["picklescan", "fickling", "modelscan"]


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
    ap.add_argument("--candidates-per-round", type=int, default=50)
    ap.add_argument("--replicate", type=int, default=1,
                    help="replicate number (1..N); recorded in campaign_runs")
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--backend", choices=["podman", "docker"], default="docker")
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
    ap.add_argument("--gen-workers", type=int, default=0,
                    help="parallel workers for candidate generation (0=auto, min(8, cpu_count))")
    ap.add_argument("--pre-filter", action="store_true",
                    help="enable the static pre-filter before the DynaHug oracle")
    ap.add_argument("--seed", type=int, default=None,
                    help="random seed for reproducibility")
    ap.add_argument("--attack-families", default=",".join(FAMILIES),
                    help="comma-separated seed attack families to sample across "
                         f"(default: {','.join(FAMILIES)})")
    ap.add_argument("--evasion-mode", choices=["adaptive", "random", "off"],
                    default="off",
                    help="Phase-1 signature-evasion pipeline: 'adaptive' lets "
"guided feedback pick strategy subsets, 'random' "
                          "samples uniformly (unguided ablation baseline), "
                          "'off' disables (legacy behaviour)")
    ap.add_argument("--evasion-strategies", default=None,
                     help="comma-separated fixed strategy subset "
                          "(stack_global_encoding,payload_obfuscation,"
                          "indirect_chain,nested_loads_wrap); overrides mode")
    ap.add_argument("--fitness-mode", choices=["current", "oracle_aware", "oracle_dominant", "continuous", "coverage_guided"],
                      default="current",
                      help="fitness computation mode for ablation: "
                           "'current' = panel evasion + boundary + novelty; "
                           "'oracle_aware' = oracle confirmation multiplier on evasion; "
                           "'oracle_dominant' = lexicographic ranking (deprecated, creates plateaus); "
                           "'continuous' = smooth multi-objective (evasion * oracle_mult + boundary + novelty + coverage); "
                           "'coverage_guided' = coverage delta primary when evasion plateaus")
    ap.add_argument("--time-budget-hours", type=float, default=24.0,
                      help="bounded-pilot time budget; the campaign stops after this "
                           "elapses even if rounds remain")
    ap.add_argument("--differential-prob", type=float, default=0.0,
                      help="probability of applying differential pickle-parser mutation (Phase 3a)")
    ap.add_argument("--family-synthesis-prob", type=float, default=0.0,
                      help="probability of applying family-synthesis mutation (Phase 3b)")
    ap.add_argument("--oracle-model-dir", default="real_benign_corpus/oracle-calibrated/v5-recalibrated",
                      help="path to recalibrated DynaHug model directory")
    ap.add_argument("--family-quota-min-pct", type=float, default=0.15,
                    help="P1.1: minimum fraction per family per round (default 0.15, 0 to disable)")
    ap.add_argument("--family-quota-max-frac", type=float, default=0.40,
                    help="P1.1: maximum fraction per family per round (default 0.40)")
    ap.add_argument("--entropy-target", type=float, default=1.5,
                    help="P1.1: family entropy target (1.61 uniform); boost missing if below")
    ap.add_argument("--demo-subset", action="store_true",
                    help="Task 3 smoke mode: one round and five candidates from ci/corpus")
    ap.add_argument("--ensemble-oracle", action="store_true",
                      help="use ensemble oracle (DynaHug + syscall anomaly detector)")
    ap.add_argument("--anomaly-model-dir", default="real_benign_corpus/oracle-calibrated/v5-recalibrated/anomaly",
                      help="path to trained anomaly detector model")
    ap.add_argument("--anomaly-threshold", type=float, default=0.0,
                      help="anomaly score threshold for ensemble decision")
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
    rng_seed: int | None = None,
) -> bytes:
    """Worker function for parallel candidate generation.
    
    Must be a top-level function for pickling in ProcessPoolExecutor.

    Forked workers inherit the parent's module-level ``random`` state at fork
    time and race, so without an explicit reseed the generated bytes depend on
    worker scheduling -- the same command can produce different candidates.
    ``rng_seed`` (derived from the campaign seed + round + candidate index)
    makes each candidate a pure function of its position, independent of
    parallelism. ``None`` keeps the legacy fork-inherited behaviour.
    """
    if rng_seed is not None:
        random.seed(rng_seed)
    from pipeline.generator import CandidateGenerator
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


def _candidate_rng_seed(base_seed: int | None, round_num: int, index: int) -> int | None:
    """Deterministic per-candidate seed for fork-safe parallel generation.

    ``(base_seed, round_num, index)`` uniquely identifies a candidate within a
    campaign, so the derived seed reproduces identical bytes for that slot on
    every run of the same command. Returns ``None`` when the campaign itself is
    unseeded (no reproducibility requested).
    """
    if base_seed is None:
        return None
    key = f"{base_seed}:{round_num}:{index}".encode("utf-8")
    return int(hashlib.sha256(key).hexdigest(), 16) % (2**32)


def run_campaign(args: argparse.Namespace) -> int:
    print("=" * 60)
    print(f"STARTING {args.mode.upper()} FUZZING CAMPAIGN (replicate {args.replicate})")
    print("=" * 60)

    if args.demo_subset:
        args.rounds = 1
        args.candidates_per_round = 5
        args.base_checkpoint = "ci/corpus/torch/benign/benign.pt"

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
        fitness_mode=args.fitness_mode,
    )

    # Family-quota: prevent single-family collapse (P1.1, config-driven).
    # Supports yaml via --family-quota-* and FeedbackController stratified sampling.
    # Try yaml, else CLI defaults.
    _cfg_min_pct = args.family_quota_min_pct
    _cfg_max_frac = args.family_quota_max_frac
    try:
        import yaml as _yaml
        with open("config/campaign_config.yaml") as _yf:
            _cfg = _yaml.safe_load(_yf) or {}
            _cc = _cfg.get("campaign", {})
            # yaml overrides CLI if set
            _cfg_min_pct = float(_cc.get("family_quota_min_pct", _cfg_min_pct))
            _cfg_max_frac = float(_cc.get("family_quota_max_frac", _cfg_max_frac))
            _cfg_entropy = float(_cc.get("entropy_target", args.entropy_target))
        args.entropy_target = _cfg_entropy
    except Exception:
        pass
    # Per-round quotas derived from pct/frac
    if args.family_quota_min_pct == 0:
        family_quota_min = 0
    else:
        family_quota_min = max(1, int(_cfg_min_pct * args.candidates_per_round)) if args.candidates_per_round >= len(families) else 0
    family_quota_max = max(1, int(_cfg_max_frac * args.candidates_per_round) + 1)
    # Keep legacy _quota_pick for unguided / fallback; guided will use controller.sample_family_with_quota
    def _quota_pick(desired: str, counts: dict[str, int]) -> str:
        if counts.get(desired, 0) >= family_quota_max:
            under = sorted(families, key=lambda f: counts.get(f, 0))
            for cand in under:
                if counts.get(cand, 0) < family_quota_max:
                    return cand
        remaining = args.candidates_per_round - sum(counts.values()) - 1
        missing = [f for f in families if counts.get(f, 0) < family_quota_min]
        if missing and remaining < len(missing):
            return random.choice(missing)
        return desired
    # Also init controller with quotas for stratified sampling
    # (will be used in per-round loop via controller.sample_family_with_quota)

    # Candidates are persisted per-run so the DB filepaths never dangle and
    # export_bypasses can copy real artifacts. Only the trigger files (used by
    # the validity oracle, which mounts the system temp dir) are ephemeral.
    candidates_root = os.path.join("data", "candidates", run_id)
    # The trigger path is baked into the candidate payload, so a deterministic
    # dir keeps candidate bytes a pure function of (seed, round, index) across
    # runs of the same command. Fall back to mkdtemp when unseeded.
    if args.seed is not None:
        temp_dir = os.path.join(
            tempfile.gettempdir(), f"regenbench_seed{args.seed}_triggers")
        os.makedirs(temp_dir, exist_ok=True)
    else:
        temp_dir = tempfile.mkdtemp(prefix=f"regenbench_{run_id}_triggers_")
    started_at = time.time()
    time_limit = args.time_budget_hours * 3600.0
    try:
        generator = CandidateGenerator()
        oracle_val = ValidityOracle(container_backend=args.backend,
                                    timeout=args.validity_timeout)
        plausibility = PlausibilityOracle(oracle_val)
        tracker = CoverageTracker(db_path, run_id=run_id)
        controller = FeedbackController(
            family_quota_min_pct=_cfg_min_pct,
            family_quota_max_frac=_cfg_max_frac,
            entropy_target=args.entropy_target,
        )
        novelty = NoveltyTracker()

        # Fixed strategy subset (--evasion-strategies) wins over mode logic.
        fixed_strategies: list[str] | None = None
        if args.evasion_strategies:
            from pipeline.evasion import STRATEGIES as _S
            requested = [s.strip() for s in args.evasion_strategies.split(",") if s.strip()]
            unknown = [s for s in requested if s not in _S]
            if unknown:
                print(f"[campaign] error: unknown evasion strategies {unknown} "
                      f"(valid: {sorted(_S)})")
                return 1
            fixed_strategies = requested

        from pipeline.evasion import select_strategies as _select_evasion_strategies

        # Parse fitness mode
        fitness_mode = FitnessMode(args.fitness_mode)

        def _pick_strategies() -> list[str]:
            if fixed_strategies is not None:
                return list(fixed_strategies)
            if args.evasion_mode == "off":
                return []
            import random as _r
            if args.evasion_mode == "adaptive" and args.mode == "guided":
                # Single-strategy sets only: stacked strategies empirically
                # kill evasion (see fitness ablation -- every >1-strategy
                # combo yields 0 bypasses). No upward bias.
                return _select_evasion_strategies(random, k=1)
            return _select_evasion_strategies(random)

        round_summaries = []
        budget_exhausted = False
        
        # Phase 5: Parallel candidate generation
        gen_workers = args.gen_workers or min(8, os.cpu_count() or 4)
        print(f"[campaign] using {gen_workers} parallel workers for candidate generation")
        
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

            # Pre-select all candidate parameters for this round
            candidate_params = []
            family_counts = {f: 0 for f in families}
            for i in range(args.candidates_per_round):
                elapsed = time.time() - started_at
                if elapsed >= time_limit:
                    print(f"\n[budget] time limit reached after {elapsed / 3600:.2f}h; "
                          f"ending campaign early.")
                    budget_exhausted = True
                    break

                if args.mode == "guided":
                    # Use combo weights with semantic novelty bias for synthesis exploration
                    combo = controller.sample_with_novelty(
                        random, set(families), novelty,
                        fixed_strategies=frozenset(fixed_strategies) if fixed_strategies else None,
                        fixed_transport="splice" if (args.evasion_mode != "off" or fixed_strategies is not None) else None
                    )
                    if combo:
                        attack_family, cand_transport, cand_strategies_fs = combo
                        cand_strategies = list(cand_strategies_fs)
                        # Enforce quota even on combo hit
                        attack_family = _quota_pick(attack_family, family_counts)
                    else:
                        # Fallback: quota-aware stratified sampling (P1.1)
                        attack_family = controller.sample_family_with_quota(random, set(families), family_counts, args.candidates_per_round)
                        cand_strategies = _pick_strategies()
                        cand_transport = "splice" if (args.evasion_mode != "off" or fixed_strategies is not None) else None

                    # Coverage-gap sampling: occasionally pick unseen callable/opcode
                    gap_chosen_callable = None
                    if random.random() < 0.1:
                        gap = controller.sample_coverage_gaps(random, tracker, set(families))
                        if gap:
                            gap_family, gap_item = gap
                            gap_family = _quota_pick(gap_family, family_counts)
                            attack_family = gap_family
                            if isinstance(gap_item, tuple) and gap_item[0] == "opcode":
                                pass  # opcode gap handled via op_swap_prob increase
                            elif attack_family == "gadget":
                                gap_chosen_callable = gap_item

                    if attack_family == "gadget":
                        if gap_chosen_callable is not None:
                            chosen_callable = gap_chosen_callable
                        else:
                            callable_weights_map = controller.get_callable_weights()
                            callable_weights_map = {c: w for c, w in callable_weights_map.items() if c in population}
                            callable_population = list(callable_weights_map.keys())
                            callable_weights = list(callable_weights_map.values())
                            chosen_callable = random.choices(callable_population, weights=callable_weights, k=1)[0]
                    else:
                        chosen_callable = None

                    family_counts[attack_family] += 1

                    op_swap_prob = controller.op_swap_prob
                    callable_sub_prob = controller.callable_sub_prob
                    arg_fuzz_prob = controller.arg_fuzz_prob
                else:
                    attack_family = random.choice(families)
                    attack_family = _quota_pick(attack_family, family_counts)
                    family_counts[attack_family] += 1
                    if attack_family == "gadget":
                        chosen_callable = random.choice(population)
                    else:
                        chosen_callable = None
                    cand_strategies = _pick_strategies()
                    cand_transport = "splice" if (args.evasion_mode != "off" or fixed_strategies is not None) else None
                    op_swap_prob = 0.15
                    callable_sub_prob = 0.15
                    arg_fuzz_prob = 0.15

                trigger_file = os.path.join(temp_dir, f"trigger_{r}_{i}.txt")
                payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"

                candidate_params.append({
                    "index": i,
                    "trigger_file": trigger_file,
                    "payload": payload,
                    "chosen_callable": chosen_callable,
                    "attack_family": attack_family,
                    "cand_strategies": cand_strategies,
                    "cand_transport": cand_transport,
                    "op_swap_prob": op_swap_prob,
                    "callable_sub_prob": callable_sub_prob,
                    "arg_fuzz_prob": arg_fuzz_prob,
                    "rng_seed": _candidate_rng_seed(args.seed, r, i),
                })

            # Phase 5: Parallel generation with ProcessPoolExecutor
            candidates = []
            with concurrent.futures.ProcessPoolExecutor(max_workers=gen_workers) as executor:
                futures = {}
                for params in candidate_params:
                    fut = executor.submit(
                        _generate_candidate_worker,
                        benign_pt_bytes,
                        params["payload"],
                        params["chosen_callable"],
                        params["attack_family"],
                        params["cand_strategies"],
                        params["cand_transport"],
                        True,  # mutate_meta
                        0.15,  # mutation_prob
                        params["op_swap_prob"],
                        params["callable_sub_prob"],
                        params["arg_fuzz_prob"],
                        0.05,  # stack_prob
                        args.differential_prob,   # Phase 3a
                        args.family_synthesis_prob,  # Phase 3b
                        params.get("rng_seed"),   # deterministic reseed
                    )
                    futures[fut] = params

                for fut in concurrent.futures.as_completed(futures):
                    params = futures[fut]
                    i = params["index"]
                    try:
                        cand_bytes = fut.result()
                    except ValueError as e:
                        # Unsupported callable - resample
                        print(f"  [skip] {params['chosen_callable']}: {e}")
                        supported = [c for c in population if c != params["chosen_callable"]] or population
                        new_callable = random.choice(supported)
                        params["chosen_callable"] = new_callable
                        # Retry once (distinct seed so the resample mutates
                        # differently than the failed attempt)
                        retry_seed = params.get("rng_seed")
                        if retry_seed is not None:
                            retry_seed = (retry_seed + 0x9E3779B9) % (2**32)
                        fut2 = executor.submit(
                            _generate_candidate_worker,
                            benign_pt_bytes,
                            params["payload"],
                            new_callable,
                            params["attack_family"],
                            params["cand_strategies"],
                            params["cand_transport"],
                            True, 0.15,
                            params["op_swap_prob"],
                            params["callable_sub_prob"],
                            params["arg_fuzz_prob"],
                            0.05,
                            args.differential_prob,
                            args.family_synthesis_prob,
                            retry_seed,
                        )
                        try:
                            cand_bytes = fut2.result()
                        except ValueError as e:
                            # The resample also failed (e.g. plausibility
                            # constraints reject the new callable too); drop
                            # this candidate slot instead of aborting the
                            # campaign. A sibling except clause cannot catch
                            # an exception raised inside this handler, so this
                            # must be a nested try.
                            print(f"  [skip] {params['chosen_callable']} retry failed: {e}")
                            continue

                    cand_path = os.path.join(round_dir, f"candidate_{i}.pt")
                    with open(cand_path, "wb") as f:
                        f.write(cand_bytes)
                    candidates.append((cand_path, cand_bytes, params["chosen_callable"],
                                       params["trigger_file"], params["attack_family"], params["cand_strategies"]))

            print(f"Generated {len(candidates)} candidate checkpoints "
                  f"(families: {family_counts}).")
            if not candidates:
                break

            config = Config(
                backend=args.backend, tag=args.tag,
                max_workers=args.workers, timeout=args.timeout,
                oracle=True, pre_filter=args.pre_filter,
                oracle_model_dir=args.oracle_model_dir,
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
            evasion_hits: dict[str, int] = {}

            # Track coverage for delta calculation
            prev_opcodes = set(tracker.seen_opcodes)
            prev_callables = set(tracker.seen_callables)

            for filepath, cand_bytes, chosen_callable, trigger_file, attack_family, cand_strategies in candidates:
                cand_results = results_by_file.get(filepath, [])
                is_valid = plausibility.confirm(cand_bytes, trigger_file)
                cand_id = hashlib.md5(filepath.encode("utf-8")).hexdigest()

                panel_verdicts = []
                scanner_verdicts: dict[str, str] = {}
                matched_rules: list[str] = []
                dynahug_verdict = "benign"
                decision_score = 0.0
                for r_scan in cand_results:
                    if r_scan.scanner == "dynahug":
                        # DynaHug provides supplementary decision_score signal only.
                        # Execution oracle (plausibility/validity) is the primary for bypass confirmation.
                        dynahug_verdict = r_scan.verdict or "error"
                        decision_score = r_scan.decision_score or 0.0
                    else:
                        # Fail-closed: a scanner that errors (parse failure, scan
                        # timeout) is recorded as "error", never as "benign", so
                        # an errored scanner cannot count as "evaded".
                        v = r_scan.verdict or "error"
                        scanner_verdicts[r_scan.scanner] = v
                        panel_verdicts.append(v)
                        if r_scan.matched_rules:
                            matched_rules.extend(r_scan.matched_rules)

                # Execution oracle verdict for bypass confirmation: "malicious" = trigger fired
                execution_oracle_verdict = "malicious" if is_valid else "benign"

                # Compute coverage delta for fitness modes that use it
                # Track with family signal so family coverage is meaningful.
                is_bypass = is_valid and check_bypass(panel_verdicts, execution_oracle_verdict)
                tracker.track_candidate(filepath, family=attack_family, is_bypass=is_bypass)
                new_opcodes = tracker.seen_opcodes - prev_opcodes
                new_callables = tracker.seen_callables - prev_callables
                coverage_delta = len(new_opcodes) + len(new_callables)
                prev_opcodes = set(tracker.seen_opcodes)
                prev_callables = set(tracker.seen_callables)

                use_multi_fitness = (
                    is_valid
                    and (args.evasion_mode != "off" or fixed_strategies is not None)
                )
                if fitness_mode == FitnessMode.ORACLE_DOMINANT:
                    # Lexicographic fitness: dynamic confirmation > panel > coverage > novelty
                    sig_ops = _candidate_signature(filepath)
                    nov = novelty.score(novelty.signature(
                        sig_ops, frozenset(cand_strategies)))
                    fit_score = compute_fitness_lexicographic(
                        scanner_verdicts=scanner_verdicts,
                        oracle_verdict=execution_oracle_verdict,
                        is_valid=is_valid,
                        novelty_score=nov if args.mode == "guided" else 0.0,
                        coverage_delta=coverage_delta,
                    )
                elif fitness_mode == FitnessMode.ORACLE_AWARE:
                    # Oracle-aware: panel evasion + execution oracle multiplier + boundary + novelty
                    if use_multi_fitness:
                        sig_ops = _candidate_signature(filepath)
                        nov = novelty.score(novelty.signature(
                            sig_ops, frozenset(cand_strategies)))
                        fit_score = compute_fitness_oracle_aware(
                            scanner_verdicts=scanner_verdicts,
                            oracle_verdict=execution_oracle_verdict,
                            is_valid=is_valid,
                            decision_score=decision_score,
                            novelty_score=nov if args.mode == "guided" else 0.0,
                        )
                    elif is_valid:
                        fit_score = compute_fitness_oracle_aware(
                            scanner_verdicts=scanner_verdicts,
                            oracle_verdict=execution_oracle_verdict,
                            is_valid=is_valid,
                            decision_score=decision_score,
                            novelty_score=0.0,
                        )
                    else:
                        fit_score = 0.0
                elif fitness_mode == FitnessMode.CONTINUOUS:
                    # Continuous: smooth multi-objective (evasion * oracle_mult + boundary + novelty + coverage)
                    if use_multi_fitness:
                        sig_ops = _candidate_signature(filepath)
                        nov = novelty.score(novelty.signature(
                            sig_ops, frozenset(cand_strategies)))
                        fit_score = compute_fitness_continuous(
                            scanner_verdicts=scanner_verdicts,
                            execution_oracle_verdict=execution_oracle_verdict,
                            is_valid=is_valid,
                            decision_score=decision_score,
                            novelty_score=nov if args.mode == "guided" else 0.0,
                            coverage_delta=coverage_delta,
                        )
                    elif is_valid:
                        fit_score = compute_fitness_continuous(
                            scanner_verdicts=scanner_verdicts,
                            execution_oracle_verdict=execution_oracle_verdict,
                            is_valid=is_valid,
                            decision_score=decision_score,
                            novelty_score=0.0,
                            coverage_delta=coverage_delta,
                        )
                    else:
                        fit_score = 0.0
                elif fitness_mode == FitnessMode.COVERAGE_GUIDED:
                    # Coverage-guided: coverage delta as primary when evasion plateaus
                    if use_multi_fitness:
                        sig_ops = _candidate_signature(filepath)
                        nov = novelty.score(novelty.signature(
                            sig_ops, frozenset(cand_strategies)))
                        fit_score = compute_fitness_coverage_guided(
                            scanner_verdicts=scanner_verdicts,
                            execution_oracle_verdict=execution_oracle_verdict,
                            is_valid=is_valid,
                            decision_score=decision_score,
                            novelty_score=nov if args.mode == "guided" else 0.0,
                            coverage_delta=coverage_delta,
                        )
                    elif is_valid:
                        fit_score = compute_fitness_coverage_guided(
                            scanner_verdicts=scanner_verdicts,
                            execution_oracle_verdict=execution_oracle_verdict,
                            is_valid=is_valid,
                            decision_score=decision_score,
                            novelty_score=0.0,
                            coverage_delta=coverage_delta,
                        )
                    else:
                        fit_score = 0.0
                else:
                    # CURRENT: original behavior
                    if use_multi_fitness:
                        sig_ops = _candidate_signature(filepath)
                        nov = novelty.score(novelty.signature(
                            sig_ops, frozenset(cand_strategies)))
                        fit_score = compute_fitness_multi(
                            scanner_verdicts=scanner_verdicts,
                            decision_score=decision_score,
                            novelty_score=nov if args.mode == "guided" else 0.0,
                        )
                    elif is_valid:
                        fit_score = compute_fitness(
                            detected_count=sum(1 for v in panel_verdicts if v == "malicious"),
                            total_scanners=len(panel_verdicts),
                            decision_score=decision_score,
                        )
                    else:
                        fit_score = 0.0

                if is_valid:
                    valid_cnt += 1

                is_bypass = is_valid and check_bypass(panel_verdicts, execution_oracle_verdict)
                if is_bypass:
                    bypasses_cnt += 1
                    # Register confirmed bypass for shelf-life tracking (H3)
                    try:
                        # Get scanner versions from the runner's images
                        scanner_versions = {}
                        for name in runner.spec:
                            scanner_versions[name] = runner.images[name]

                        register_confirmed_bypass(
                            candidate_id=cand_id,
                            run_id=run_id,
                            family=attack_family,
                            callable=(
                                f"{chosen_callable[0]}::{chosen_callable[1]}"
                                if chosen_callable else f"family::{attack_family}"
                            ),
                            transport=cand_transport or "loads",
                            strategies=cand_strategies,
                            artifact_path=filepath,
                            scanner_versions=scanner_versions,
                            panel_verdicts=scanner_verdicts,
                            oracle_verdict=execution_oracle_verdict,
                            dynahug_verdict=dynahug_verdict,
                            decision_score=decision_score,
                        )
                    except Exception as e:
                        print(f"[shelf-life] Failed to register bypass: {e}")

                evaded_scanners = [s for s, v in scanner_verdicts.items()
                                   if v == "benign"]
                for s in evaded_scanners:
                    evasion_hits[s] = evasion_hits.get(s, 0) + 1

                # Compute panel verdict summary
                if all(v == "benign" for v in panel_verdicts) and panel_verdicts:
                    panel_verdict_summary = "all_benign"
                elif any(v == "malicious" for v in panel_verdicts):
                    panel_verdict_summary = "any_malicious"
                elif any(v == "error" for v in panel_verdicts):
                    panel_verdict_summary = "error"
                else:
                    panel_verdict_summary = "none"

                # Compute novelty score (already computed above for fitness)
                sig_ops = _candidate_signature(filepath)
                nov_score = novelty.score(novelty.signature(
                    sig_ops, frozenset(cand_strategies)))

                # P2.3 consensus tier: strace proxy = execution verdict for now
                # (when StraceOracle is wired, replace strace_verdict with its verdict)
                try:
                    strace_verdict = "malicious" if is_valid else "benign"
                    consensus_tier = check_bypass_tier(panel_verdicts, strace_verdict, dynahug_verdict)
                except Exception:
                    consensus_tier = None

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
                    mutation_strategy=",".join(cand_strategies) if cand_strategies else "none",
                    parent_id=None,  # No parent tracking in current implementation
                    generation=1,     # No generational tracking in current implementation
                    oracle_verdict=execution_oracle_verdict,
                    panel_verdict=panel_verdict_summary,
                    coverage_delta=coverage_delta,
                    novelty_score=nov_score,
                    consensus_tier=consensus_tier,
                )
                log_fitness(db_path, cand_id, fit_score, is_valid,
                            transport=cand_transport or "loads",
                            strategies=",".join(cand_strategies) if cand_strategies else None,
                            consensus_tier=consensus_tier)

                round_results.append({
                    "callable": chosen_callable,
                    "family": attack_family,
                    "fitness": fit_score,
                    "evaded_all": all(v == "benign" for v in panel_verdicts),
                    "valid": is_valid,
                    "transport": cand_transport or "loads",
                    "strategies": list(cand_strategies or []),
                    # Phase-2 grey-box keys (FeedbackController ingests them).
                    "scanner_verdicts": scanner_verdicts,
                    "matched_rules": matched_rules,
                })

            # P1.4: log with family coverage + entropy (instruments post-mutation stream)
            opcode_cov, callable_cov = tracker.log_round(r, family_counts)
            if args.mode == "guided":
                controller.update(round_results)

            mean_fitness = sum(x["fitness"] for x in round_results) / len(round_results)
            fam_explored, fam_bypass = tracker.family_coverage()
            entropy = CoverageTracker.family_entropy(family_counts)
            round_summaries.append({
                "round": r,
                "generated_count": len(candidates),
                "valid_count": valid_cnt,
                "bypass_count": bypasses_cnt,
                "mean_fitness": mean_fitness,
                "opcode_cov": opcode_cov,
                "callable_cov": callable_cov,
                "fam_explored": fam_explored,
                "fam_bypass": fam_bypass,
                "entropy": entropy,
                "families": family_counts,
                "evasion_hits": dict(evasion_hits),
            })

            print(f"Round {r} Complete: Valid={valid_cnt}/{len(candidates)}, "
                  f"Bypasses={bypasses_cnt}, Mean Fitness={mean_fitness:.3f}, "
                  f"Opcode Cov={opcode_cov * 100:.1f}% (reachable), Callable Cov={callable_cov * 100:.1f}%, "
                  f"Family={fam_explored*100:.0f}%/{fam_bypass*100:.0f}% ent={entropy:.2f}, "
                  f"Per-scanner evasions={evasion_hits or '{}'}")

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
            "| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |",
            "| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for s in round_summaries:
            report_lines.append(
                f"| {s['round']} | {s['valid_count']} / {s['generated_count']} | "
                f"{s['bypass_count']} | {s['mean_fitness']:.3f} | "
                f"{s['opcode_cov'] * 100:.1f}% | {s['callable_cov'] * 100:.1f}% | "
                f"{s.get('fam_bypass',0)*100:.0f}% | {s.get('entropy',0):.2f} |"
            )
        report_lines += [
            "",
            "## Attack-family distribution",
            "",
            "| Family | Candidates |",
            "| :--- | :---: |",
        ]
        report_lines += [f"| {f} | {family_totals[f]} |" for f in families]

        if args.evasion_mode != "off" or fixed_strategies is not None:
            totals: dict[str, int] = {}
            for s in round_summaries:
                for scanner, n in s.get("evasion_hits", {}).items():
                    totals[scanner] = totals.get(scanner, 0) + n
            report_lines += [
                "",
                "## Per-scanner evasions (verdict=benign on valid candidates)",
                "",
                f"Evasion mode: **{args.evasion_mode}**"
                + (f", fixed strategies: {fixed_strategies}" if fixed_strategies else ""),
                "",
                "| Scanner | Evasions |",
                "| :--- | :---: |",
            ]
            report_lines += [f"| {s} | {n} |" for s, n in sorted(totals.items())] or \
                ["| (none) | 0 |"]
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


def _candidate_signature(filepath: str):
    """Parse the embedded pickle of a candidate for novelty signatures."""
    import zipfile
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
        if magic.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(filepath) as z:
                name = [n for n in z.namelist() if n.endswith("data.pkl")][0]
                pkl = z.read(name)
        else:
            with open(filepath, "rb") as f:
                pkl = f.read()
        return parse_pickle(pkl)
    except Exception:
        return []


if __name__ == "__main__":
    sys.exit(run_campaign(parse_args()))
