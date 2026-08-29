#!/usr/bin/env python3
"""ShadowPickle Baseline Replication (H1 validation).

Generates the 3 handcrafted ShadowPickle families and runs them through
the full scanner panel + execution oracle to establish baseline evasion rates.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.generator import CandidateGenerator
from pipeline.runner import Runner, Config
from pipeline.validity import ValidityOracle
from pipeline.plausibility import PlausibilityOracle
from pipeline.templates import FAMILY_TEMPLATES, FAMILY_LABELS
from pipeline.comparator import check_bypass
from pipeline.db import init_db, log_candidate, log_fitness, log_campaign_run, complete_campaign_run


SHADOWPICKLE_FAMILIES = ("overwritten", "external", "indirect_chain")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run ShadowPickle baseline replication.")
    ap.add_argument("--base-checkpoint", default="ci/corpus/torch/benign/benign.pt",
                    help="benign torch checkpoint used as the mutation base")
    ap.add_argument("--db", default="data/regenbench_shadowpickle.db")
    ap.add_argument("--backend", choices=["podman", "docker"], default="docker")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--candidates-per-family", type=int, default=20,
                    help="number of candidates to generate per family")
    ap.add_argument("--panel-scanners", nargs="+", default=None,
                    help="override panel scanner list")
    args = ap.parse_args(argv)

    print("=" * 60)
    print("SHADOWPICKLE BASELINE REPLICATION (H1)")
    print("=" * 60)

    base_abs = os.path.abspath(args.base_checkpoint)
    if not os.path.isfile(base_abs):
        print(f"[error] base checkpoint not found: {base_abs}")
        return 1

    with open(base_abs, "rb") as f:
        benign_pt_bytes = f.read()

    db_path = args.db
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    init_db(db_path)

    run_id = f"shadowpickle-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    total_candidates = len(SHADOWPICKLE_FAMILIES) * args.candidates_per_family
    log_campaign_run(db_path, run_id, "shadowpickle_baseline", 1,
                     base_abs, total_candidates, 1)

    generator = CandidateGenerator()
    oracle_val = ValidityOracle(container_backend=args.backend, timeout=20)
    plausibility = PlausibilityOracle(oracle_val)

    panel = args.panel_scanners or ["picklescan", "fickling", "modelscan"]
    config = Config(
        backend=args.backend, tag=args.tag,
        max_workers=4, timeout=args.timeout,
        oracle=True, pre_filter=True,
    )

    candidates_root = os.path.join("data", "candidates", run_id)
    temp_dir = tempfile.mkdtemp(prefix=f"shadowpickle_{run_id}_triggers_")

    try:
        all_candidates = []
        for family in SHADOWPICKLE_FAMILIES:
            print(f"\n--- Generating {args.candidates_per_family} candidates for {family} ---")
            family_dir = os.path.join(candidates_root, family)
            os.makedirs(family_dir, exist_ok=True)

            for i in range(args.candidates_per_family):
                trigger_file = os.path.join(temp_dir, f"trigger_{family}_{i}.txt")
                payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"

                try:
                    cand_bytes = generator.generate_candidate_pt(
                        benign_pt_bytes=benign_pt_bytes,
                        payload_code=payload,
                        dangerous_callable=None,
                        attack_family=family,
                        mutate_meta=False,  # Template families don't use meta mutation
                    )
                except ValueError as e:
                    print(f"  [skip] {family}: {e}")
                    continue

                cand_path = os.path.join(family_dir, f"candidate_{i}.pt")
                with open(cand_path, "wb") as f:
                    f.write(cand_bytes)

                all_candidates.append((cand_path, cand_bytes, trigger_file, family))

        print(f"\nGenerated {len(all_candidates)} total candidates.")

        # Run scanners
        runner = Runner(config, scanners=panel + ["dynahug"])
        cand_paths = [c[0] for c in all_candidates]
        results = runner.run(cand_paths, db_path=db_path)

        results_by_file = {}
        for res in results:
            results_by_file.setdefault(res.artifact, []).append(res)

        # Evaluate
        bypasses = 0
        valid_count = 0
        family_stats = {f: {"valid": 0, "bypasses": 0, "evaded": 0} for f in SHADOWPICKLE_FAMILIES}

        for filepath, cand_bytes, trigger_file, family in all_candidates:
            cand_results = results_by_file.get(filepath, [])
            is_valid = plausibility.confirm(cand_bytes, trigger_file)
            cand_id = hashlib.md5(filepath.encode("utf-8")).hexdigest()

            panel_verdicts = []
            scanner_verdicts = {}
            dynahug_verdict = "benign"
            decision_score = 0.0

            for r_scan in cand_results:
                if r_scan.scanner == "dynahug":
                    dynahug_verdict = r_scan.verdict or "error"
                    decision_score = r_scan.decision_score or 0.0
                else:
                    v = r_scan.verdict or "error"
                    scanner_verdicts[r_scan.scanner] = v
                    panel_verdicts.append(v)

            execution_oracle_verdict = "malicious" if is_valid else "benign"

            if is_valid:
                valid_count += 1
                family_stats[family]["valid"] += 1
                fit_score = 1.0  # placeholder
            else:
                fit_score = 0.0

            is_bypass = is_valid and check_bypass(panel_verdicts, execution_oracle_verdict)
            if is_bypass:
                bypasses += 1
                family_stats[family]["bypasses"] += 1

            evaded = all(v == "benign" for v in panel_verdicts) and panel_verdicts
            if evaded:
                family_stats[family]["evaded"] += 1

            log_candidate(
                db_path, cand_id, filepath, "shadowpickle_baseline",
                round_num=1, seed_model=base_abs,
                mutation_template=FAMILY_LABELS[family],
                campaign_type="shadowpickle_baseline", run_id=run_id,
            )
            log_fitness(db_path, cand_id, fit_score, is_valid,
                        transport="loads", strategies="none")

        # Report
        print("\n" + "=" * 60)
        print("SHADOWPICKLE BASELINE RESULTS")
        print("=" * 60)
        print(f"Total candidates: {len(all_candidates)}")
        print(f"Valid candidates: {valid_count}")
        print(f"Confirmed bypasses: {bypasses}")
        print(f"Bypass rate: {bypasses / max(1, valid_count) * 100:.1f}%")
        print()
        print("Per-family breakdown:")
        for family in SHADOWPICKLE_FAMILIES:
            s = family_stats[family]
            print(f"  {family}: valid={s['valid']}, evaded={s['evaded']}, "
                  f"bypasses={s['bypasses']}, "
                  f"bypass_rate={s['bypasses'] / max(1, s['valid']) * 100:.1f}%")

        complete_campaign_run(db_path, run_id)
        print(f"\nResults stored in {db_path}")
        return 0

    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())