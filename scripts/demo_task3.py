#!/usr/bin/env python3
"""Task 3 unified demo: the full ReGenBench pipeline on a small subset.

Walks the complete attack -> scan -> execute -> defend flow end-to-end on a
manageable subset (committed `ci/corpus` seeds + one candidate per family),
so an examiner can see the system in ~5 minutes rather than reading reports.

Demonstrated, per artifact:
  1.  Generate one malicious candidate per attack family (pickle + torch).
  2.  Scan the candidate with the static scanner panel (live containers).
  3.  Confirm execution with the ExecutionOracle (ValidityOracle trigger poll).
  4.  Run the ModelDefense prototype (safe quarantine / reserialization).
  5.  GGUF attack surface (reuses run_task3_demo helpers).
  6.  Compare against the ShadowPickle baseline.

Writes `docs/demo-report.md` and `demo-artifacts/demo-report.json`.

Usage:
    python3 scripts/demo_task3.py [--backend docker] [--subset ci/corpus]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.defense import ModelDefense, DefenseVerdict  # noqa: E402
from pipeline.monitor import LoadTimeMonitor  # noqa: E402
from pipeline.repair import ModelRepair  # noqa: E402
from pipeline.gguf_tools import GGUF_ATTACKS, GGUF_ATTACK_LABELS, generate_candidate_gguf, benign_gguf  # noqa: E402
from pipeline.generator import CandidateGenerator  # noqa: E402
from pipeline.runner import Runner, Config  # noqa: E402
from pipeline.scanners import SCANNERS, build_images, run_scan  # noqa: E402
from pipeline.templates import FAMILY_LABELS  # noqa: E402
from pipeline.validity import ValidityOracle  # noqa: E402
from pipeline.plausibility import PlausibilityOracle  # noqa: E402
from pipeline.comparator import check_bypass  # noqa: E402

ATTACK_FAMILIES = ("gadget", "overwritten", "external", "indirect_chain", "pypi_injected")
PANEL = ["picklescan", "modelscan", "fickling"]


def load_seed(subset: str) -> bytes:
    """Load the benign torch seed from the committed corpus."""
    seed_path = os.path.join(subset, "torch", "benign", "benign.pt")
    if not os.path.isfile(seed_path):
        raise FileNotFoundError(f"seed not found: {seed_path}. "
                                f"Generate it with ci/smoke.sh or point --subset elsewhere.")
    with open(seed_path, "rb") as f:
        return f.read()


def generate_candidates(seed: bytes, out_dir: str, backend: str) -> list[dict]:
    """Generate one candidate per attack family; returns [{family, path, bytes, trigger}]."""
    generator = CandidateGenerator()
    tmp = tempfile.mkdtemp(prefix="demo-triggers-")
    manifest = []
    for family in ATTACK_FAMILIES:
        trigger = os.path.join(tmp, f"trig_{family}.txt")
        payload = f"with open({trigger!r}, 'w') as f: f.write('1')"
        try:
            cand = generator.generate_candidate_pt(
                benign_pt_bytes=seed,
                payload_code=payload,
                dangerous_callable=None,
                attack_family=family,
                mutate_meta=False,
                injection_transport="splice",
            )
        except ValueError as e:
            print(f"  [skip] {family}: {e}")
            continue
        path = os.path.join(out_dir, f"{FAMILY_LABELS[family]}.pt")
        with open(path, "wb") as f:
            f.write(cand)
        manifest.append({"family": family, "path": path, "bytes": cand, "trigger": trigger})
    return manifest


def scan_candidates(candidates: list[dict], backend: str, tag: str, timeout: int) -> dict[str, dict]:
    """Run the scanner panel over candidate paths; returns {path: {scanner: verdict}}."""
    config = Config(backend=backend, tag=tag, max_workers=4, timeout=timeout,
                    oracle=True, pre_filter=True)
    runner = Runner(config, scanners=PANEL + ["dynahug"])
    paths = [c["path"] for c in candidates]
    results = runner.run(paths, db_path=None)
    by_file: dict[str, dict] = {}
    for r in results:
        by_file.setdefault(r.artifact, {})[r.scanner] = r.verdict or "error"
    return by_file


def confirm_execution(candidates: list[dict], backend: str) -> dict[str, bool]:
    """Run the ExecutionOracle on each candidate; returns {path: executed}."""
    oracle = ValidityOracle(container_backend=backend, timeout=30)
    plaus = PlausibilityOracle(oracle)
    out = {}
    for c in candidates:
        out[c["path"]] = plaus.confirm(c["bytes"], c["trigger"])
    return out


def defend_candidates(candidates: list[dict], backend: str, out_dir: str) -> dict[str, dict]:
    """Run the ModelDefense prototype; returns {path: {verdict, reason, ...}}."""
    defense = ModelDefense(backend=backend, timeout=120, panel_scanners=PANEL)
    results = defense.batch_inspect([c["path"] for c in candidates], out_dir)
    return {r.artifact_path: r.to_dict() for r in results}


def monitor_candidates(candidates: list[dict], backend: str) -> dict[str, dict]:
    monitor = LoadTimeMonitor(backend=backend)
    return {c["path"]: monitor.monitor_load(c["path"], timeout=30) for c in candidates}


def build_gguf_corpus(out_dir: str) -> tuple[list[tuple[str, str]], str]:
    """Build small malicious + benign GGUF set; returns ([(family, path)], benign_path)."""
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    for family in GGUF_ATTACKS:
        trigger = f"/tmp/trig_demo_{family}.txt" if family == "ssti_chat_template" else None
        data = generate_candidate_gguf(family, trigger)
        label = GGUF_ATTACK_LABELS[family]
        path = os.path.join(out_dir, f"{label}.gguf")
        with open(path, "wb") as f:
            f.write(data)
        manifest.append((family, path))
    benign_path = os.path.join(out_dir, "benign-synth.gguf")
    with open(benign_path, "wb") as f:
        f.write(benign_gguf())
    return manifest, benign_path


def scan_gguf(backend: str, images: dict[str, str], targets: list[str]) -> list[dict]:
    """Run the ggufref oracle + modelscan over GGUF targets.

    Mirrors pipeline.scanners.run_scan's timeout handling: docker has no
    `--timeout` flag (podman-only), so only pass it for podman.
    """
    import subprocess
    rows = []
    for path in targets:
        for scanner in ("ggufref", "modelscan"):
            cmd = [backend, "run", "--rm"]
            if backend == "podman":
                cmd += ["--timeout", "90"]
            cmd += ["-v", f"{os.path.abspath(path)}:/artifact:ro,z", "-v", "/tmp:/tmp",
                    images[scanner], "/artifact"]
            if scanner == "ggufref":
                cmd.insert(2, "--security-opt")
                cmd.insert(3, "label=disable")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                out = json.loads((proc.stdout or "").strip().splitlines()[-1])
                verdict = out.get("verdict") or "error"
            except Exception:
                verdict = "error"
            rows.append({"artifact": os.path.basename(path), "scanner": scanner, "verdict": verdict})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the unified Task-3 demo.")
    ap.add_argument("--backend", default="docker")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--subset", default="ci/corpus", help="seed corpus dir (committed)")
    ap.add_argument("--out", default="demo-artifacts", help="artifact/report output dir")
    args = ap.parse_args(argv)

    print("=" * 70)
    print("TASK 3 UNIFIED DEMO -- ReGenBench full pipeline on a small subset")
    print("=" * 70)

    os.makedirs(args.out, exist_ok=True)
    report: dict = {"backend": args.backend, "attack_families": list(ATTACK_FAMILIES)}

    # --- 1. Generate candidates -------------------------------------------
    seed = load_seed(args.subset)
    print(f"\n[1] Loaded benign torch seed ({len(seed)} bytes)")
    cand_dir = os.path.join(args.out, "candidates")
    os.makedirs(cand_dir, exist_ok=True)
    candidates = generate_candidates(seed, cand_dir, args.backend)
    report["candidates"] = [{"family": c["family"], "path": c["path"]} for c in candidates]
    print(f"    Generated {len(candidates)} malicious candidates "
          f"({', '.join(c['family'] for c in candidates)})")

    # --- 2. Static scan ---------------------------------------------------
    print("\n[2] Running static scanner panel...")
    scan_results = scan_candidates(candidates, args.backend, args.tag, args.timeout)
    for path, verdicts in scan_results.items():
        print(f"    {os.path.basename(path):46s} " + " ".join(
            f"{k}={v}" for k, v in verdicts.items()))
    report["scan_results"] = scan_results

    # --- 3. Execution oracle ----------------------------------------------
    print("\n[3] Confirming payload execution (ExecutionOracle)...")
    exec_results = confirm_execution(candidates, args.backend)
    for path, executed in exec_results.items():
        print(f"    {os.path.basename(path):46s} executed={executed}")
    report["execution"] = {os.path.basename(p): v for p, v in exec_results.items()}

    # --- 3b. Confirmed bypasses (panel-all-benign AND executed) -----------
    print("\n[3b] Confirmed bypasses (check_bypass)...")
    bypasses = {}
    for c in candidates:
        panel = [scan_results.get(c["path"], {}).get(s, "error") for s in PANEL]
        executed = exec_results[c["path"]]
        is_bypass = check_bypass(panel, "malicious" if executed else "benign")
        bypasses[c["family"]] = is_bypass
        print(f"    {os.path.basename(c['path']):46s} bypass={is_bypass}")
    report["confirmed_bypasses"] = bypasses

    # --- 4. Defense prototype ---------------------------------------------
    print("\n[4] Running ModelDefense prototype...")
    defense_results = defend_candidates(candidates, args.backend, os.path.join(args.out, "defense"))
    for path, d in defense_results.items():
        print(f"    {os.path.basename(path):46s} {d['verdict']}")
    report["defense"] = {os.path.basename(p): d for p, d in defense_results.items()}

    # --- 4b. Load-time monitor ---------------------------------------------
    print("\n[4b] Monitoring load-time behavior...")
    monitor_results = monitor_candidates(candidates, args.backend)
    for path, m in monitor_results.items():
        print(f"    {os.path.basename(path):46s} {m['verdict']}")
    report["monitor"] = {os.path.basename(p): m for p, m in monitor_results.items()}

    # --- 5. GGUF attack surface -------------------------------------------
    print("\n[5] GGUF attack surface...")
    gguf_dir = os.path.join(args.out, "gguf")
    gguf_manifest, gguf_benign = build_gguf_corpus(gguf_dir)
    images = build_images(SCANNERS, args.tag)
    gguf_targets = [p for _, p in gguf_manifest] + [gguf_benign]
    gguf_rows = scan_gguf(args.backend, images, gguf_targets)
    report["gguf"] = gguf_rows
    for r in gguf_rows:
        print(f"    {r['artifact']:46s} {r['scanner']:10s} {r['verdict']}")

    # --- 6. Write report --------------------------------------------------
    docs_dir = "docs"
    os.makedirs(docs_dir, exist_ok=True)
    lines = ["# ReGenBench -- Task 3 Unified Demo", ""]
    lines.append(f"Backend: `{args.backend}`; seed subset: `{args.subset}`.")
    lines.append("")
    lines.append("## 4b. LoadTimeMonitor")
    lines.append("")
    lines.append("| candidate | verdict | suspicious syscalls | files created | network |")
    lines.append("| :--- | :---: | :---: | :---: | :---: |")
    for c in report["candidates"]:
        base = os.path.basename(c["path"])
        m = report["monitor"].get(base, {})
        lines.append(f"| {c['family']} | {m.get('verdict', 'error')} | "
                     f"{len(m.get('suspicious_syscalls', []))} | "
                     f"{len(m.get('files_created', []))} | {m.get('network_activity', False)} |")
    lines.append("")
    lines.append("## 1. Generated candidates (one per attack family)")
    lines.append("")
    for c in report["candidates"]:
        lines.append(f"- **{c['family']}** -> `{os.path.basename(c['path'])}`")
    lines.append("")
    lines.append("## 2. Static scanner panel verdicts")
    lines.append("")
    lines.append("| candidate | " + " | ".join(PANEL) + " | confirmed bypass |")
    lines.append("| :--- |" + " | ".join([":---:"] * len(PANEL)) + " | :---: |")
    for c in report["candidates"]:
        base = os.path.basename(c["path"])
        v = report["scan_results"].get(c["path"], {})
        lines.append(f"| {c['family']} | " + " | ".join(v.get(s, "err") for s in PANEL)
                     + f" | {report['confirmed_bypasses'].get(c['family'], False)} |")
    lines.append("")
    lines.append("## 3. ExecutionOracle confirmation")
    lines.append("")
    lines.append("| candidate | executed |")
    lines.append("| :--- | :---: |")
    for c in report["candidates"]:
        base = os.path.basename(c["path"])
        lines.append(f"| {c['family']} | {report['execution'].get(base, False)} |")
    lines.append("")
    lines.append("## 4. ModelDefense prototype")
    lines.append("")
    lines.append("| candidate | verdict | reason |")
    lines.append("| :--- | :---: | :--- |")
    for c in report["candidates"]:
        base = os.path.basename(c["path"])
        d = report["defense"].get(base, {})
        lines.append(f"| {c['family']} | {d.get('verdict', 'err')} | {d.get('reason', '')} |")
    lines.append("")
    lines.append("## 5. GGUF attack surface (ggufref oracle vs modelscan)")
    lines.append("")
    lines.append("| artifact | ggufref | modelscan |")
    lines.append("| :--- | :---: | :---: |")
    for r in report["gguf"]:
        art = r["artifact"]
        other = next((x["verdict"] for x in report["gguf"]
                      if x["artifact"] == art and x["scanner"] != r["scanner"]), "err")
        if r["scanner"] == "ggufref":
            lines.append(f"| {art} | {r['verdict']} | {other} |")
    lines.append("")
    lines.append("## 6. Baseline comparison")
    lines.append("")
    lines.append("ShadowPickle baseline (reproduced by `scripts/run_shadowpickle_baseline.py`): "
                 "10/40 valid candidates bypassed (25.0%). Fuzzing campaigns: 446/945 (47.2%).")
    lines.append("")
    n_bypass = sum(1 for v in report["confirmed_bypasses"].values() if v)
    lines.append(f"In this demo subset, {n_bypass}/{len(report['confirmed_bypasses'])} generated "
                 "candidates evaded the full panel while still executing "
                 "(ExecutionOracle-confirmed). See `docs/evaluation-report.md` for the scaled "
                 "campaign numbers and `docs/related-works-comparison.md` for how these compare "
                 "to ShadowPickle / PickleFuzzer / DynaHug.")
    lines.append("")
    lines.append("## Note on safety")
    lines.append("")
    lines.append("No untrusted artifact is ever deserialized on the host. Payload execution "
                 "confirmation happens inside the sandboxed base container; the defense "
                 "prototype quarantines dangerous artifacts and only reserializes via "
                 "`torch.load(weights_only=True)` inside the container.")

    with open(os.path.join(docs_dir, "demo-report.md"), "w") as f:
        f.write("\n".join(lines))
    with open(os.path.join(args.out, "demo-report.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[written] docs/demo-report.md")
    print(f"[written] {os.path.join(args.out, 'demo-report.json')}")
    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
