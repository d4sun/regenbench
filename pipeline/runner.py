"""T0.10 local task queue / orchestration.

Drives `generator -> filter -> panel/oracle fan-out` across the scanner and
oracle containers on a single host with a bounded `concurrent.futures` pool,
so the campaign parallelizes across 4+ scanners plus the sandboxed oracle
without resource thrash or distributed infrastructure.

Pipeline stages:

    generator   yield candidate artifact host-paths (dir walk / explicit).
    filter      predicate dropping artifacts cheaply (extension, size, name).
    fan-out     bounded thread pool running every panel scanner (+ the oracle
                for torch artifacts) per artifact; each task is a short-lived
                container subprocess.

A `TrackingSink` (see pipeline/tracking) receives per-task results; a no-op
sink is used when tracking is disabled.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable

from pipeline.scanners import (
    GGUF_EXTENSIONS,
    ORACLE_EXTENSIONS,
    SCANNERS,
    ScanResult,
    build_images,
    expected_scanners,
    run_scan,
)

DEFAULT_EXTS = {".pkl", ".pt", ".pth", ".onnx", ".keras", ".h5", ".hdf5", ".joblib", ".model", ".bin", ".gguf"}


class TrackingSink:
    """Injected metric sink; the no-op default. MLflow impl in T0.9."""

    def log_scans(self, results: Iterable[ScanResult]) -> None:
        pass

    def close(self) -> None:
        pass


@dataclass
class Config:
    backend: str = "podman"
    tag: str = ":latest"
    max_workers: int = 0
    timeout: int = 300
    extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTS))
    min_size: int = 0
    skip: set[str] = field(default_factory=set)
    oracle: bool = True
    pre_filter: bool = True
    oracle_model_dir: str | None = None


def make_generator(paths: list[str]) -> tuple[list[str], Callable[[], list[str]]]:
    """Return (root_paths, gen) where gen walks a dir tree or returns explicit
    files. Explicit file list is used verbatim (bypasses extension filter)."""
    files = [p for p in paths if os.path.isfile(p)]
    dirs = [p for p in paths if os.path.isdir(p)]

    def gen() -> list[str]:
        result = list(files)
        for d0 in dirs:
            for root, _dirs, names in os.walk(d0):
                for n in names:
                    result.append(os.path.join(root, n))
        return result

    return paths, gen


class Runner:
    """Bound an artifact generator + filter to a concurrent scan fan-out."""

    def __init__(self, config: Config, sink: TrackingSink | None = None,
                 scanners: list[str] | None = None,
                 overrides: list[str] | None = None):
        self.config = config
        self.sink = sink or TrackingSink()
        self.spec = expected_scanners(SCANNERS, scanners)
        self.images = build_images(self.spec, config.tag, overrides)

    def _filter(self, rel: str) -> bool:
        base = os.path.basename(rel)
        if os.path.basename(os.path.dirname(rel)) in self.config.skip:
            return False
        if base.startswith("."):
            return False
        if any(s in base for s in self.config.skip):
            return False
        # Optional extension filter: reject files whose suffix is not admitted.
        if self.config.extensions:
            ext = os.path.splitext(base)[1].lower()
            if ext not in self.config.extensions:
                return False
        # Optional minimum-size filter: reject empty/trivial artifacts.
        if self.config.min_size and self.config.min_size > 0:
            try:
                if os.path.getsize(rel) < self.config.min_size:
                    return False
            except OSError:
                return False
        return True

    def _scanners_for(self, src: str) -> list[str]:
        names = []
        ext = os.path.splitext(src)[1].lower()
        for name, meta in self.spec.items():
            if meta.get("mount_only_pt") and not self.config.oracle:
                continue
            if name == "dynahug":
                if not self.config.oracle:
                    continue
                if ext not in ORACLE_EXTENSIONS:
                    continue  # oracle only deserializes torch checkpoints
            if name == "ggufref":
                if not self.config.oracle:
                    continue
                if ext not in GGUF_EXTENSIONS:
                    continue  # reference parser only reads GGUF files
            names.append(name)
        return names

    def _one(self, src: str, scanner: str) -> ScanResult:
        t0 = time.time()
        out, err = run_scan(
            self.config.backend, self.images[scanner], src, self.config.timeout,
            oracle_model_dir=self.config.oracle_model_dir)
        dur = time.time() - t0
        if err or out is None:
            res = ScanResult(scanner, src, None, None, error=err or "no output", duration=dur)
        else:
            res = ScanResult(
                scanner, src,
                verdict=out.get("verdict"),
                exit_code=out.get("exit_code"),
                decision_score=out.get("decision_score"),
                findings=out.get("findings") or [],
                duration=dur,
            )
        return res

    def run(self, artifacts: Iterable[str], db_path: str | None = None) -> list[ScanResult]:
        import hashlib
        from pipeline.pre_filter import is_admitted
        from pipeline.db import init_db, log_candidate, log_panel_result, log_oracle_result

        artifacts = list(dict.fromkeys(artifacts))
        if db_path:
            init_db(db_path)

        jobs = []
        pre_filtered_artifacts = set()
        
        for src in artifacts:
            if self._filter(src) is False:
                continue

            # Generate candidate ID linking all records
            cand_id = hashlib.md5(src.encode("utf-8")).hexdigest()
            if db_path:
                log_candidate(db_path, cand_id, src, "Fuzzer Campaign")

            scanners = self._scanners_for(src)
            
            # Check pre-filter for DynaHug oracle
            if "dynahug" in scanners and self.config.pre_filter:
                admitted = is_admitted(src)
                if not admitted:
                    pre_filtered_artifacts.add(src)
                    scanners = [s for s in scanners if s != "dynahug"]
                    if db_path:
                        log_oracle_result(db_path, cand_id, "benign", 0.0, 0.0, True)

            for scanner in scanners:
                jobs.append((src, scanner, cand_id))

        workers = self.config.max_workers or max(1, min(32, (os.cpu_count() or 4)))
        results: list[ScanResult] = []
        
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as ex:
            futs = {ex.submit(self._one, src, scanner): (src, scanner, cand_id)
                    for src, scanner, cand_id in jobs}
            for fut in as_completed(futs):
                res = fut.result()
                src, scanner, cand_id = futs[fut]
                results.append(res)
                
                # Log execution output to the database
                if db_path:
                    if scanner == "dynahug":
                        log_oracle_result(db_path, cand_id, res.verdict or "error", res.decision_score, res.duration, False)
                    else:
                        log_panel_result(db_path, cand_id, scanner, res.verdict or "error", res.exit_code, res.findings, res.duration)

        # Append fake benign ScanResult for pre-filtered dynahug runs so that the summaries are balanced
        for src in pre_filtered_artifacts:
            cand_id = hashlib.md5(src.encode("utf-8")).hexdigest()
            res = ScanResult("dynahug", src, "benign", 0, decision_score=0.0, duration=0.0)
            results.append(res)

        results.sort(key=lambda r: (r.artifact, r.scanner))
        if self.sink is not None:
            self.sink.log_scans(results)
        return results


def summarize(results: list[ScanResult]) -> dict:
    by_scanner: dict[str, dict] = {}
    for r in results:
        b = by_scanner.setdefault(r.scanner, {"total": 0, "malicious": 0, "benign": 0,
                                               "error": 0, "durations": []})
        b["total"] += 1
        if r.verdict == "malicious":
            b["malicious"] += 1
        elif r.verdict == "benign":
            b["benign"] += 1
        else:
            b["error"] += 1
        b["durations"].append(r.duration)
    for b in by_scanner.values():
        b["mean_duration"] = round(sum(b["durations"]) / len(b["durations"]), 3)
        del b["durations"]
    summary = {
        "artifacts": len({r.artifact for r in results}),
        "tasks": len(results),
        "by_scanner": by_scanner,
    }
    return summary


def print_report(results: list[ScanResult], summary: dict) -> None:
    header = f"{'SCANNER':<12} {'ARTIFACT':<40} VERDICT    EXIT  SCORE   SECS"
    print(header)
    print("-" * 88)
    for r in results:
        score = f"{r.decision_score:+.3f}" if r.decision_score is not None else "  -   "
        verdict = r.verdict if r.verdict else "error"
        exit_code = f"{r.exit_code:<5}" if r.exit_code is not None else "  -  "
        print(f"{r.scanner:<12} {r.artifact:<40} {verdict:<10} {exit_code} {score} {r.duration:5.1f}")
    print("-" * 88)
    for name, b in summary["by_scanner"].items():
        print(f"{name}: {b['malicious']} malicious / {b['benign']} benign / "
              f"{b['error']} error   (n={b['total']}, mean {b['mean_duration']}s)")
    print(f"\n{summary['tasks']} tasks across {summary['artifacts']} artifacts.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline-run", description=__doc__)
    ap.add_argument("paths", nargs="+", help="artifact files and/or directories to scan")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--image", action="append", default=[],
                    help="scanner=image:tag override")
    ap.add_argument("--scanner", action="append", default=None,
                    help="restrict panel (default all)")
    ap.add_argument("--workers", type=int, default=0,
                    help="pool size (default min(32, cpu_count))")
    ap.add_argument("--timeout", type=int, default=300, help="per-scan timeout (s)")
    ap.add_argument("--tag-filter", action="append", default=[],
                    help="skip artifacts whose basename contains this substring")
    ap.add_argument("--oracle", action="store_true",
                    help="also fan out to the DynaHug oracle on torch artifacts")
    ap.add_argument("--json", metavar="PATH", default=None,
                    help="write the full result set as JSON")
    ap.add_argument("--db", metavar="PATH", default=None,
                    help="write results to a unified SQLite database")
    args = ap.parse_args(argv)

    config = Config(
        backend=args.backend,
        tag=args.tag,
        max_workers=args.workers,
        timeout=args.timeout,
        skip=set(args.tag_filter),
        oracle=args.oracle,
    )

    _, gen = make_generator(args.paths)
    runner = Runner(config, scanners=args.scanner, overrides=args.image)
    artifacts = gen()
    print(f"[pipeline] {len(artifacts)} artifact(s), pool={runner.config.max_workers or 'auto'}, backend={args.backend}")
    results = runner.run(artifacts, db_path=args.db)
    summary = summarize(results)
    print_report(results, summary)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "summary": summary,
                "results": [{
                    "scanner": r.scanner, "artifact": r.artifact,
                    "verdict": r.verdict, "exit_code": r.exit_code,
                    "decision_score": r.decision_score, "duration": r.duration,
                } for r in results],
            }, f, indent=2)
    return 0 if not any(r.error for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())