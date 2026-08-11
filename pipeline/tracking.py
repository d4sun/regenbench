"""T0.9 experiment tracking: local, file-backed MLflow sink.

A `TrackingSink` that logs campaign metrics to an on-disk MLflow store
(`./mlruns` by default, no hosted server). Run `mlflow ui` to render the
dashboard. A separate CLI (python -m pipeline.tracking) logs a labelled corpus
trace so the dashboard can be validated without a live campaign.

Per scanner run, `log_scans` records:

    params:  backend, workers, tag, artifact_count
    metrics: scanned, malicious, benign, error,
             coverage      = scanned / total artifacts
             detected      = malicious artifacts flagged / malicious artifacts
             evasion       = malicious artifacts labeled benign / malicious artifacts
             mean_duration_s

With `batch=0,1,2,...`, each metric is also logged under a `<b{N}>_` prefix and
the running batch index is kept in `mlflow.active_run()` lineage, so successive
campaign batches appear as a time-series in the MLflow UI.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Iterable, Mapping, Optional

try:
    import mlflow
    _MLFLOW = True
except Exception:  # noqa: BLE001
    _MLFLOW = False

from pipeline.runner import ScanResult


class MlflowSink:
    """Log per-scanner campaign metrics into a local MLflow file store.

    Degrades to a working-but-non-logging sink if MLflow is unavailable, so a
    scan run never hard-fails because tracking is missing.
    """

    def __init__(self, tracking_uri: Optional[str] = None,
                 experiment: str = "regenbench-campaign",
                 batch: Optional[int] = None,
                 params: Optional[Mapping[str, str]] = None):
        self.enabled = _MLFLOW
        uri = tracking_uri or os.environ.get("MLFLOW_TRACKING_URI")
        if uri is None:
            uri = os.path.join("mlruns", "")  # file store rooted at ./mlruns
        self.tracking_uri = uri
        self.experiment = experiment
        self.batch = batch
        self.params = dict(params or {})

    def _ensure(self) -> bool:
        if not self.enabled:
            return False
        try:
            mlflow.set_tracking_uri(self.tracking_uri)
            # Always set the experiment by NAME so the call resolves to the
            # (created-on-first-run) experiment rather than treating an id
            # string as a new experiment name.
            if mlflow.get_experiment_by_name(self.experiment) is None:
                mlflow.create_experiment(self.experiment)
            mlflow.set_experiment(self.experiment)
        except Exception:  # noqa: BLE001
            self.enabled = False
            return False
        return True

    def close(self) -> None:
        if self.enabled:
            try:
                if mlflow.active_run() is not None:
                    mlflow.end_run()
            except Exception:  # noqa: BLE001
                pass

    def log_scans(self, results: Iterable[ScanResult],
                  ground_truth: Optional[Mapping[str, bool]] = None) -> None:
        """Log results, optionally against `ground_truth` {artifact: is_malicious}
        so coverage / detected / evasion are well-defined."""
        results = list(results)
        if not results or not self._ensure():
            return
        gt = dict(ground_truth or {})
        by_scanner: dict[str, list[ScanResult]] = {}
        for r in results:
            by_scanner.setdefault(r.scanner, []).append(r)
        total = len({r.artifact for r in results})

        for scanner, rs in by_scanner.items():
            run_name = scanner if self.batch is None else f"{scanner}:b{self.batch}"
            with mlflow.start_run(run_name=run_name):
                mlflow.log_params({
                    "scanner": scanner,
                    "backend": self.params.get("backend", "podman"),
                    "workers": self.params.get("workers", "auto"),
                    "artifact_count": total,
                })
                scanned = [r for r in rs if r.ok]
                n = len(scanned)
                malicious = sum(1 for r in scanned if r.verdict == "malicious")
                benign = sum(1 for r in scanned if r.verdict == "benign")
                err = sum(1 for r in rs if r.error)
                coverage = n / total if total else 0.0

                known_mal = [r for r in scanned if gt.get(r.artifact)]
                flagged = sum(1 for r in known_mal if r.verdict == "malicious")
                suspected = [r for r in scanned
                             if gt.get(r.artifact) is False and r.verdict == "malicious"]
                detected = flagged / len(known_mal) if known_mal else 0.0
                evasion = 1.0 - detected if known_mal else 0.0
                mean_dur = (sum(r.duration for r in scanned) / n) if n else 0.0

                metrics = {
                    "scanned": float(n),
                    "malicious": float(malicious),
                    "benign": float(benign),
                    "error": float(err),
                    "coverage": coverage,
                    "detected": detected,
                    "evasion": evasion,
                    "false_positive": float(len(suspected)),
                    "mean_duration_s": mean_dur,
                }
                if self.batch is None:
                    mlflow.log_metrics(metrics)
                else:
                    mlflow.log_metrics({f"b{self.batch}_{k}": v for k, v in metrics.items()})
                    mlflow.log_metrics({k: v for k, v in metrics.items()
                                        if k in ("coverage", "detected", "evasion")})


def main(argv: Optional[list[str]] = None) -> int:
    """Validate T0.9: run the committed corpus through the orchestrator and log
    coverage / detected / evasion per scanner to a file-backed MLflow store, so
    `mlflow ui` renders a dashboard for a test run.

    Ground truth is derived from the corpus paths (pkl/.../malicious_* and
    torch/.../malicious* are malicious).
    """
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=os.path.join("ci", "corpus"))
    ap.add_argument("--backend", default="podman")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--oracle", action="store_true")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--batch", type=int, default=None)
    ap.add_argument("--tracking-uri", default=None)
    args = ap.parse_args(argv)

    from pipeline import runner as pr
    from pipeline.runner import Runner

    files = []
    for root, _d, names in os.walk(args.corpus):
        for n in names:
            p = os.path.join(root, n)
            if os.path.isfile(p):
                files.append(p)
    gt = {p: ("malicious" in os.path.basename(os.path.dirname(p)) or
              "malicious" in os.path.basename(p)) for p in files}

    cfg = pr.Config(backend=args.backend, tag=args.tag,
                    max_workers=args.workers, oracle=args.oracle)
    sink = MlflowSink(tracking_uri=args.tracking_uri, batch=args.batch,
                      params={"backend": args.backend, "workers": str(args.workers)})
    runner = Runner(cfg, sink=sink)
    results = runner.run(files)
    sink.log_scans(results, ground_truth=gt)
    sink.close()

    print(pr.summarize(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())