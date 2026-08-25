"""Phase 4 — Ensemble Oracle (DynaHug + Syscall Anomaly Detector).

Combines DynaHug's behavioral classifier with an Isolation Forest on syscall
frequency vectors to reduce false positives and improve bypass confirmation.
"""

from __future__ import annotations

import json
import os
import joblib
import numpy as np
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction import DictVectorizer

from pipeline.validity import ValidityOracle


class SyscallAnomalyDetector:
    """Isolation Forest on syscall frequency vectors for anomaly detection."""

    def __init__(
        self,
        contamination: float = 0.01,
        n_estimators: int = 200,
        random_state: int = 1337,
    ):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        self.vectorizer = DictVectorizer(sparse=False)
        self.scaler = StandardScaler(with_mean=False)
        self.syscall_names: list[str] = []
        self._fitted = False

    @staticmethod
    def _parse_strace_summary(content: str) -> dict[str, int]:
        """Parse strace -c summary output into syscall counts."""
        counts = {}
        for line in content.split("\n"):
            if (
                line.startswith("% time")
                or line.startswith("------")
                or line.startswith("100.00")
                or line.endswith("...>")
            ):
                continue
            parts = line.split()
            try:
                if len(parts) >= 5:
                    calls = int(parts[3])
                    syscall = parts[-1]
                    counts[syscall] = calls
            except (ValueError, IndexError):
                continue
        return counts

    def _build_feature_vector(self, counts: dict[str, int]) -> np.ndarray:
        """Build presence+frequency feature vector over pinned syscall vocabulary."""
        features = {}
        for sc in self.syscall_names:
            v = counts.get(sc, 0)
            features[f"presence_{sc}"] = 1 if v > 0 else 0
            features[f"frequency_{sc}"] = v
        X = self.vectorizer.transform([features])
        freq_idx = [
            i for i, n in enumerate(self.vectorizer.get_feature_names_out())
            if n.startswith("frequency_")
        ]
        if freq_idx:
            X[:, freq_idx] = self.scaler.transform(X[:, freq_idx])
        return X

    def train(self, benign_traces: list[dict[str, Any]]) -> dict[str, Any]:
        """Train on benign traces only."""
        if not benign_traces:
            raise ValueError("No benign traces provided")

        self.syscall_names = sorted(
            {sc for t in benign_traces for sc in t.get("counts", {})}
        )

        feature_dicts = []
        for t in benign_traces:
            counts = t.get("counts", {})
            fd = {}
            for sc in self.syscall_names:
                v = counts.get(sc, 0)
                fd[f"presence_{sc}"] = 1 if v > 0 else 0
                fd[f"frequency_{sc}"] = v
            feature_dicts.append(fd)

        X = self.vectorizer.fit_transform(feature_dicts)
        freq_idx = [
            i for i, n in enumerate(self.vectorizer.get_feature_names_out())
            if n.startswith("frequency_")
        ]
        if freq_idx:
            X[:, freq_idx] = self.scaler.fit_transform(X[:, freq_idx])

        self.model.fit(X)
        self._fitted = True

        scores = self.model.decision_function(X)
        return {
            "n_samples": len(benign_traces),
            "n_features": X.shape[1],
            "train_scores": {
                "mean": float(np.mean(scores)),
                "std": float(np.std(scores)),
                "min": float(np.min(scores)),
                "max": float(np.max(scores)),
                "positive_rate": float(np.mean(scores > 0)),
            },
        }

    def predict(self, counts: dict[str, int]) -> float:
        """Return anomaly score (higher = more anomalous)."""
        if not self._fitted:
            raise RuntimeError("Model not fitted. Call train() first.")
        X = self._build_feature_vector(counts)
        return float(self.model.decision_function(X)[0])

    def is_anomalous(self, counts: dict[str, int], threshold: float = 0.0) -> bool:
        """Return True if trace is anomalous (below threshold)."""
        score = self.predict(counts)
        return score < threshold

    def save(self, path: str) -> None:
        """Save model artifacts."""
        os.makedirs(path, exist_ok=True)
        joblib.dump(self.model, os.path.join(path, "isolation_forest.pkl"))
        joblib.dump(self.vectorizer, os.path.join(path, "vectorizer.pkl"))
        joblib.dump(self.scaler, os.path.join(path, "scaler.pkl"))
        with open(os.path.join(path, "syscalls.txt"), "w") as f:
            f.write("\n".join(self.syscall_names) + "\n")

    @classmethod
    def load(cls, path: str) -> "SyscallAnomalyDetector":
        """Load model artifacts."""
        detector = cls()
        detector.model = joblib.load(os.path.join(path, "isolation_forest.pkl"))
        detector.vectorizer = joblib.load(os.path.join(path, "vectorizer.pkl"))
        detector.scaler = joblib.load(os.path.join(path, "scaler.pkl"))
        with open(os.path.join(path, "syscalls.txt")) as f:
            detector.syscall_names = [ln.strip() for ln in f if ln.strip()]
        detector._fitted = True
        return detector


class EnsembleOracle(ValidityOracle):
    """Ensemble oracle combining DynaHug + syscall anomaly detection."""

    def __init__(
        self,
        container_backend: str = "podman",
        container_image: str = "localhost/regenbench/base:latest",
        timeout: int = 20,
        dynahug_model_dir: str | None = None,
        anomaly_model_dir: str | None = None,
        anomaly_threshold: float = 0.0,
    ):
        super().__init__(container_backend, container_image, timeout)
        self.anomaly_threshold = anomaly_threshold

        self.dynahug_model_dir = dynahug_model_dir or os.environ.get(
            "REGENBENCH_ORACLE_MODEL_DIR",
            os.path.abspath("real_benign_corpus/oracle-calibrated/v5-recalibrated"),
        )

        self.anomaly_detector = None
        if anomaly_model_dir and os.path.exists(anomaly_model_dir):
            self.anomaly_detector = SyscallAnomalyDetector.load(anomaly_model_dir)
        elif anomaly_model_dir:
            print(f"[ensemble-oracle] Warning: anomaly model dir not found: {anomaly_model_dir}")

    def _collect_syscall_trace(self, pt_path: str) -> dict[str, int] | None:
        """Run the oracle container and extract syscall counts."""
        cmd = [
            self.backend, "run", "--rm",
            "-v", f"{os.path.abspath(pt_path)}:/artifact:ro,z",
        ]
        # Pass calibrated model dir if available
        if self.dynahug_model_dir and os.path.exists(self.dynahug_model_dir):
            cmd += ["-e", "DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated",
                    "-v", f"{os.path.abspath(self.dynahug_model_dir)}:/opt/dynahug/recalibrated:ro,z"]
        cmd += ["localhost/regenbench/dynahug:latest", "/artifact"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return None
        try:
            out = json.loads((proc.stdout or "").strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return None
        if out.get("verdict") == "error":
            return None
        raw_output = out.get("raw_output") or ""
        marker = "--- strace -c -f summary ---"
        if marker in raw_output:
            summary_text = raw_output.split(marker, 1)[1]
            summary_text = summary_text.split("--- syscalls observed ---", 1)[0]
        else:
            summary_text = raw_output
        return SyscallAnomalyDetector._parse_strace_summary(summary_text)

    def validate_torch(self, pt_bytes: bytes, trigger_file: str) -> bool:
        """Validate using ensemble: both DynaHug AND anomaly detector must agree."""
        if os.path.exists(trigger_file):
            try:
                os.remove(trigger_file)
            except OSError:
                pass

        temp_dir = tempfile.gettempdir()
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            temp_file_name = os.path.basename(f.name)
        host_pt_path = os.path.join(temp_dir, temp_file_name)
        with open(host_pt_path, "wb") as f:
            f.write(pt_bytes)

        import shutil
        has_container_tool = shutil.which(self.backend) is not None
        dynahug_result = False
        anomaly_result = False

        if not has_container_tool:
            print(f"[ensemble-oracle] container runtime unavailable: {self.backend}")
        else:
            container_pt_path = f"/tmp/{temp_file_name}"

            # 1. DynaHug validation (full oracle with OCSVM)
            cmd = [
                self.backend, "run", "--rm",
                "-v", f"{temp_dir}:/tmp:z",
            ]
            if self.dynahug_model_dir and os.path.exists(self.dynahug_model_dir):
                cmd += ["-e", "DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated",
                        "-v", f"{os.path.abspath(self.dynahug_model_dir)}:/opt/dynahug/recalibrated:ro,z"]
            cmd += [self.image, "/tmp/" + temp_file_name]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                if proc.returncode == 0:
                    dynahug_result = True
                # Parse decision score from output
                try:
                    out = json.loads((proc.stdout or "").strip().splitlines()[-1])
                    self._last_dynahug_score = out.get("decision_score", None)
                    self._last_dynahug_verdict = out.get("verdict", "error")
                except Exception:
                    self._last_dynahug_score = None
                    self._last_dynahug_verdict = "error"
            except (OSError, subprocess.TimeoutExpired):
                dynahug_result = False
                self._last_dynahug_score = None
                self._last_dynahug_verdict = "error"

            # 2. Syscall anomaly detection
            if self.anomaly_detector is not None:
                counts = self._collect_syscall_trace(host_pt_path)
                if counts is not None:
                    is_anomalous = self.anomaly_detector.is_anomalous(
                        counts, self.anomaly_threshold
                    )
                    # Anomalous = potential bypass (execution diverged from benign)
                    anomaly_result = is_anomalous

        try:
            os.remove(host_pt_path)
        except OSError:
            pass

        executed = self._trigger_exists(trigger_file)
        if executed:
            try:
                os.remove(trigger_file)
            except OSError:
                pass

        # Ensemble decision: combine DynaHug decision score with anomaly score
        # Anomaly score > 0 = looks benign, < 0 = anomalous
        # Convert anomaly score to confidence: higher = more benign
        # We want: dynahug says malicious (not valid) AND anomaly says anomalous
        # But for fitness scoring, we want continuous signal
        
        # Binary ensemble decision for validity
        ensemble_valid = dynahug_result and anomaly_result and executed
        
        # For fitness scoring, store both scores
        self._last_anomaly_score = anomaly_score if 'anomaly_score' in locals() else 0.0
        self._last_dynahug_result = dynahug_result
        
        return ensemble_valid

    def _trigger_exists(self, path: str, wait: float = 5.0) -> bool:
        """Poll for the sentinel file."""
        import time
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if os.path.exists(path):
                return True
            time.sleep(0.05)
        return False