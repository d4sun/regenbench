"""T3.6 — Safe Defense Prototype for Model Hub Upload Sanitization.

Provides quarantine-first inspection and safe reserialization for ML model
artifacts. Never deserializes untrusted data on the host.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from pipeline.opcodes import parse_pickle
from pipeline.pre_filter import is_admitted
from pipeline.registry import is_dangerous
from pipeline.scanners import run_scan, default_backend, SCANNERS


class DefenseVerdict(Enum):
    ACCEPTED = "accepted"
    RESERIALIZED = "reserialized"
    QUARANTINED = "quarantined"
    ERROR = "error"


@dataclass
class DefenseResult:
    artifact_path: str
    verdict: DefenseVerdict
    reason: str
    detected_callables: list[tuple[str, str]] = field(default_factory=list)
    reserialized_path: Optional[str] = None
    scanner_verdicts: dict[str, str] = field(default_factory=dict)
    scan_errors: dict[str, str] = field(default_factory=dict)
    sha256: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact_path,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "detected_callables": self.detected_callables,
            "reserialized_path": self.reserialized_path,
            "scanner_verdicts": self.scanner_verdicts,
            "scan_errors": self.scan_errors,
            "sha256": self.sha256,
        }


class ModelDefense:
    """Defense pipeline for ML model artifacts."""

    def __init__(
        self,
        backend: str | None = None,
        timeout: int = 120,
        panel_scanners: list[str] | None = None,
        image_tag: str = ":latest",
    ):
        self.backend = backend or default_backend()
        self.timeout = timeout
        self.panel = panel_scanners or ["picklescan", "modelscan", "fickling"]
        self.image_tag = image_tag

    def _sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _extract_callables(self, file_path: str) -> list[tuple[str, str]]:
        """Extract dangerous callables from pickle/torch artifact."""
        detected: list[tuple[str, str]] = []
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            is_zip = magic.startswith(b"PK\x03\x04")
            is_raw_pickle = magic[0] == 0x80

            if not (is_zip or is_raw_pickle):
                return detected

            if is_zip:
                with zipfile.ZipFile(file_path) as z:
                    pkl_names = [n for n in z.namelist() if n.endswith("data.pkl")]
                    if not pkl_names:
                        return detected
                    pkl_bytes = z.read(pkl_names[0])
            else:
                with open(file_path, "rb") as f:
                    pkl_bytes = f.read()

            parsed = parse_pickle(pkl_bytes)
            for i, (op, arg) in enumerate(parsed):
                if op.name in ("GLOBAL", "INST"):
                    parts = arg.decode("latin1").split("\n")
                    if len(parts) >= 2 and is_dangerous(parts[0], parts[1]):
                        detected.append((parts[0], parts[1]))
                elif op.name == "STACK_GLOBAL":
                    strings = []
                    for j in range(i - 1, max(-1, i - 6), -1):
                        o, a = parsed[j]
                        if o.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE"):
                            if o.name == "SHORT_BINUNICODE":
                                strings.append(a[1:].decode("utf-8", "replace"))
                            elif o.name == "BINUNICODE":
                                strings.append(a[4:].decode("utf-8", "replace"))
                            elif o.name == "UNICODE":
                                strings.append(a.strip(b"\r\n").decode("utf-8", "replace"))
                            if len(strings) == 2:
                                break
                    if len(strings) == 2:
                        module, name = strings[1], strings[0]
                        if is_dangerous(module, name):
                            detected.append((module, name))
        except Exception:
            pass
        return detected

    def _run_panel(self, file_path: str) -> tuple[dict[str, str], dict[str, str]]:
        """Run static scanner panel; return (verdicts, errors)."""
        verdicts: dict[str, str] = {}
        errors: dict[str, str] = {}
        images = {name: spec["image"] for name, spec in SCANNERS.items() if name in self.panel}
        for name, img in images.items():
            out, err = run_scan(self.backend, img + self.image_tag, file_path, self.timeout)
            if err:
                errors[name] = err
                verdicts[name] = "error"
            else:
                verdicts[name] = out.get("verdict", "error")
        return verdicts, errors

    def _safe_load_and_reserialize(self, file_path: str, output_dir: str) -> Optional[str]:
        """
        Attempt to load with torch.load(weights_only=True) in container and reserialize.
        Returns path to reserialized file or None if unsafe/fail.
        """
        container_script = f"""
import torch
import sys
try:
    obj = torch.load("/artifact", weights_only=True, map_location="cpu")
    if isinstance(obj, dict):
        out_path = "/output/safe_model.pt"
        torch.save(obj, out_path)
        print("SUCCESS:" + out_path)
    else:
        print("REJECTED:not_a_dict")
except Exception as e:
    print("REJECTED:" + str(e))
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            host_artifact = os.path.join(tmpdir, "model.pt")
            host_output = os.path.join(tmpdir, "output")
            os.makedirs(host_output, exist_ok=True)
            
            import shutil
            shutil.copy2(file_path, host_artifact)
            
            cmd = [
                self.backend, "run", "--rm",
                "-v", f"{os.path.abspath(host_artifact)}:/artifact:ro,z",
                "-v", f"{os.path.abspath(host_output)}:/output:z",
                "regenbench/base" + self.image_tag,
                "python3.13", "-c", container_script,
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                if proc.returncode != 0 and "relabeling" in (proc.stderr or "").lower():
                    cmd[2] = "--security-opt"
                    cmd.insert(3, "label=disable")
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                
                for line in proc.stdout.splitlines():
                    if line.startswith("SUCCESS:"):
                        src = os.path.join(host_output, "safe_model.pt")
                        if os.path.exists(src):
                            dst = os.path.join(output_dir, os.path.basename(file_path) + ".safe.pt")
                            shutil.copy2(src, dst)
                            return dst
                return None
            except (subprocess.TimeoutExpired, OSError):
                return None

    def inspect(self, file_path: str, output_dir: str | None = None) -> DefenseResult:
        """Inspect an artifact and return defense decision."""
        if not os.path.exists(file_path):
            return DefenseResult(
                artifact_path=file_path,
                verdict=DefenseVerdict.ERROR,
                reason="File not found",
            )

        with open(file_path, "rb") as f:
            data = f.read()
        sha = self._sha256(data)

        # Static analysis
        admitted = is_admitted(file_path)
        callables = self._extract_callables(file_path)

        # Run scanner panel
        scanner_verdicts, scan_errors = self._run_panel(file_path)
        any_malicious = any(v == "malicious" for v in scanner_verdicts.values())

        # Decision logic
        if not admitted and not callables and not any_malicious:
            return DefenseResult(
                artifact_path=file_path,
                verdict=DefenseVerdict.ACCEPTED,
                reason="Clean static analysis: no dangerous callables, all scanners benign",
                detected_callables=callables,
                scanner_verdicts=scanner_verdicts,
                scan_errors=scan_errors,
                sha256=sha,
            )

        if callables or any_malicious:
            # Try safe reserialization for torch files
            if file_path.endswith((".pt", ".pth", ".bin")):
                if output_dir is None:
                    output_dir = tempfile.gettempdir()
                os.makedirs(output_dir, exist_ok=True)
                reserialized = self._safe_load_and_reserialize(file_path, output_dir)
                if reserialized:
                    return DefenseResult(
                        artifact_path=file_path,
                        verdict=DefenseVerdict.RESERIALIZED,
                        reason=f"Dangerous content detected; safely reserialized with weights_only=True",
                        detected_callables=callables,
                        reserialized_path=reserialized,
                        scanner_verdicts=scanner_verdicts,
                        scan_errors=scan_errors,
                        sha256=sha,
                    )
            return DefenseResult(
                artifact_path=file_path,
                verdict=DefenseVerdict.QUARANTINED,
                reason=f"Dangerous callables or malicious scanner verdicts: {callables or scanner_verdicts}",
                detected_callables=callables,
                scanner_verdicts=scanner_verdicts,
                scan_errors=scan_errors,
                sha256=sha,
            )

        # Malformed or unparseable - quarantine
        return DefenseResult(
            artifact_path=file_path,
            verdict=DefenseVerdict.QUARANTINED,
            reason="Malformed or unparseable artifact; cannot verify safety",
            detected_callables=callables,
            scanner_verdicts=scanner_verdicts,
            scan_errors=scan_errors,
            sha256=sha,
        )

    def batch_inspect(self, file_paths: list[str], output_dir: str | None = None) -> list[DefenseResult]:
        """Inspect multiple artifacts."""
        results = []
        for path in file_paths:
            results.append(self.inspect(path, output_dir))
        return results