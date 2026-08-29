"""Containerized load-time monitoring for model artifacts."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class LoadTimeMonitor:
    """Observe dangerous process, file, and network activity during loading."""

    def __init__(self, backend: str = "docker", image: str = "regenbench/base:latest"):
        self.backend = backend
        self.image = image

    def monitor_load(self, pt_path: str, timeout: int = 10) -> dict:
        result = {
            "suspicious_syscalls": [], "files_created": [],
            "network_activity": False, "verdict": "suspicious", "error": None,
        }
        if not os.path.isfile(pt_path):
            result["error"] = "artifact not found"
            return result
        if shutil.which(self.backend) is None:
            result["error"] = f"container runtime unavailable: {self.backend}"
            return result

        with tempfile.TemporaryDirectory(prefix="regenbench-monitor-") as td:
            artifact = os.path.join(td, "artifact" + Path(pt_path).suffix)
            shutil.copyfile(pt_path, artifact)
            trace = os.path.join(td, "trace.log")
            cmd = [
                self.backend, "run", "--rm", "--security-opt", "label=disable",
                "-v", f"{artifact}:/artifact:ro", "-v", f"{td}:/monitor",
                self.image, "sh", "-c",
                "strace -f -e trace=execve,openat,connect,sendto,recvfrom "
                "-o /monitor/trace.log python3.13 -c "
                "\"import torch; torch.load('/artifact', weights_only=False, map_location='cpu')\"",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                result["error"] = "monitor timeout"
                return result
            except OSError as exc:
                result["error"] = str(exc)
                return result

            trace_text = Path(trace).read_text(errors="replace") if os.path.exists(trace) else ""
            if not trace_text:
                result["error"] = (proc.stderr or "strace produced no trace").strip()[-500:]
            suspicious = []
            for line in trace_text.splitlines():
                if any(call in line for call in ("execve(", "connect(", "sendto(", "recvfrom(")):
                    suspicious.append(line)
            result["suspicious_syscalls"] = suspicious
            result["network_activity"] = any(
                call in trace_text for call in ("connect(", "sendto(", "recvfrom(")
            )
            created = []
            for candidate in Path(td).iterdir():
                if candidate.name not in {"artifact" + Path(pt_path).suffix, "trace.log"}:
                    created.append(str(candidate))
            result["files_created"] = created
            if proc.returncode != 0 and not suspicious and not created and result["error"] is None:
                result["error"] = (proc.stderr or "load failed").strip()[-500:]
            result["verdict"] = "suspicious" if result["error"] or suspicious or created or result["network_activity"] else "clean"
            return result
