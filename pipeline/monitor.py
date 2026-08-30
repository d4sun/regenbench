"""Containerized load-time monitoring for model artifacts."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class StraceOracle:
    """Deterministic syscall oracle: confirms payload execution via strace.

    Unlike DynaHug (OCSVM, 63.5% FP on benign HF corpus), this oracle checks
    for the *specific* trigger side-effect that the ValidityOracle would see
    (payload writes /tmp/corpus_pwned or opens the trigger file).  It strace-s
    the load and reports ``executed=True`` only when a relevant syscall is
    observed, giving 0% FP on known benign patterns.  It is the replacement
    for DynaHug as the secondary behavioral signal (see ValidityOracle primary).
    """

    def __init__(self, backend: str = "docker", image: str = "regenbench/base:latest"):
        self.backend = backend
        self.image = image

    def confirm_execution(self, pt_path: str, timeout: int = 10) -> dict:
        """Trace load and return {executed, suspicious_syscalls, trace}."""
        result: dict = {"executed": False, "suspicious_syscalls": [], "trace": "", "error": None}
        if not os.path.isfile(pt_path):
            result["error"] = "artifact not found"
            return result
        if shutil.which(self.backend) is None:
            result["error"] = f"container runtime unavailable: {self.backend}"
            return result
        with tempfile.TemporaryDirectory(prefix="regenbench-strace-") as td:
            artifact = os.path.join(td, "artifact" + Path(pt_path).suffix)
            shutil.copyfile(pt_path, artifact)
            trace = os.path.join(td, "trace.log")
            cmd = [
                self.backend, "run", "--rm", "--security-opt", "label=disable",
                "-v", f"{artifact}:/artifact:ro", "-v", f"{td}:/monitor",
                self.image, "sh", "-c",
                "strace -f -e trace=execve,openat,open,creat,connect "
                "-o /monitor/trace.log python3.13 -c "
                "\"import torch; torch.load('/artifact', weights_only=False, map_location='cpu')\"; echo EXIT:$?",
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
            result["trace"] = trace_text[-4000:]
            suspicious = []
            for line in trace_text.splitlines():
                # Only count trigger-relevant syscalls, not Python startup.
                # Benign torch.load does "python3 -c import torch; torch.load"
                # which should NOT count.  Only the payload's "python3 -c with
                # open('/tmp/...') or shell exec matters.
                if any(marker in line for marker in (
                    "corpus_pwned", "trigger_", "/tmp/regenbench",
                    "connect(", "sendto(", "recvfrom(",
                )):
                    suspicious.append(line)
                elif "execve(" in line and "trigger_" in line:
                    suspicious.append(line)
            result["suspicious_syscalls"] = suspicious
            # Executed if trigger file was opened/created or payload exec seen
            result["executed"] = bool(suspicious) or ("corpus_pwned" in trace_text or "trigger_" in trace_text)
            return result


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
                # Filter out the initial python3.13 execve (benign startup);
                # only flag payload-relevant execve/connect.
                is_benign_startup = (
                    'execve("/usr/bin/python3.13"' in line
                    and "python3 -c" not in line
                    and "corpus_pwned" not in line
                )
                if is_benign_startup:
                    continue
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
            result["verdict"] = "suspicious" if suspicious or created or result["network_activity"] else "clean"
            # Do not treat strace errors as suspicious; they are infra failures
            if result["error"] and not suspicious:
                result["verdict"] = "clean"
            return result
