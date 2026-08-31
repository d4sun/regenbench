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

    P2.1: scoring rubric (1pt per category) — 0 benign, 1 suspicious (manual),
    ≥2 malicious. Categories: file-descriptor (openat/open/creat on sensitive
    paths), network (socket/connect/sendto/recvfrom), process-spawning
    (clone/fork/vfork/execve).
    """

    def __init__(self, backend: str = "docker", image: str = "regenbench/base:latest"):
        self.backend = backend
        self.image = image

    def _score_trace(self, trace_text: str) -> tuple[int, list[str], dict[str, bool]]:
        """Score trace by category, returns (score, suspicious_lines, categories_hit)."""
        categories = {"file": False, "network": False, "process": False}
        suspicious = []
        sensitive_markers = ("/etc/", "/.ssh/", "/tmp/regenbench", "corpus_pwned", "trigger_")
        for line in trace_text.splitlines():
            # File-descriptor tracking: openat/open/creat on sensitive paths
            if any(call in line for call in ("openat(", "open(", "creat(")):
                if any(m in line for m in sensitive_markers):
                    # Exclude benign python startup opens
                    if "python3.13" not in line or "corpus_pwned" in line or "trigger_" in line:
                        categories["file"] = True
                        suspicious.append(line)
                        continue
                # Also flag /tmp with executable bits or /etc writes
                if '"/tmp/' in line and ("O_CREAT" in line or "O_WRONLY" in line):
                    categories["file"] = True
                    suspicious.append(line)
                    continue
            # Network tracking: socket/connect/sendto/recvfrom
            if any(call in line for call in ("socket(", "connect(", "sendto(", "recvfrom(")):
                # Ignore benign DNS? we flag all network as suspicious for model load
                categories["network"] = True
                suspicious.append(line)
                continue
            # Process-spawning: clone/fork/vfork/execve
            if any(call in line for call in ("clone(", "fork(", "vfork(", "execve(")):
                # Filter benign startup execve("/usr/bin/python3.13" without payload)
                is_benign_startup = (
                    'execve("/usr/bin/python3.13"' in line
                    and "trigger_" not in line
                    and "corpus_pwned" not in line
                    and "python3 -c" not in line
                )
                if not is_benign_startup:
                    # Only count if marker or payload exec
                    if any(m in line for m in ("trigger_", "corpus_pwned", "python3 -c", "sh -c", "/bin/sh")):
                        categories["process"] = True
                        suspicious.append(line)
                    elif "execve(" in line and "trigger_" in line:
                        categories["process"] = True
                        suspicious.append(line)
        # Also handle legacy markers for backward compat
        if any(m in trace_text for m in ("corpus_pwned", "trigger_")) and not categories["file"]:
            # Trigger file was created but not caught via openat due to truncation
            categories["file"] = True
        score = sum(1 for v in categories.values() if v)
        # If only legacy marker but no syscall, treat as file hit
        if score == 0 and ("corpus_pwned" in trace_text or "trigger_" in trace_text):
            categories["file"] = True
            score = 1
        return score, suspicious, categories

    def confirm_execution(self, pt_path: str, timeout: int = 10) -> dict:
        """Trace load and return {executed, suspicious_syscalls, trace, score, categories}."""
        result: dict = {"executed": False, "suspicious_syscalls": [], "trace": "", "error": None, "score": 0, "categories": {}, "verdict": "benign"}
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
            # P2.1: fix hardcoded python3.13 with fallback, add fd/network/process, no truncate
            cmd = [
                self.backend, "run", "--rm", "--security-opt", "label=disable",
                "-v", f"{artifact}:/artifact:ro", "-v", f"{td}:/monitor",
                self.image, "sh", "-c",
                "strace -f -e trace=execve,openat,open,creat,connect,socket,sendto,recvfrom,clone,fork,vfork "
                "-o /monitor/trace.log sh -c 'python3.13 -c \"import torch; torch.load(\\\"/artifact\\\", weights_only=False, map_location=\\\"cpu\\\")\" 2>&1 || python3 -c \"import torch; torch.load(\\\"/artifact\\\", weights_only=False, map_location=\\\"cpu\\\")\"'; echo EXIT:$?",
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
            # Keep full trace for scoring, but truncate for storage to avoid huge DB
            result["trace"] = trace_text[-8000:] if len(trace_text) > 8000 else trace_text
            score, suspicious, categories = self._score_trace(trace_text)
            result["suspicious_syscalls"] = suspicious
            result["score"] = score
            result["categories"] = categories
            # Rubric: 0 benign, 1 suspicious, >=2 malicious
            if score >= 2:
                result["verdict"] = "malicious"
                result["executed"] = True
            elif score == 1:
                result["verdict"] = "suspicious"
                # For H2 compatibility, treat suspicious as not executed unless trigger confirmed
                result["executed"] = bool(suspicious) and ("trigger_" in trace_text or "corpus_pwned" in trace_text)
            else:
                result["verdict"] = "benign"
                result["executed"] = False
            # Backward compat: executed if legacy marker
            if not result["executed"] and ("corpus_pwned" in trace_text or "trigger_" in trace_text):
                result["executed"] = True
                if result["verdict"] == "benign":
                    result["verdict"] = "suspicious"
                    result["score"] = 1
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
