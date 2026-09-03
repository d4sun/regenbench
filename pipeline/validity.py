"""T3.5 — Validity Oracle.

Filters malformed or non-functional pickle/torch candidates by validating:
1. Successful loading without unpickling errors.
2. Correct execution of the injected payload (verifying trigger side-effects).
3. The returned model/dictionary remains structurally functional.
"""

from __future__ import annotations

import os
import sys
import json
import pickle
import subprocess
import tempfile
import time
from typing import Any


def _trigger_exists(path: str, wait: float = 5.0) -> bool:
    """Poll for the sentinel file.

    The injected payload may launch an async child (e.g. subprocess.Popen)
    that writes the trigger after ``pickle.load`` returns, so we wait briefly
    instead of declaring the candidate non-executing on a race.
    """
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def _debug_enabled() -> bool:
    """True when REGENBENCH_VALIDITY_DEBUG is set to a truthy value.

    Campaign runs print a compact one-line failure summary by default; full
    container stdout/stderr (which can be large tracebacks from mutated
    candidates) is only printed when this is enabled.
    """
    return os.environ.get("REGENBENCH_VALIDITY_DEBUG", "").lower() in (
        "1", "true", "yes", "on")


def _summary_line(stderr: str) -> str:
    """Pick one readable line from container stderr for the non-debug
    one-line failure summary: skip Python traceback framing (``Traceback``,
    ``File "..."``, indented frames) and prefer the exception/message line."""
    lines = (stderr or "").splitlines()
    for ln in lines:
        s = ln.strip()
        if (not s or s.startswith(("Traceback", 'File "', "File '"))
                or ln[:1] in (" ", "\t")):
            continue
        return s[:160]
    for ln in reversed(lines):
        if ln.strip():
            return ln.strip()[:160]
    return ""


def _log_validation_failure(proc, action: str) -> None:
    """Report a failed sandbox container run.

    Debug mode prints the full container stdout/stderr (useful when triaging a
    specific candidate); otherwise a single line with the exit code and one
    stderr line keeps campaign logs readable.
    """
    if _debug_enabled():
        print(f"[validity-debug] {action} failed with code {proc.returncode}")
        print(f"[validity-debug] {action} stdout: {proc.stdout}")
        print(f"[validity-debug] {action} stderr: {proc.stderr}")
        return
    print(f"[validity] {action} failed (exit {proc.returncode}): {_summary_line(proc.stderr)}")


def _log_run_exception(exc: Exception) -> None:
    if _debug_enabled():
        print(f"[validity-debug] Container run exception: {exc}")
    else:
        print(f"[validity] container run exception: {exc}")


def _run_validation_cmd(cmd, retry_cmd, timeout):
    """Run a validity sandbox container, retrying once on transient
    docker/OCI startup failures (exit 125/126/127) and once on the SELinux
    relabel rejection (the existing ``label=disable`` retry). Rare infra
    failures should not silently drop a candidate as invalid."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode in (125, 126, 127):
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and "relabeling" in (proc.stderr or "").lower():
        proc = subprocess.run(retry_cmd, capture_output=True, text=True, timeout=timeout)
    return proc


class ValidityOracle:
    """Validates candidates to ensure they load successfully and trigger execution.
    
    Supports both PT (pickle/torch) and GGUF formats with a unified interface.
    """

    def __init__(self, container_backend: str | None = None, container_image: str = "localhost/regenbench/base:latest",
                 timeout: int = 20):
        if container_backend is None:
            from pipeline.scanners import default_backend
            container_backend = default_backend()
        self.backend = container_backend
        self.image = container_image
        self.timeout = timeout

    def validate(self, bytes_payload: bytes, trigger_file: str, format: str) -> dict:
        """Unified validation dispatcher for PT and GGUF formats.
        
        Returns:
            dict with keys: verdict (executed|benign|error), trigger_found (bool), duration (float)
        """
        if format == 'pt':
            return self.validate_torch(bytes_payload, trigger_file)
        elif format == 'gguf':
            return self.validate_gguf(bytes_payload, trigger_file)
        else:
            raise ValueError(f"Unknown format: {format}")

    def validate_pickle(self, pkl_bytes: bytes, trigger_file: str) -> dict:
        """Confirm that the pickle parses/loads successfully and triggers the payload execution."""
        # Clean up any existing trigger file
        if os.path.exists(trigger_file):
            try:
                os.remove(trigger_file)
            except OSError:
                pass

        # Write candidate to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(pkl_bytes)
            temp_pkl_path = f.name

        # Candidate bytes are untrusted and may execute arbitrary code during
        # deserialization. Never load them on the host.
        import shutil
        has_container_tool = shutil.which(self.backend) is not None
        success_load = False
        if has_container_tool:
            import os as _os
            host_dir = _os.path.dirname(temp_pkl_path)
            name = _os.path.basename(temp_pkl_path)
            container_path = f"/tmp/{name}"
            container_script = f"""
import pickle
with open({container_path!r}, 'rb') as f:
    obj = pickle.load(f)
assert obj is not None
"""
            cmd = [
                self.backend, "run", "--rm",
                "-v", f"{host_dir}:/tmp:z",
                self.image, "python3.13", "-c", container_script,
            ]
            retry_cmd = [
                self.backend, "run", "--rm",
                "--security-opt", "label=disable",
                "-v", f"{host_dir}:/tmp",
                self.image, "python3.13", "-c", container_script,
            ]
            try:
                proc = _run_validation_cmd(cmd, retry_cmd, self.timeout)
                success_load = (proc.returncode == 0)
                if not success_load:
                    _log_validation_failure(proc, "pickle validity")
            except (OSError, subprocess.TimeoutExpired) as e:
                _log_run_exception(e)
                success_load = False
        else:
            print(f"[validity-debug] container runtime unavailable: {self.backend}")
        try:
            os.remove(temp_pkl_path)
        except OSError:
            pass

        # Validate both load success and payload execution trigger
        executed = _trigger_exists(trigger_file)
        
        # Clean up trigger file
        if executed:
            try:
                os.remove(trigger_file)
            except OSError:
                pass
                 
        return {"verdict": "executed" if (success_load and executed) else "benign", 
                "trigger_found": executed, "duration": 0.0}

    def validate_torch(self, pt_bytes: bytes, trigger_file: str) -> dict:
        """Confirm that the PyTorch model checkpoint loads without error and triggers execution."""
        if os.path.exists(trigger_file):
            try:
                os.remove(trigger_file)
            except OSError:
                pass

        # Save candidate to /tmp (so it is mountable inside container)
        temp_dir = tempfile.gettempdir()
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            temp_file_name = os.path.basename(f.name)
        host_pt_path = os.path.join(temp_dir, temp_file_name)
        
        with open(host_pt_path, "wb") as f:
            f.write(pt_bytes)

        import shutil
        has_container_tool = shutil.which(self.backend) is not None
        success_load = False

        if not has_container_tool:
            print(f"[validity-debug] container runtime unavailable: {self.backend}")
            try:
                os.remove(host_pt_path)
            except OSError:
                pass
        else:
            # Run torch.load inside the container sandbox
            container_pt_path = f"/tmp/{temp_file_name}"
            container_script = f"""
import torch
obj = torch.load({container_pt_path!r}, weights_only=False, map_location='cpu')
assert isinstance(obj, dict)
"""
            cmd = [
                self.backend, "run", "--rm",
                "-v", f"{temp_dir}:/tmp:z",
                self.image, "python3.13", "-c", container_script
            ]
            retry_cmd = [
                self.backend, "run", "--rm",
                "--security-opt", "label=disable",
                "-v", f"{temp_dir}:/tmp",
                self.image, "python3.13", "-c", container_script
            ]

            try:
                proc = _run_validation_cmd(cmd, retry_cmd, self.timeout)
                success_load = (proc.returncode == 0)
                if not success_load:
                    _log_validation_failure(proc, "torch validity")
            except (OSError, subprocess.TimeoutExpired) as e:
                _log_run_exception(e)
                success_load = False
            finally:
                try:
                    os.remove(host_pt_path)
                except OSError:
                    pass

        executed = _trigger_exists(trigger_file)
        
        if executed:
            try:
                os.remove(trigger_file)
            except OSError:
                pass
                 
        return {"verdict": "executed" if (success_load and executed) else "benign",
                "trigger_found": executed, "duration": 0.0}

    def validate_gguf(self, gguf_bytes: bytes, trigger_file: str = "/tmp/trigger_gguf.txt") -> dict:
        """Confirm that a GGUF artifact parses with the reference reader
        (ggml-org/gguf) inside the Task-3 sandbox, and/or executes via strace.

        Thin wrapper over :func:`pipeline.scanners.run_scan` (the single path
        that knows the GGUF reference-oracle isolation flags); interprets the
        loader's ``summary.load_ok`` and ``summary.strace_executed``.

        Ground truth for the demo corpus: malformed-header attacks are rejected
        by the reference reader (their whole point), so ``False`` is the
        expected result for those families; the SSTI chat-template payload is
        structurally valid and renders (executing the Jinja2 gadget), so it
        must return ``True``.
        """
        import shutil
        from pipeline.scanners import run_scan
        has_container_tool = shutil.which(self.backend) is not None
        if not has_container_tool:
            print("[validity-debug] validate_gguf requires the gguf container")
            return {"verdict": "error", "trigger_found": False, "duration": 0.0}

        # Clean up trigger file
        if os.path.exists(trigger_file):
            try:
                os.remove(trigger_file)
            except OSError:
                pass

        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(gguf_bytes)
            host_path = f.name

        try:
            out, err = run_scan(
                self.backend, "localhost/regenbench/gguf:latest", host_path,
                timeout=self.timeout, gguf_ref=True)
            if err or out is None:
                print("[validity-debug] gguf oracle error:", (err or "")[:200])
                return {"verdict": "error", "trigger_found": False, "duration": 0.0}
            summary = out.get("summary") or {}
            executed = bool(summary.get("load_ok") or summary.get("strace_executed"))
        finally:
            try:
                os.remove(host_path)
            except OSError:
                pass

        # Check trigger file if execution was confirmed
        if executed:
            executed = _trigger_exists(trigger_file, wait=2.0)
            if executed:
                try:
                    os.remove(trigger_file)
                except OSError:
                    pass

        return {"verdict": "executed" if executed else "benign",
                "trigger_found": executed, "duration": 0.0}
