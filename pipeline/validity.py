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


class ValidityOracle:
    """Validates candidates to ensure they load successfully and trigger execution."""

    def __init__(self, container_backend: str | None = None, container_image: str = "localhost/regenbench/base:latest",
                 timeout: int = 20):
        if container_backend is None:
            from pipeline.scanners import default_backend
            container_backend = default_backend()
        self.backend = container_backend
        self.image = container_image
        self.timeout = timeout

    def validate_pickle(self, pkl_bytes: bytes, trigger_file: str) -> bool:
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
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                if proc.returncode != 0 and "relabeling" in (proc.stderr or "").lower():
                    retry = [
                        self.backend, "run", "--rm",
                        "--security-opt", "label=disable",
                        "-v", f"{host_dir}:/tmp",
                        self.image, "python3.13", "-c", container_script,
                    ]
                    proc = subprocess.run(retry, capture_output=True, text=True, timeout=self.timeout)
                success_load = (proc.returncode == 0)
                if not success_load:
                    print(f"[validity-debug] Container failed with code {proc.returncode}")
                    print(f"[validity-debug] Container stdout: {proc.stdout}")
                    print(f"[validity-debug] Container stderr: {proc.stderr}")
            except (OSError, subprocess.TimeoutExpired) as e:
                print(f"[validity-debug] Container run exception: {e}")
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
                
        return success_load and executed

    def validate_torch(self, pt_bytes: bytes, trigger_file: str) -> bool:
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

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                if proc.returncode != 0 and "relabeling" in (proc.stderr or "").lower():
                    # Some podman/SELinux setups refuse to relabel system /tmp
                    # with :Z ("SELinux relabeling of /tmp is not allowed").
                    # Retry the same mount without the relabel flag (the
                    # trigger path is baked into the pickle as an absolute
                    # /tmp/... path, so the mount target must stay /tmp).
                    retry = [
                        self.backend, "run", "--rm",
                        "--security-opt", "label=disable",
                        "-v", f"{temp_dir}:/tmp",
                        self.image, "python3.13", "-c", container_script
                    ]
                    proc = subprocess.run(retry, capture_output=True, text=True, timeout=self.timeout)
                success_load = (proc.returncode == 0)
                if not success_load:
                    print(f"[validity-debug] Container failed with code {proc.returncode}")
                    print(f"[validity-debug] Container stdout: {proc.stdout}")
                    print(f"[validity-debug] Container stderr: {proc.stderr}")
            except (OSError, subprocess.TimeoutExpired) as e:
                print(f"[validity-debug] Container run exception: {e}")
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
                
        return success_load and executed

    def validate_gguf(self, gguf_bytes: bytes) -> bool:
        """Confirm that a GGUF artifact parses with the reference reader
        (ggml-org/gguf) inside the Task-3 sandbox.

        Thin wrapper over :func:`pipeline.scanners.run_scan` (the single path
        that knows the GGUF reference-oracle isolation flags); interprets the
        loader's ``summary.load_ok``.

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
            return False

        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(gguf_bytes)
            host_path = f.name

        try:
            out, err = run_scan(
                self.backend, "localhost/regenbench/gguf:latest", host_path,
                timeout=self.timeout, gguf_ref=True)
            if err or out is None:
                print("[validity-debug] gguf oracle error:", (err or "")[:200])
                return False
            ok = bool((out.get("summary") or {}).get("load_ok"))
        finally:
            try:
                os.remove(host_path)
            except OSError:
                pass
        return ok
