"""Scanner/oracle image registry and the container-launch primitive.

Runs the T0.3-T0.7 containers against an artifact and returns the parsed
[unified verdict schema](../docs/verdict-schema.md) JSON. All images reuse the
same invocation: the host artifact is mounted read-only at `/artifact` and its
path is passed as argv, so payloads cannot write the host.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Optional

# Static analysis panel (pkl-format capable) + the behavioral oracle.
# kind: "panel" runs on any artifact; "oracle" adds a decision_score signal.
# P5.2: exts for format-aware routing (fixes Fickling 100% FP on GGUF).
SCANNERS: dict[str, dict] = {
    "picklescan": {"image": "regenbench/picklescan", "kind": "panel", "exts": {".pkl", ".pt", ".pth", ".bin", ".onnx", ".h5", ".hdf5", ".joblib", ".model"}},
    "modelscan": {"image": "regenbench/modelscan", "kind": "panel", "exts": {".pkl", ".pt", ".pth", ".bin", ".onnx", ".h5", ".hdf5", ".joblib", ".model", ".gguf"}},
    "fickling": {"image": "regenbench/fickling", "kind": "panel", "exts": {".pkl", ".pt", ".pth", ".bin"}},
    "modeltracer": {"image": "regenbench/modeltracer", "kind": "panel", "exts": {".pkl", ".pt", ".pth", ".bin"}},
    "dynahug": {"image": "regenbench/dynahug", "kind": "oracle", "exts": {".pt", ".pth", ".bin"}, "mount_only_pt": True},
    "ggufref": {"image": "regenbench/gguf", "kind": "oracle", "exts": {".gguf"}, "mount_only_gguf": True},
}

# Artifact formats sent to the behavioral oracle. The DynaHug oracle (T0.7)
# deserializes torch checkpoints; non-torch inputs cannot be loaded and so
# yield no behavioral signal. The ggufref oracle (Task 3) parses GGUF files
# with the ggml-org reference reader and renders chat templates through the
# unsandboxed Jinja2 path (CVE-2024-34359).
ORACLE_EXTENSIONS = {".pt", ".pth", ".bin"}
GGUF_EXTENSIONS = {".gguf"}

# If set, the dynahug container mounts this directory and points
# DYNAHUG_MODEL_DIR at it, so a locally-recalibrated OCSVM (fit on this
# environment's strace profiles) is used instead of the pretrained upstream
# model. See scripts/calibrate_oracle.py.
ORACLE_MODEL_DIR_ENV = "REGENBENCH_ORACLE_MODEL_DIR"


def default_backend(prefer: str = "podman") -> str:
    """Pick a usable container runtime, preferring ``prefer`` when present.

    podman was the original assumption; docker-only hosts (the lab baseline)
    should not need an explicit --backend on every command. Falls back to
    docker when podman is not on PATH, and to ``prefer`` otherwise.
    """
    import shutil
    if shutil.which(prefer) is not None:
        return prefer
    if shutil.which("docker") is not None:
        return "docker"
    return prefer


@dataclass
class ScanResult:
    """Outcome of running one scanner image on one artifact."""

    scanner: str
    artifact: str
    verdict: Optional[str]
    exit_code: Optional[int]
    decision_score: Optional[float] = None
    findings: list = field(default_factory=list)
    matched_rules: list = field(default_factory=list)
    error: Optional[str] = None
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None and self.verdict is not None


def full_image(image: str, tag: str) -> str:
    return f"{image}{tag}"


def run_scan(backend: str, image_full: str, src: str,
             timeout: int = 300,
             oracle_model_dir: str | None = None) -> tuple[Optional[dict], Optional[str]]:
    """Run `image_full` on the host file/dir `src`; return (parsed_json, error).
    `image_full` is the fully-qualified container id (image[:tag]).
    `oracle_model_dir` (or $REGENBENCH_ORACLE_MODEL_DIR) mounts a recalibrated
    DynaHug model dir and sets DYNAHUG_MODEL_DIR inside the container."""
    cmd = [
        backend, "run", "--rm",
        "-v", f"{os.path.abspath(src)}:/artifact:ro,z",
    ]
    # Container-side timeout via conmon is a podman feature; docker run has no
    # --timeout flag and rejects it ("unknown flag"). The host-side subprocess
    # timeout below bounds the docker path instead.
    if backend == "podman":
        cmd.insert(2, "--timeout")
        cmd.insert(3, str(timeout))
    model_dir = oracle_model_dir or os.environ.get(ORACLE_MODEL_DIR_ENV)
    if model_dir:
        if not os.path.isdir(model_dir):
            return None, f"oracle model dir does not exist: {model_dir}"
        cmd += ["-e", "DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated",
                "-v", f"{os.path.abspath(model_dir)}:/opt/dynahug/recalibrated:ro,z"]
    cmd += [image_full, "/artifact"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 15)
    except subprocess.TimeoutExpired:
        return None, f"timeout running {image_full} on {src}"
    except OSError as exc:
        return None, f"could not run {backend}: {exc}"
    try:
        out = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return None, (proc.stdout or proc.stderr or "").strip()[-400:]
    return out, None


def build_images(spec: dict[str, dict], tag: str,
                 overrides: list[str] | None = None) -> dict[str, str]:
    """Resolve the image map (scanner -> fully-qualified image:tag).
    Overrides `name=image:tag` (e.g. published registries) are used verbatim;
    otherwise the default tag is appended."""
    images = {name: spec[name]["image"] for name in spec}
    for kv in overrides or []:
        key, _, val = kv.partition("=")
        if key in images and val:
            images[key] = val  # override includes its own tag
    return {name: full_image(img, tag) if ":" not in img else img
            for name, img in images.items()}


def expected_scanners(spec: dict[str, dict] | None = None,
                      selected: list[str] | None = None) -> dict[str, dict]:
    if spec is None:
        spec = SCANNERS
    if selected:
        return {k: v for k, v in spec.items() if k in selected}
    return dict(spec)


def get_scanner_version(backend: str, image: str) -> str:
    """Get the image ID/hash for a scanner image using podman/docker inspect.
    
    Returns the first 12 characters of the image ID, or 'unknown' on failure.
    """
    import subprocess
    try:
        inspect = subprocess.run(
            [backend, "inspect", image, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=30
        )
        if inspect.returncode == 0:
            return inspect.stdout.strip()[:12]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "unknown"


def pull_scanner_image(backend: str, image: str) -> tuple[bool, str]:
    """Pull the latest scanner image and return (success, version)."""
    import subprocess
    try:
        print(f"[scanner] Pulling {image}...")
        result = subprocess.run([backend, "pull", image], capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            version = get_scanner_version(backend, image)
            print(f"  {image}: {version}")
            return True, version
        else:
            print(f"  {image}: pull failed - {result.stderr[:200]}")
            return False, "error"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"  {image}: pull error - {e}")
        return False, "error"
