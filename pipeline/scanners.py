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
SCANNERS: dict[str, dict] = {
    "picklescan": {"image": "regenbench/picklescan", "kind": "panel"},
    "modelscan": {"image": "regenbench/modelscan", "kind": "panel"},
    "fickling": {"image": "regenbench/fickling", "kind": "panel"},
    "modeltracer": {"image": "regenbench/modeltracer", "kind": "panel"},
    "dynahug": {"image": "regenbench/dynahug", "kind": "oracle", "mount_only_pt": True},
}

# Artifact formats sent to the behavioral oracle. The DynaHug oracle (T0.7)
# deserializes torch checkpoints; non-torch inputs cannot be loaded and so
# yield no behavioral signal.
ORACLE_EXTENSIONS = {".pt", ".pth"}


@dataclass
class ScanResult:
    """Outcome of running one scanner image on one artifact."""

    scanner: str
    artifact: str
    verdict: Optional[str]
    exit_code: Optional[int]
    decision_score: Optional[float] = None
    findings: list = field(default_factory=list)
    error: Optional[str] = None
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None and self.verdict is not None


def full_image(image: str, tag: str) -> str:
    return f"{image}{tag}"


def run_scan(backend: str, image_full: str, src: str,
             timeout: int = 300) -> tuple[Optional[dict], Optional[str]]:
    """Run `image_full` on the host file/dir `src`; return (parsed_json, error).
    `image_full` is the fully-qualified container id (image[:tag])."""
    cmd = [
        backend, "run", "--rm",
        "-v", f"{os.path.abspath(src)}:/artifact:ro,Z",
        image_full, "/artifact",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timeout running {image_full} on {src}"
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