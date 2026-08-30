"""Model repair wrapper built on static sanitization and quarantine policy."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from pipeline.sanitizer import PickleSanitizer


@dataclass
class RepairResult:
    source: str
    repaired: str | None
    changed: bool
    quarantined: bool
    reason: str


class ModelRepair:
    """Repair supported pickle/Torch artifacts into a separate output path."""

    def __init__(self, sanitizer: PickleSanitizer | None = None):
        self.sanitizer = sanitizer or PickleSanitizer()

    def repair_file(self, source: str, output_dir: str) -> RepairResult:
        if not os.path.isfile(source):
            return RepairResult(source, None, False, True, "source file not found")
        data = Path(source).read_bytes()
        suffix = Path(source).suffix.lower()
        try:
            if suffix in {".pkl", ".pickle"}:
                repaired = self.sanitizer.sanitize(data)
            elif suffix in {".pt", ".pth", ".bin"}:
                repaired = self.sanitizer.sanitize_torch(data)
            else:
                return RepairResult(source, None, False, True, f"unsupported format: {suffix}")
        except Exception as exc:
            return RepairResult(source, None, False, True, f"unrepairable: {exc}")

        os.makedirs(output_dir, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()[:12]
        destination = os.path.join(output_dir, f"{Path(source).name}.{digest}.safe{suffix}")
        Path(destination).write_bytes(repaired)
        return RepairResult(source, destination, repaired != data, False, "sanitized")
