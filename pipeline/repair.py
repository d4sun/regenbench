"""Model repair wrapper built on static sanitization and quarantine policy."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from pipeline.opcodes import parse_pickle
from pipeline.registry import is_dangerous
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

    def __init__(self, sanitizer: PickleSanitizer | None = None, triage_log: str | None = None):
        self.sanitizer = sanitizer or PickleSanitizer()
        self.triage_log = triage_log or "data/repair_triage.jsonl"

    def _triage_failure(self, source: str, data: bytes, exc: Exception) -> dict:
        """P3.1: log (family, callable, registry miss vs splice vs nested) for FN."""
        try:
            parsed = parse_pickle(data)
            callables = []
            for op, arg in parsed:
                if op.name in {"GLOBAL", "INST"}:
                    try:
                        mod, name = arg.decode("latin1").split("\n")[:2]
                        if is_dangerous(mod, name):
                            callables.append(f"{mod}.{name}")
                    except Exception:
                        pass
            # Detect patterns
            has_splice = self.sanitizer._has_splice_transport(parsed) if hasattr(self.sanitizer, "_has_splice_transport") else False
            has_chain = self.sanitizer._has_indirect_chain(parsed) if hasattr(self.sanitizer, "_has_indirect_chain") else False
            # Check registry miss
            registry_miss = []
            for c in callables:
                mod, name = c.split(".", 1) if "." in c else (c, "")
                if not is_dangerous(mod, name):
                    registry_miss.append(c)
            # Infer family from callable
            family = "unknown"
            if any("IPython" in c for c in callables):
                family = "pypi_injected"
            elif any("runstring" in c for c in callables):
                family = "external"
            elif has_chain:
                family = "indirect_chain"
            elif any("OrderedDict" in c for c in callables):
                family = "overwritten"
            elif callables:
                family = "gadget"
            triage = {
                "source": source,
                "family": family,
                "callables": callables,
                "has_splice": has_splice,
                "has_chain": has_chain,
                "registry_miss": registry_miss,
                "reason": str(exc),
                "category": "splice_evades_string_match" if has_splice else "nested_pickle_shallow_scan" if has_chain else "missing_registry_entry" if registry_miss else "other",
            }
            # Append to log
            try:
                os.makedirs(os.path.dirname(self.triage_log) or ".", exist_ok=True)
                with open(self.triage_log, "a") as f:
                    f.write(json.dumps(triage) + "\n")
            except Exception:
                pass
            return triage
        except Exception:
            return {"source": source, "reason": str(exc), "category": "triage_failed"}

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
            triage = self._triage_failure(source, data, exc)
            return RepairResult(source, None, False, True, f"unrepairable: {exc} | triage={triage['category']}:{triage['family']}:{','.join(triage.get('callables', [])[:2])}")

        os.makedirs(output_dir, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()[:12]
        destination = os.path.join(output_dir, f"{Path(source).name}.{digest}.safe{suffix}")
        Path(destination).write_bytes(repaired)
        return RepairResult(source, destination, repaired != data, False, "sanitized")
