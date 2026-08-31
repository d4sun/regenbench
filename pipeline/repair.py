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
    tag: str = "sanitized"          # sanitized | quarantined
    loadable: bool | None = None    # weights_only=True loadable (torch only)


class ModelRepair:
    """Repair supported pickle/Torch artifacts into a separate output path."""

    def __init__(self, sanitizer: PickleSanitizer | None = None, triage_log: str | None = None,
                 backend: str | None = None):
        self.sanitizer = sanitizer or PickleSanitizer()
        self.triage_log = triage_log or "data/repair_triage.jsonl"
        if backend is None:
            import shutil
            self.backend = "podman" if shutil.which("podman") else ("docker" if shutil.which("docker") else None)
        else:
            self.backend = backend

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

    def _reserialize_in_container(self, source_path: str, output_dir: str,
                                  timeout: int = 120) -> tuple[str | None, bool | None, str]:
        """Re-save a sanitized torch file inside regenbench/base.

        The sanitized file has no dangerous references (payload tail removed), so
        ``torch.load(weights_only=False)`` is safe. ``torch.save`` normalizes to
        torch's proto-2 default, making the result ``torch.load(weights_only=True)``
        loadable regardless of the seed's original pickle protocol (e.g. proto-5
        checkpoints with SHORT_BINUNICODE that torch's weights_only pre-scan
        rejects). Returns (host_out_path, weights_only_loadable, status).
        """
        import subprocess
        import tempfile
        import shutil
        if not self.backend:
            return None, None, "no-container-backend"
        td = tempfile.mkdtemp(prefix="repair-reser-")
        try:
            artifact = os.path.join(td, "artifact.pt")
            shutil.copy2(source_path, artifact)
            out_dir = os.path.join(td, "out")
            os.makedirs(out_dir, exist_ok=True)
            script = (
                "import torch,sys\n"
                "try:\n"
                "    obj=torch.load('/in/artifact.pt', weights_only=False, map_location='cpu')\n"
                "except Exception as e:\n"
                "    print('REPAIR_LOAD_FAIL:', str(e)[:200])\n"
                "    sys.exit(2)\n"
                "if isinstance(obj, dict):\n"
                "    torch.save(obj, '/out/safe.pt')\n"
                "    try:\n"
                "        torch.load('/out/safe.pt', weights_only=True, map_location='cpu')\n"
                "        print('REPAIR_OK')\n"
                "    except Exception as e:\n"
                "        print('REPAIR_SAVED_BUT_NOT_WO:', str(e)[:200])\n"
                "else:\n"
                "    print('REPAIR_NOT_DICT')\n"
            )
            cmd = [
                self.backend, "run", "--rm",
                "-v", f"{artifact}:/in/artifact.pt:ro,z",
                "-v", f"{out_dir}:/out:z",
                "regenbench/base:latest",
                "python3.13", "-c", script,
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                return None, None, "container-timeout"
            out_text = (proc.stdout or "") + (proc.stderr or "")
            safe_path = os.path.join(out_dir, "safe.pt")
            if not os.path.exists(safe_path):
                return None, None, out_text.strip()[-300:]
            dest = os.path.join(output_dir, os.path.basename(source_path) + ".reserialized.pt")
            shutil.copy2(safe_path, dest)
            wo_ok = "REPAIR_OK" in out_text
            status = "sanitized" if wo_ok else ("reserialized-not-wo" if "SAVED_BUT_NOT_WO" in out_text else "other")
            return dest, wo_ok, status
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def repair_file(self, source: str, output_dir: str, reserialize: bool = True) -> RepairResult:
        if not os.path.isfile(source):
            return RepairResult(source, None, False, True, "source file not found", "quarantined")
        data = Path(source).read_bytes()
        suffix = Path(source).suffix.lower()
        try:
            if suffix in {".pkl", ".pickle"}:
                repaired = self.sanitizer.sanitize(data)
            elif suffix in {".pt", ".pth", ".bin"}:
                repaired = self.sanitizer.sanitize_torch(data)
            else:
                return RepairResult(source, None, False, True, f"unsupported format: {suffix}", "quarantined")
        except Exception as exc:
            triage = self._triage_failure(source, data, exc)
            return RepairResult(
                source, None, False, True,
                f"unrepairable: {exc} | triage={triage['category']}:{triage['family']}:{','.join(triage.get('callables', [])[:2])}",
                "quarantined", False)

        os.makedirs(output_dir, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()[:12]
        destination = os.path.join(output_dir, f"{Path(source).name}.{digest}.safe{suffix}")
        Path(destination).write_bytes(repaired)

        # A.5: for torch artifacts, reserialize in-container so the repaired file
        # is torch.load(weights_only=True) loadable; else tag loadability by
        # static parse (raw pickle has no torch requirement).
        if suffix in {".pt", ".pth", ".bin"} and reserialize:
            reser_path, loadable, status = self._reserialize_in_container(destination, output_dir)
            if reser_path:
                os.remove(destination)  # superseded by reserialized file
                destination = reser_path
            tag = "sanitized" if loadable else ("quarantined" if reser_path is None else "quarantined")
            return RepairResult(source, destination, True, tag == "quarantined",
                                f"{status}" if not loadable else "sanitized", tag, loadable)
        # Raw pickle: sanitized if no dangerous remains (always parseable)
        return RepairResult(source, destination, repaired != data, False, "sanitized", "sanitized", True)
