"""Fail-safe sanitization of pickle streams embedded in model artifacts."""

from __future__ import annotations

import io
import zipfile

from pipeline.opcodes import OPCODES_BY_NAME, parse_pickle
from pipeline.registry import is_dangerous


class PickleSanitizer:
    """Rewrite known dangerous callable references without unpickling data."""

    SAFE_REPLACEMENTS: dict[tuple[str, str], tuple[str, str]] = {
        ("os", "system"): ("builtins", "len"),
        ("subprocess", "Popen"): ("builtins", "len"),
        ("builtins", "eval"): ("builtins", "len"),
        ("builtins", "exec"): ("builtins", "len"),
        ("IPython.utils.process", "system"): ("builtins", "len"),
    }

    @staticmethod
    def _string_value(op_name: str, arg: bytes) -> str | None:
        if op_name == "SHORT_BINUNICODE":
            return arg[1:].decode("utf-8")
        if op_name == "BINUNICODE":
            return arg[4:].decode("utf-8")
        if op_name == "UNICODE":
            return arg.rstrip(b"\r\n").decode("utf-8")
        if op_name == "SHORT_BINSTRING":
            return arg[1:].decode("latin1")
        if op_name == "BINSTRING":
            return arg[4:].decode("latin1")
        return None

    @staticmethod
    def _encode_string(op_name: str, value: str) -> bytes:
        raw = value.encode("utf-8")
        if op_name == "SHORT_BINUNICODE" and len(raw) <= 255:
            return bytes([len(raw)]) + raw
        if op_name == "BINUNICODE":
            return len(raw).to_bytes(4, "little") + raw
        if op_name == "UNICODE":
            return raw + b"\n"
        raise ValueError(f"cannot safely encode replacement as {op_name}")

    def _replacement(self, module: str, name: str) -> tuple[str, str]:
        replacement = self.SAFE_REPLACEMENTS.get((module, name))
        if replacement is None:
            raise ValueError(f"no safe replacement for dangerous callable {module}.{name}")
        return replacement

    def sanitize(self, pkl_bytes: bytes, on_unrepairable: str = "raise") -> bytes:
        """Return a reconstructed stream with supported dangerous references replaced.

        ``strip`` produces a benign empty dictionary when a stream cannot be
        repaired. It never removes arbitrary opcode ranges from an untrusted
        stream.
        """
        if on_unrepairable not in {"raise", "strip"}:
            raise ValueError("on_unrepairable must be 'raise' or 'strip'")
        try:
            parsed = parse_pickle(pkl_bytes)
            changed: dict[int, bytes] = {}
            for i, (op, arg) in enumerate(parsed):
                if op.name in {"GLOBAL", "INST"}:
                    fields = arg.decode("latin1").split("\n")
                    if len(fields) < 2:
                        raise ValueError(f"malformed {op.name} operand")
                    module, name = fields[0], fields[1]
                    if is_dangerous(module, name):
                        new_module, new_name = self._replacement(module, name)
                        changed[i] = f"{new_module}\n{new_name}\n".encode("latin1")
                elif op.name == "STACK_GLOBAL":
                    refs: list[tuple[int, str]] = []
                    for j in range(i - 1, -1, -1):
                        value = self._string_value(parsed[j][0].name, parsed[j][1])
                        if value is not None:
                            refs.append((j, value))
                            if len(refs) == 2:
                                break
                        elif parsed[j][0].name not in {"MEMOIZE", "BINPUT", "LONG_BINPUT"}:
                            break
                    if len(refs) == 2:
                        name_idx, name = refs[0]
                        module_idx, module = refs[1]
                        if is_dangerous(module, name):
                            new_module, new_name = self._replacement(module, name)
                            module_op = parsed[module_idx][0].name
                            name_op = parsed[name_idx][0].name
                            changed[module_idx] = self._encode_string(module_op, new_module)
                            changed[name_idx] = self._encode_string(name_op, new_name)

            rebuilt = b"".join(
                op.code + (changed[i] if i in changed else arg)
                for i, (op, arg) in enumerate(parsed)
            )
            parse_pickle(rebuilt)
            return rebuilt
        except Exception:
            if on_unrepairable == "strip":
                return b"\x80\x04}\x94."
            raise

    def sanitize_torch(self, pt_bytes: bytes, on_unrepairable: str = "raise") -> bytes:
        """Sanitize ``data.pkl`` in a Torch ZIP without deserializing it."""
        try:
            source = zipfile.ZipFile(io.BytesIO(pt_bytes))
            names = [name for name in source.namelist() if name.endswith("data.pkl")]
            if not names:
                raise ValueError("Torch archive contains no data.pkl")
            target = names[0]
            output = io.BytesIO()
            with source, zipfile.ZipFile(output, "w") as dest:
                for info in source.infolist():
                    data = source.read(info.filename)
                    if info.filename == target:
                        data = self.sanitize(data, on_unrepairable)
                    dest.writestr(info, data)
            return output.getvalue()
        except Exception:
            if on_unrepairable == "strip":
                raise ValueError("cannot strip an unrepairable Torch archive safely")
            raise
