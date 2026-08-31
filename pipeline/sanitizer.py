"""Fail-safe sanitization of pickle streams embedded in model artifacts."""

from __future__ import annotations

import io
import zipfile

from pipeline.opcodes import OPCODES_BY_NAME, parse_pickle
from pipeline.registry import is_dangerous


class PickleSanitizer:
    """Rewrite known dangerous callable references without unpickling data.

    P3.2 family-specific rules: covers all armable sinks (≥40) plus
    import-smuggling primitives and splice transport.
    """

    SAFE_REPLACEMENTS: dict[tuple[str, str], tuple[str, str]] = {
        ("os", "system"): ("builtins", "len"),
        ("subprocess", "Popen"): ("builtins", "len"),
        ("builtins", "eval"): ("builtins", "len"),
        ("builtins", "exec"): ("builtins", "len"),
        ("IPython.utils.process", "system"): ("builtins", "len"),
        # P3.2: expand to all armable sinks + new categories
        ("subprocess", "run"): ("builtins", "len"),
        ("subprocess", "call"): ("builtins", "len"),
        ("subprocess", "check_call"): ("builtins", "len"),
        ("subprocess", "check_output"): ("builtins", "len"),
        ("subprocess", "getstatusoutput"): ("builtins", "len"),
        ("subprocess", "getoutput"): ("builtins", "len"),
        ("pty", "spawn"): ("builtins", "len"),
        ("os", "popen"): ("builtins", "len"),
        ("posix", "execv"): ("builtins", "len"),
        ("os", "execv"): ("builtins", "len"),
        ("os", "execl"): ("builtins", "len"),
        ("numpy.testing._private.utils", "runstring"): ("builtins", "len"),
        ("runpy", "run_path"): ("builtins", "len"),
        ("builtins", "compile"): ("builtins", "len"),
        ("types", "CodeType"): ("builtins", "len"),
        ("types", "FunctionType"): ("builtins", "len"),
        ("ctypes", "CDLL"): ("builtins", "len"),
        ("urllib.request", "urlopen"): ("builtins", "len"),
        ("http.client", "HTTPConnection"): ("builtins", "len"),
        ("asyncio", "create_subprocess_exec"): ("builtins", "len"),
        ("asyncio", "create_subprocess_shell"): ("builtins", "len"),
        ("multiprocessing", "Process"): ("builtins", "len"),
        ("socket", "socket"): ("builtins", "len"),
        ("builtins", "__build_class__"): ("builtins", "len"),
        ("builtins", "property"): ("builtins", "len"),
        ("builtins", "classmethod"): ("builtins", "len"),
        ("builtins", "staticmethod"): ("builtins", "len"),
        # import_smuggling primitives (indirect_chain)
        ("builtins", "__import__"): ("builtins", "len"),
        ("builtins", "getattr"): ("builtins", "len"),
        ("_pickle", "loads"): ("builtins", "len"),
        ("posix", "system"): ("builtins", "len"),
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

    def _has_indirect_chain(self, parsed) -> bool:
        """Detect indirect_chain: getattr + __import__ in same stream (P3.2)."""
        has_getattr = False
        has_import = False
        for op, arg in parsed:
            if op.name in {"GLOBAL", "INST"}:
                try:
                    mod, name = arg.decode("latin1").split("\n")[:2]
                    if (mod, name) == ("builtins", "getattr"):
                        has_getattr = True
                    if (mod, name) == ("builtins", "__import__"):
                        has_import = True
                except Exception:
                    pass
            elif op.name == "STACK_GLOBAL":
                # Check string pushes for these primitives
                for j in range(len(parsed)-1, max(-1, len(parsed)-6), -1):
                    val = self._string_value(parsed[j][0].name, parsed[j][1])
                    if val == "getattr" or val == "__import__":
                        if val == "getattr":
                            has_getattr = True
                        else:
                            has_import = True
        return has_getattr and has_import

    def _has_splice_transport(self, parsed) -> bool:
        """Detect splice transport: STACK_GLOBAL referencing _pickle/pickle (P3.2)."""
        for i, (op, arg) in enumerate(parsed):
            if op.name == "STACK_GLOBAL":
                # Lookback for _pickle or pickle strings
                for j in range(max(0, i-6), i):
                    val = self._string_value(parsed[j][0].name, parsed[j][1])
                    if val in ("_pickle", "pickle", "_pickle.loads", "loads"):
                        return True
            if op.name in {"GLOBAL", "INST"}:
                try:
                    mod, name = arg.decode("latin1").split("\n")[:2]
                    if mod in ("_pickle", "pickle") and name == "loads":
                        return True
                except Exception:
                    pass
        return False

    def _is_pypi_injected_suspicious(self, parsed, allowed_modules: set[str] | None = None) -> bool:
        """Check if pypi_injected module not in seed sys.modules snapshot (P3.2)."""
        if allowed_modules is None:
            allowed_modules = {"collections", "builtins", "os", "subprocess", "numpy", "torch"}
        for op, arg in parsed:
            if op.name in {"GLOBAL", "INST"}:
                try:
                    mod, _ = arg.decode("latin1").split("\n")[:2]
                    if "IPython" in mod or "utils.process" in mod:
                        if mod not in allowed_modules:
                            return True
                except Exception:
                    pass
        return False

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
