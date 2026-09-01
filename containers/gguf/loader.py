#!/usr/bin/env python3
"""GGUF reference loader used by the Task-3 oracle sandbox.

Parses a .gguf artifact with the reference reader (ggml-org/gguf) and, when a
``tokenizer.chat_template`` is present, renders it through Jinja2 exactly like
``llama-cpp-python``'s ``Jinja2ChatFormatter`` (the unsandboxed render path of
CVE-2024-34359 "Llama Drama"). Also performs a light header inspection so the
wrapper can attribute each malformed-header attack family.

Emits one JSON object on stdout:
  {
    "load_ok": bool,
    "reference_error": str | null,     # GGUFReader failure, if any
    "header": {magic, version, tensor_count, kv_count},
    "malformed": [str],                # detected malformed-header attack ids
    "chat_template_present": bool,
    "ssti_suspicious": [str],          # static SSTI signals in the template
    "rendered": bool,                  # chat template was rendered
    "render_error": str | null,
    "triggered": bool                  # template render created the trigger file
  }
"""

import json
import os
import sys
import struct


# Suspicious Jinja2/SSTI signals (JFrog's static-analysis keyword list, plus
# the concrete gadget family used by the retr0reg PoC).
SSTI_SIGNALS = [
    "__class__", "__globals__", "__subclasses__", "__builtins__",
    "__import__", "os.system", "os.popen", "popen", "subprocess",
    "system(", "eval(", "exec(", "_module",
]

# KV-count / tensor-count sentinel used by the vellaveto PoC (2^63-1).
_OVERFLOW_SENTINEL = 0x7FFFFFFFFFFFFFFF


def parse_header(data: bytes) -> dict:
    """Read the fixed GGUF header (magic, version, tensor_count, kv_count)."""
    if len(data) < 4:
        return {"magic": None, "version": None, "tensor_count": None, "kv_count": None}
    if data[:4] != b"GGUF":
        return {"magic": data[:4].hex(), "version": None, "tensor_count": None, "kv_count": None}
    if len(data) < 24:
        version, tensor_count, kv_count = None, None, None
    else:
        version, tensor_count, kv_count = struct.unpack_from("<IQQ", data, 4)
    return {"magic": "GGUF", "version": version, "tensor_count": tensor_count,
            "kv_count": kv_count}


def classify_malformed(data: bytes, header: dict) -> list[str]:
    """Attribute the vellaveto malformed-header attack families.

    Header-level families (version/nkv/ntensors/string) are read directly from
    the size prefixes. Tensor-level families (path-traversal, negative dims)
    are attributed from a structured walk of the tensor-info section, so that
    ordinary vocabulary tokens containing ``..`` (common in real tokenizers)
    do not cause false positives.
    """
    found: list[str] = []
    if header.get("version") == 0:
        found.append("version-zero")
    if header.get("kv_count") == _OVERFLOW_SENTINEL:
        found.append("nkv-overflow")
    if header.get("tensor_count") == _OVERFLOW_SENTINEL:
        found.append("ntensors-overflow")
    # String-length overflow: first KV key length prefix == 2^63-1 with short
    # payload (matches the 37-byte PoC layout: 24-byte header + sentinel).
    if len(data) >= 32 and header.get("kv_count") not in (None, 0):
        key_len = struct.unpack_from("<Q", data, 24)[0]
        if key_len == _OVERFLOW_SENTINEL:
            found.append("string-overflow")

    tensors = _tensor_section(data)
    if tensors is not None:
        for name, dims in tensors:
            if ".." in name:
                found.append("path-traversal")
                break
        for _name, dims in tensors:
            if any(d >= 1 << 63 for d in dims):
                found.append("negative-dims")
                break
    return found


def _tensor_section(data: bytes) -> list[tuple[str, list[int]]] | None:
    """Best-effort structured walk of the tensor-info section.

    Returns (name, dims) per tensor, or None if the stream cannot be walked
    (in which case header-level families already carry the classification).
    Mirrors the spec layout used by the reference reader (offset 24 header,
    then [u64 len][bytes] keys, u32 value-type + typed values, then
    [u64 len][bytes] tensor names with u32 n_dims + u64 dims).
    """
    if len(data) < 24 or data[:4] != b"GGUF":
        return None
    version, tensor_count, kv_count = struct.unpack_from("<IQQ", data, 4)
    # Cap kv_count so a crafted large-but-sub-sentinel count cannot force a
    # long CPU walk (mirrors the host-side cap the old parse_gguf applied).
    if (version not in (2, 3) or kv_count >= _OVERFLOW_SENTINEL
            or tensor_count >= _OVERFLOW_SENTINEL or kv_count > 100_000):
        return None
    pos = 24
    for _ in range(kv_count):
        key, pos = _walk_string(data, pos)
        if key is None or pos is None:
            return None
        vtype, pos = _walk_u32(data, pos)
        if vtype is None or pos is None:
            return None
        pos = _walk_value(data, pos, vtype)
        if pos is None:
            return None
    out = []
    for _ in range(tensor_count):
        name, pos = _walk_string(data, pos)
        if name is None or pos is None:
            return None
        n_dims, pos = _walk_u32(data, pos)
        if n_dims is None or pos is None:
            return None
        dims = []
        for _ in range(n_dims):
            d, pos = _walk_u64(data, pos)
            if d is None or pos is None:
                return None
            dims.append(d)
        _gtype, pos = _walk_u32(data, pos)
        if _gtype is None or pos is None:
            return None
        _offset, pos = _walk_u64(data, pos)
        if _offset is None or pos is None:
            return None
        out.append((name, dims))
    return out


def _walk_string(data: bytes, pos: int) -> tuple[str | None, int | None]:
    if pos + 8 > len(data):
        return None, None
    slen = struct.unpack_from("<Q", data, pos)[0]
    pos += 8
    if slen > 1 << 20 or pos + slen > len(data):
        return None, None
    raw = data[pos:pos + slen]
    return raw.decode("utf-8", "replace"), pos + slen


def _walk_u32(data: bytes, pos: int) -> tuple[int | None, int | None]:
    if pos + 4 > len(data):
        return None, None
    return struct.unpack_from("<I", data, pos)[0], pos + 4


def _walk_u64(data: bytes, pos: int) -> tuple[int | None, int | None]:
    if pos + 8 > len(data):
        return None, None
    return struct.unpack_from("<Q", data, pos)[0], pos + 8


def _walk_value(data: bytes, pos: int, vtype: int) -> int | None:
    """Skip a metadata value (pos points just past the type byte)."""
    if vtype == 8:  # GGUFValueType.STRING
        _s, pos = _walk_string(data, pos)
        return pos
    if vtype == 9:  # GGUFValueType.ARRAY = [u32 elem][u64 len][elems]
        elem_type, pos = _walk_u32(data, pos)
        if elem_type is None or pos is None:
            return None
        count, pos = _walk_u64(data, pos)
        if count is None or pos is None or count > 1 << 20:
            return None
        for _ in range(count):
            if elem_type == 8:
                _s, pos = _walk_string(data, pos)
            else:
                size = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
                        10: 8, 11: 8, 12: 8}.get(elem_type, 8)
                pos = None if pos is None else pos + size
            if pos is None:
                return None
        return pos
    size = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}.get(vtype)
    return None if size is None or pos + size > len(data) else pos + size


def parse_with_reference(data: bytes):
    """Parse with the ggml-org reference reader in a single pass.

    Returns (load_ok, reference_error, chat_template): the reference reader is
    invoked once and the ``tokenizer.chat_template`` string is extracted from
    the same reader object (previously parsed twice). ``chat_template`` is
    None when absent or when parsing failed.
    """
    from gguf import GGUFReader
    path = _materialize(data)
    reader = None
    try:
        reader = GGUFReader(path)
        ok, ref_err = True, None
    except Exception as e:  # noqa: BLE001  -- any reader failure is the signal
        ok, ref_err = False, f"{type(e).__name__}: {str(e)[:300]}"
    template = None
    if reader is not None:
        field = reader.fields.get("tokenizer.chat_template")
        if field is not None:
            try:
                # STRING values are exposed as numpy uint8 arrays by the
                # reference reader; decode them like llama-cpp-python does.
                val = field.contents()
                if isinstance(val, bytes):
                    template = val.decode("utf-8", errors="ignore")
                elif hasattr(val, "tobytes"):
                    template = val.tobytes().decode("utf-8", errors="ignore")
                else:
                    template = str(val)
            except Exception:  # noqa: BLE001
                template = None
    _cleanup(path)
    return ok, ref_err, template


def _materialize(data: bytes) -> str:
    """GGUFReader only accepts a filesystem path; write the bytes to /tmp."""
    import tempfile
    fd, path = tempfile.mkstemp(prefix="ggufref-", suffix=".gguf")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _cleanup(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def render_chat_template(template: str) -> str:
    """Replicate llama-cpp-python's Jinja2ChatFormatter.render (unsandboxed)."""
    import jinja2
    env = jinja2.Environment(
        loader=jinja2.BaseLoader(),
        trim_blocks=True,
        lstrip_blocks=True,
    ).from_string(template)
    return env.render(
        messages=[{"role": "user", "content": "regenbench"}],
        eos_token="</s>",
        bos_token="<s>",
        raise_exception=lambda message: (_ for _ in ()).throw(ValueError(message)),
        add_generation_prompt=True,
        functions=None,
        function_call=None,
        tools=None,
        tool_choice=None,
    )


def _discover_trigger(template: str) -> str | None:
    """Find the file a payload intends to write (``popen("touch <path>")``),
    so the loader can detect execution without an externally supplied path."""
    import re
    m = re.search(r'popen\s*\(\s*["\']touch\s+(\S+)["\']', template)
    return m.group(1) if m else None


def render_with_strace(template: str) -> dict:
    """Render the chat template under ``strace -f`` and report whether it
    executed (a child process was spawned: execve/execveat).

    Execution confirmation is **decoupled from static detection**: the render
    runs as a subprocess under strace inside the container (network-disabled,
    container-scoped tmpfs /tmp), and ``strace_executed`` is decided from the
    syscall log, independent of ggufref's SSTI_SIGNALS / trigger-file polling.
    This mirrors the pickle-side StraceOracle methodology.
    """
    import subprocess
    import tempfile

    tmpl = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".j2",
                                         delete=False, dir="/tmp") as f:
            f.write(template)
            tmpl = f.name
        log = "/tmp/gguf_strace.log"
        try:
            os.remove(log)
        except OSError:
            pass
        # Replicate loader.render_chat_template's exact llama-cpp-python context.
        code = (
            "import jinja2;"
            "t=jinja2.Environment(loader=jinja2.BaseLoader(),trim_blocks=True,"
            "lstrip_blocks=True).from_string(open('{tmpl}').read());"
            "t.render(messages=[{{'role':'user','content':'regenbench'}}],"
            "eos_token='</s>',bos_token='<s>',"
            "raise_exception=lambda m:(_ for _ in ()).throw(ValueError(m)),"
            "add_generation_prompt=True,functions=None,function_call=None,"
            "tools=None,tool_choice=None)"
        ).format(tmpl=tmpl)
        proc = subprocess.run(
            ["strace", "-f", "-e", "trace=execve,execveat,clone,openat,write",
             "-o", log, "python3.13", "-c", code],
            capture_output=True, text=True, timeout=25)
        log_text = ""
        try:
            with open(log) as f:
                log_text = f.read()
        except OSError:
            pass
        executed = ("execve(" in log_text or "execveat(" in log_text)
        return {"strace_executed": executed, "strace_log": log_text[-3000:],
                "rc": proc.returncode, "stderr": (proc.stderr or "")[-300:]}
    except Exception as e:  # noqa: BLE001
        return {"strace_executed": False, "strace_log": "",
                "error": f"{type(e).__name__}: {str(e)[:200]}"}
    finally:
        if tmpl:
            try:
                os.remove(tmpl)
            except OSError:
                pass


def main() -> int:
    args = [a for a in sys.argv[1:] if a.startswith("--")]
    strace_mode = "--strace-mode" in args
    target = next((a for a in sys.argv[1:] if not a.startswith("--")), "/artifact")
    trigger = None
    try:
        with open(target, "rb") as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({"load_ok": False, "reference_error": f"read: {e}",
                          "header": {}, "malformed": [], "triggered": False}))
        return 2

    header = parse_header(data)
    malformed = classify_malformed(data, header)
    ok, ref_err, template = parse_with_reference(data)

    suspicious = [s for s in SSTI_SIGNALS if template and s in template]

    triggered = False
    strace_executed = False
    strace_log = ""
    rendered = False
    render_error = None
    if template is not None:
        rendered = True
        trigger = trigger or _discover_trigger(template)
        if trigger and os.path.exists(trigger):
            try:
                os.remove(trigger)
            except OSError:
                pass
        try:
            if strace_mode:
                # Decoupled execution confirmation: render under strace and
                # observe process spawns; independent of SSTI_SIGNALS/trigger.
                sr = render_with_strace(template)
                strace_executed = sr.get("strace_executed", False)
                strace_log = sr.get("strace_log", "")
            else:
                render_chat_template(template)
            # Trigger-file poll (baseline SSTI detection path).
            import time
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if trigger and os.path.exists(trigger):
                    triggered = True
                    break
                time.sleep(0.05)
        except Exception as e:  # noqa: BLE001
            render_error = f"{type(e).__name__}: {str(e)[:200]}"

    print(json.dumps({
        "load_ok": ok,
        "reference_error": ref_err,
        "header": header,
        "malformed": malformed,
        "chat_template_present": template is not None,
        "ssti_suspicious": suspicious,
        "rendered": rendered,
        "render_error": render_error,
        "triggered": triggered,
        "strace_executed": strace_executed,
        "strace_log": strace_log,
    }))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())