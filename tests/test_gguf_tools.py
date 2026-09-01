"""GGUF builder + attack-family tests (Phase 3 of GGUF remediation).

Host-side tests assert the builder emits structurally valid GGUF v3 for the
benign template and all 7 attack families. Docker-gated tests exercise the
canonical (reference-reader) classification: benign parses, all 6 vellaveto
malformed families are rejected, and the SSTI payload loads but executes.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline import scanners  # noqa: E402
from pipeline.gguf_tools import (  # noqa: E402
    GGUF_ATTACKS,
    GGUF_ATTACK_LABELS,
    _OVERFLOW_SENTINEL,
    benign_gguf,
    generate_candidate_gguf,
)

GGUF_MAGIC = b"GGUF"


def _header(data: bytes) -> tuple[int, int, int]:
    """(version, tensor_count, kv_count) from the fixed 24-byte header."""
    assert data[:4] == GGUF_MAGIC
    return struct.unpack_from("<IQQ", data, 4)


class TestGgufBuilder(unittest.TestCase):
    def test_benign_gguf_header(self):
        data = benign_gguf()
        version, tensor_count, kv_count = _header(data)
        self.assertEqual(version, 3)
        self.assertEqual(tensor_count, 0)
        self.assertGreaterEqual(kv_count, 13)

    def test_benign_gguf_with_chat_template(self):
        data = benign_gguf(chat_template="{{ x }}")
        self.assertIn(b"tokenizer.chat_template", data)

    def test_nkv_overflow_sentinel(self):
        version, tensor_count, kv_count = _header(generate_candidate_gguf("nkv_overflow"))
        self.assertEqual(version, 3)
        self.assertEqual(tensor_count, 0)
        self.assertEqual(kv_count, _OVERFLOW_SENTINEL)

    def test_ntensors_overflow_sentinel(self):
        version, tensor_count, kv_count = _header(generate_candidate_gguf("ntensors_overflow"))
        self.assertEqual(version, 3)
        self.assertEqual(tensor_count, _OVERFLOW_SENTINEL)
        self.assertEqual(kv_count, 0)

    def test_version_zero(self):
        version, tensor_count, kv_count = _header(generate_candidate_gguf("version_zero"))
        self.assertEqual(version, 0)

    def test_string_overflow_first_key_len_sentinel(self):
        data = generate_candidate_gguf("string_overflow")
        version, tensor_count, kv_count = _header(data)
        self.assertEqual(kv_count, 1)
        # first KV key length prefix at offset 24
        self.assertEqual(struct.unpack_from("<Q", data, 24)[0], _OVERFLOW_SENTINEL)

    def test_path_traversal_contains_traversal_name(self):
        data = generate_candidate_gguf("path_traversal")
        self.assertIn(b"../../../etc/passwd", data)

    def test_negative_dims_contains_signed_negative_dims(self):
        data = generate_candidate_gguf("negative_dims")
        self.assertIn(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF), data)

    def test_ssti_contains_gadget_and_trigger(self):
        data = generate_candidate_gguf("ssti_chat_template", "/tmp/trig_x.txt")
        version, tensor_count, kv_count = _header(data)
        self.assertEqual(version, 3)
        self.assertIn(b"popen", data)
        self.assertIn(b"__class__", data)
        self.assertIn(b"/tmp/trig_x.txt", data)

    def test_all_attacks_emit_gguf_magic(self):
        for fam in GGUF_ATTACKS:
            with self.subTest(fam=fam):
                self.assertTrue(generate_candidate_gguf(fam).startswith(GGUF_MAGIC))


def _have_docker_and_gguf_image() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                             capture_output=True, text=True, timeout=30)
        return ("regenbench/gguf:latest" in out.stdout
                or "localhost/regenbench/gguf:latest" in out.stdout)
    except Exception:  # noqa: BLE001
        return False


@unittest.skipUnless(_have_docker_and_gguf_image(),
                     "docker + regenbench/gguf image required")
class TestGgufReferenceClassification(unittest.TestCase):
    """Canonical (reference-reader) classification through run_scan."""

    def _classify(self, data: bytes) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            out, err = scanners.run_scan("docker", "regenbench/gguf", path,
                                         timeout=120, gguf_ref=True)
        finally:
            os.remove(path)
        self.assertIsNone(err, err)
        return out

    def test_benign_roundtrip_load_ok(self):
        out = self._classify(benign_gguf())
        self.assertTrue((out.get("summary") or {}).get("load_ok"))
        self.assertEqual(out.get("verdict"), "benign")

    def test_all_malformed_families_rejected(self):
        for fam in GGUF_ATTACKS:
            if fam.startswith("ssti_"):
                continue  # SSTI families load OK (render-time / exec-time attacks)
            with self.subTest(fam=fam):
                out = self._classify(generate_candidate_gguf(fam))
                self.assertFalse((out.get("summary") or {}).get("load_ok"),
                                 f"{fam} must be rejected by the reference reader")
                self.assertEqual(out.get("verdict"), "malicious")

    def test_ssti_loads_but_triggers(self):
        out = self._classify(generate_candidate_gguf("ssti_chat_template", "/tmp/trig_t.txt"))
        self.assertTrue((out.get("summary") or {}).get("load_ok"))
        self.assertEqual(out.get("verdict"), "malicious")
        self.assertTrue(any(f.endswith("triggered") for f in out.get("findings", [])))


if __name__ == "__main__":
    unittest.main()