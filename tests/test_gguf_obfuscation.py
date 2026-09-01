"""GGUF SSTI obfuscation tests (Phase B-lite of the GGUF bypass quick-win).

Two guarantees:
1. Host-side: every `SSTI_OBFUSCATED_VARIANTS` template avoids all literal
   `SSTI_SIGNALS` substrings that ggufref's static detector greps for.
2. Container-gated: each variant, embedded in a benign GGUF and scanned via
   `run_scan(gguf_ref=True)`, is reported `benign` by ggufref's static verdict
   yet `strace_executed=True` (process spawn observed by the strace-based GGUF
   execution oracle) — i.e. a genuine confirmed bypass (panel all-benign AND
   execution-confirmed). The baseline `ssti_chat_template` is caught
   (verdict=malicious) for contrast.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline import scanners  # noqa: E402
from pipeline.gguf_tools import (  # noqa: E402
    SSTI_OBFUSCATED_VARIANTS,
    benign_gguf,
)

# Mirror of containers/gguf/loader.py SSTI_SIGNALS (kept in sync by review).
SSTI_SIGNALS = [
    "__class__", "__globals__", "__subclasses__", "__builtins__",
    "__import__", "os.system", "os.popen", "popen", "subprocess",
    "system(", "eval(", "exec(", "_module",
]


class TestGgufSstiObfuscationSignals(unittest.TestCase):
    def test_variants_avoid_all_static_signals(self):
        self.assertGreaterEqual(len(SSTI_OBFUSCATED_VARIANTS), 2)
        for name, tpl in SSTI_OBFUSCATED_VARIANTS.items():
            with self.subTest(name=name):
                hits = [s for s in SSTI_SIGNALS if s in tpl]
                self.assertEqual(hits, [], f"{name} contains signals: {hits}")


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
class TestGgufSstiObfuscationExecution(unittest.TestCase):
    """Container-gated: obfuscated variants must evade ggufref's static verdict
    while being execution-confirmed by the strace oracle."""

    def _scan(self, template: str) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(benign_gguf(chat_template=template))
            path = f.name
        try:
            out, err = scanners.run_scan("docker", "regenbench/gguf", path,
                                         timeout=120, gguf_ref=True)
        finally:
            os.remove(path)
        self.assertIsNone(err, err)
        return out

    def test_each_obfuscated_variant_is_a_confirmed_bypass(self):
        for name, tpl in SSTI_OBFUSCATED_VARIANTS.items():
            with self.subTest(name=name):
                out = self._scan(tpl)
                self.assertEqual(out.get("verdict"), "benign",
                                 f"{name} should evade ggufref static detection")
                summary = out.get("summary") or {}
                self.assertTrue(summary.get("strace_executed"),
                                f"{name} must be execution-confirmed via strace")
                self.assertNotIn("triggered",
                                 [f for f in out.get("findings", []) if f == "ssti:triggered"])

    def test_baseline_ssti_is_caught(self):
        out = self._scan("{% for x in ().__class__.__base__.__subclasses__() %}"
                         '{% if "warning" in x.__name__ %}'
                         "{{x()._module.__builtins__['__import__']('os').popen("
                         '"touch /tmp/trig_base.txt"'
                         ")}}{%endif%}{% endfor %}")
        self.assertEqual(out.get("verdict"), "malicious",
                         "baseline ssti_chat_template must still be detected")


if __name__ == "__main__":
    unittest.main()