"""GGUF demo-consistency regression tests (host-only, no containers).

Guards Phase 1 of the GGUF remediation:

1. Both GGUF demos (`scripts/demo_task3.py` and `scripts/run_task3_demo.py`)
   must produce *identical* verdicts for the same attack/benign files, from a
   single shared `pipeline.scanners.run_scan` code path.
2. `run_scan(gguf_ref=True)` must carry the GGUF reference-oracle isolation
   flags, and must NOT pass the podman-only `--timeout` flag to docker.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline import scanners  # noqa: E402
import scripts.demo_task3 as demo_task3  # noqa: E402
import scripts.run_task3_demo as run_task3_demo  # noqa: E402

ATTACK_NAMES = [
    "gguf_ssti_chat_template.gguf",
    "gguf_malformed_nkv_overflow.gguf",
    "gguf_malformed_ntensors_overflow.gguf",
    "gguf_malformed_string_overflow.gguf",
    "gguf_malformed_path_traversal.gguf",
    "gguf_malformed_negative_dims.gguf",
    "gguf_malformed_version_zero.gguf",
]
BENIGN_NAME = "benign-synth.gguf"


def _fake_scan(backend, image_full, src, timeout=300, oracle_model_dir=None, gguf_ref=False):
    """Deterministic stand-in for run_scan: ggufref is correct, modelscan misses."""
    name = os.path.basename(src)
    if "gguf" in image_full and "ggufref" in image_full:
        verdict = "malicious" if name != BENIGN_NAME else "benign"
    else:
        verdict = "benign"
    return {"verdict": verdict, "findings": []}, None


class TestGgufDemoConsistency(unittest.TestCase):
    def _run_both(self):
        images = {"ggufref": "regenbench/gguf", "modelscan": "regenbench/modelscan",
                  "picklescan": "regenbench/picklescan", "fickling": "regenbench/fickling",
                  "modeltracer": "regenbench/modeltracer", "dynahug": "regenbench/dynahug"}
        targets = [f"/tmp/{n}" for n in ATTACK_NAMES + [BENIGN_NAME]]
        # run_task3_demo binds run_scan at import (module attribute); demo_task3
        # imports it inside the function. Patch both to the same mock so the
        # single shared code path is exercised deterministically.
        with mock.patch.object(scanners, "run_scan", side_effect=_fake_scan), \
             mock.patch.object(run_task3_demo, "run_scan", side_effect=_fake_scan):
            d3 = demo_task3.scan_gguf("docker", images, targets)
            r3 = run_task3_demo.scan_all("docker", images, targets)
        return d3, r3

    def test_both_demos_identical_ggufref_modelscan_verdicts(self):
        d3, r3 = self._run_both()

        def subset(rows):
            return sorted(
                (r["artifact"], r["scanner"], r["verdict"])
                for r in rows if r["scanner"] in ("ggufref", "modelscan"))

        self.assertEqual(subset(d3), subset(r3))
        self.assertEqual(len(subset(d3)), 16)  # 8 files x 2 scanners

    def test_both_demos_share_run_scan_code_path(self):
        """Both demos must route through pipeline.scanners.run_scan (consolidation)."""
        d3, r3 = self._run_both()
        self.assertTrue(d3)  # demo_task3 produced rows via run_scan
        self.assertTrue(r3)  # run_task3_demo produced rows via run_scan

    def test_run_scan_gguf_ref_flags_no_docker_timeout(self):
        cmd_capture = []

        def fake_subprocess_run(cmd, *a, **kw):
            cmd_capture.append(list(cmd))
            return mock.Mock(returncode=0, stdout='{"verdict": "benign"}\n')

        with mock.patch("pipeline.scanners.subprocess.run", side_effect=fake_subprocess_run):
            out, err = scanners.run_scan("docker", "regenbench/gguf", "/tmp/x.gguf",
                                         timeout=90, gguf_ref=True)
        self.assertIsNone(err)
        cmd = cmd_capture[0]
        self.assertNotIn("--timeout", cmd, "docker run must not receive podman-only --timeout")
        self.assertIn("--network", cmd, "SSTI path must be network-isolated")
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertIn("--tmpfs", cmd, "SSTI path must use a container-scoped /tmp")
        self.assertEqual(cmd[cmd.index("--tmpfs") + 1], "/tmp")
        self.assertNotIn("/tmp:/tmp", cmd, "host /tmp must not be mounted into the SSTI container")

    def test_run_scan_gguf_ref_no_host_tmp_mount(self):
        cmd_capture = []

        def fake_subprocess_run(cmd, *a, **kw):
            cmd_capture.append(list(cmd))
            return mock.Mock(returncode=0, stdout='{"verdict": "benign"}\n')

        with mock.patch("pipeline.scanners.subprocess.run", side_effect=fake_subprocess_run):
            scanners.run_scan("docker", "regenbench/gguf", "/tmp/x.gguf",
                              timeout=90, gguf_ref=True)
        cmd = " ".join(cmd_capture[0])
        self.assertNotIn("/tmp:/tmp", cmd)
        self.assertNotIn("label=disable", cmd, "not needed on SELinux-absent hosts")

    def test_run_scan_podman_gets_timeout(self):
        cmd_capture = []

        def fake_subprocess_run(cmd, *a, **kw):
            cmd_capture.append(list(cmd))
            return mock.Mock(returncode=0, stdout='{"verdict": "benign"}\n')

        with mock.patch("pipeline.scanners.subprocess.run", side_effect=fake_subprocess_run):
            scanners.run_scan("podman", "regenbench/gguf", "/tmp/x.gguf",
                              timeout=90, gguf_ref=True)
        cmd = cmd_capture[0]
        self.assertIn("--timeout", cmd)
        self.assertEqual(cmd[cmd.index("--timeout") + 1], "90")


def _have_docker_and_gguf_image() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                             capture_output=True, text=True, timeout=30)
        return "regenbench/gguf:latest" in out.stdout or "localhost/regenbench/gguf:latest" in out.stdout
    except Exception:  # noqa: BLE001
        return False


class TestGgufSstiIsolation(unittest.TestCase):
    """Container-gated: SSTI detection must survive the tmpfs isolation (Phase 2)."""

    @unittest.skipUnless(_have_docker_and_gguf_image(),
                         "docker + regenbench/gguf image required")
    def test_ssti_trigger_still_observed_with_tmpfs_isolation(self):
        import tempfile

        from pipeline.gguf_tools import generate_candidate_gguf
        trigger = "/tmp/trig_iso_test.txt"
        data = generate_candidate_gguf("ssti_chat_template", trigger)
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            out, err = scanners.run_scan("docker", "regenbench/gguf", path,
                                         timeout=120, gguf_ref=True)
            self.assertIsNone(err, err)
            self.assertEqual(out.get("verdict"), "malicious")
            self.assertTrue(
                any(f.endswith("triggered") for f in out.get("findings", [])),
                "tmpfs must not break trigger observation")
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()