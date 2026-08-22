"""Phase 2 correctness tests for pipeline/validity.py (T3.5).

Layers:
  1. Pure logic: _trigger_exists polling semantics.
  2. Branch logic with mocked subprocess: timeout -> False, SELinux relabel
     retry drops the :z mount, plain failure never retries, trigger cleanup.
  3. Host-fallback path (no container runtime): load success AND trigger
     conjunction.
  4. Real container integration (skipped without podman + built images):
     known-good executing pickle -> True; known-bad bytes -> False;
     GGUF reference-reader verdict parsing.

All executed candidate bytes in this file are self-written benign payloads
(touch a sentinel / create a directory); nothing arbitrary is run.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.validity import ValidityOracle, _trigger_exists  # noqa: E402

HAVE_PODMAN = __import__("shutil").which("podman") is not None
BASE_IMAGE = "localhost/regenbench/base:latest"
GGUF_IMAGE = "localhost/regenbench/gguf:latest"


def _image_exists(image: str) -> bool:
    if not HAVE_PODMAN:
        return False
    r = subprocess.run(["podman", "image", "exists", image],
                       capture_output=True)
    return r.returncode == 0


def _executing_pickle(trigger_path: str) -> bytes:
    """Self-written pickle that runs `os.system('touch <trigger>')` at load,
    then leaves a truthy object on the stack (loads must return non-None).

    Note: True is encoded as 'I01' -- a bare 'N' would push None and the
    load-side `assert obj is not None` would (correctly) reject us."""
    return (
        b"\x80\x02cos\nsystem\n(S'touch "
        + trigger_path.encode()
        + b"'\ntRI01\n."
    )


class TestTriggerExists(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_existing_file_returns_true_immediately(self):
        p = self.dir / "trig"
        p.touch()
        t0 = time.monotonic()
        self.assertTrue(_trigger_exists(str(p), wait=5.0))
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_missing_file_returns_false_after_wait(self):
        p = self.dir / "never"
        t0 = time.monotonic()
        self.assertFalse(_trigger_exists(str(p), wait=0.2))
        self.assertGreaterEqual(time.monotonic() - t0, 0.15)

    def test_file_created_mid_poll_is_detected(self):
        p = self.dir / "late"
        timer = threading.Timer(0.15, p.touch)
        timer.start()
        self.addCleanup(timer.cancel)
        self.assertTrue(_trigger_exists(str(p), wait=2.0))


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@mock.patch("pipeline.validity._trigger_exists", return_value=True)
class TestValidatePickleBranches(unittest.TestCase):
    """Mocked container runs: assert command shape and decision logic."""

    def setUp(self):
        self.oracle = ValidityOracle(container_backend="podman", timeout=10)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.trigger = str(Path(self._tmp.name) / "trig")

    def test_timeout_yields_false(self, _):
        with mock.patch("pipeline.validity.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd="podman", timeout=1)):
            self.assertFalse(
                self.oracle.validate_pickle(b"\x80\x02N.", self.trigger))

    def test_selinux_relabel_failure_retries_without_z_mount(self, _):
        calls = []

        def fake_run(cmd, **_kw):
            calls.append(list(cmd))
            if "-v" in cmd and cmd[cmd.index("-v") + 1].endswith(":z"):
                return _FakeProc(returncode=1, stderr="Error: relabeling /tmp not allowed")
            return _FakeProc(returncode=0)

        with mock.patch("pipeline.validity.subprocess.run", side_effect=fake_run):
            ok = self.oracle.validate_pickle(b"\x80\x02N.", self.trigger)

        self.assertEqual(len(calls), 2, "must retry exactly once")
        first, second = calls
        # First attempt carries the shared :z mount...
        self.assertIn("-v", first)
        self.assertTrue(first[first.index("-v") + 1].endswith(":z"))
        # ...retry disables labeling and mounts without the relabel flag.
        self.assertIn("--security-opt", second)
        self.assertIn("label=disable", second)
        mount = second[second.index("-v") + 1]
        self.assertFalse(mount.endswith(":z"))
        self.assertTrue(mount.startswith("/"))
        self.assertTrue(ok)

    def test_plain_container_failure_never_retries_and_returns_false(self, _):
        calls = []

        def fake_run(cmd, **_kw):
            calls.append(list(cmd))
            return _FakeProc(returncode=1, stderr="no such image")

        with mock.patch("pipeline.validity.subprocess.run", side_effect=fake_run):
            ok = self.oracle.validate_pickle(b"\x80\x02N.", self.trigger)

        self.assertEqual(len(calls), 1)
        self.assertFalse(ok)

    def test_success_command_shape(self, _):
        captured = {}

        def fake_run(cmd, **_kw):
            captured["cmd"] = list(cmd)
            return _FakeProc(returncode=0)

        with mock.patch("pipeline.validity.subprocess.run", side_effect=fake_run):
            self.assertTrue(self.oracle.validate_pickle(b"\x80\x02N.", self.trigger))

        cmd = captured["cmd"]
        self.assertEqual(cmd[:3], ["podman", "run", "--rm"])
        self.assertIn(BASE_IMAGE, cmd)
        self.assertIn("python3.13", cmd)
        mount = cmd[cmd.index("-v") + 1]
        self.assertTrue(mount.split(":")[-1] == "z")
        self.assertIn(":z", mount)


class TestValidatePickleCleanupAndConjunction(unittest.TestCase):
    def setUp(self):
        self.oracle = ValidityOracle(container_backend="podman", timeout=20)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.trigger = str(self.dir / "trig")

    def test_preexisting_trigger_removed_before_validation(self):
        Path(self.trigger).write_text("stale")
        with mock.patch("pipeline.validity.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)), \
             mock.patch("pipeline.validity._trigger_exists", return_value=False):
            self.oracle.validate_pickle(b"\x80\x02N.", self.trigger)
        self.assertFalse(os.path.exists(self.trigger))

    @unittest.skipUnless(HAVE_PODMAN and _image_exists(BASE_IMAGE),
                         f"{BASE_IMAGE} unavailable")
    def test_known_good_executing_pickle_passes_in_container(self):
        # Trigger lives under the same tempdir mounted at /tmp inside the box.
        trig_dir = tempfile.mkdtemp(prefix="rb_trig_")
        trigger = os.path.join(trig_dir, "trig")
        try:
            ok = self.oracle.validate_pickle(_executing_pickle(trigger), trigger)
        finally:
            if os.path.exists(trigger):
                os.remove(trigger)
            os.rmdir(trig_dir)
        self.assertTrue(ok)

    @unittest.skipUnless(HAVE_PODMAN and _image_exists(BASE_IMAGE),
                         f"{BASE_IMAGE} unavailable")
    def test_load_without_trigger_fails_conjunction(self):
        # Loads fine but writes no sentinel -> must be rejected.
        ok = self.oracle.validate_pickle(b"\x80\x02}", self.trigger)  # empty dict
        self.assertFalse(ok)

    def test_malformed_bytes_fail_closed_to_false_on_host_fallback(self):
        fallback = ValidityOracle(container_backend="definitely-not-a-runtime-xyz",
                                  timeout=10)
        self.assertFalse(fallback.validate_pickle(
            b"\x80\x04X\xff\xff\xff\xff", self.trigger))


class TestHostFallbackExecutesPayload(unittest.TestCase):
    """Without a container runtime the oracle loads via a host subprocess.

    The conjunction rule requires BOTH a successful load and a fired trigger;
    verify each half independently using harmless self-written fixtures."""

    def setUp(self):
        self.oracle = ValidityOracle(container_backend="definitely-not-a-runtime-xyz",
                                     timeout=15)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.trigger = str(Path(self._tmp.name) / "trig")

    def test_trigger_without_successful_load_is_rejected(self):
        # Host-fallback path: the trigger "fires" (mocked) but the load
        # itself fails on truncated bytes -> conjunction must reject.
        with mock.patch("pipeline.validity._trigger_exists", return_value=True):
            ok = self.oracle.validate_pickle(b"\x80\x04X\xff\xff\xff\xff",
                                             self.trigger)
        self.assertFalse(ok)

    def test_successful_benign_load_without_trigger_is_rejected(self):
        ok = self.oracle.validate_pickle(b"\x80\x02}q\x00.", self.trigger)
        self.assertFalse(ok)


class TestValidateTorchFallback(unittest.TestCase):
    def test_unknown_backend_falls_back_and_never_crashes(self):
        oracle = ValidityOracle(container_backend="definitely-not-a-runtime-xyz",
                                timeout=10)
        with tempfile.TemporaryDirectory() as d:
            trigger = str(Path(d) / "trig")
            ok = oracle.validate_torch(b"PK\x03\x04garbage", trigger)
        self.assertFalse(ok)


class TestGgufValidation(unittest.TestCase):
    def setUp(self):
        self.oracle = ValidityOracle(container_backend="podman", timeout=30)

    @unittest.skipUnless(HAVE_PODMAN and _image_exists(GGUF_IMAGE),
                         f"{GGUF_IMAGE} unavailable")
    def test_malformed_gguf_header_rejected_by_reference_reader(self):
        bad = b"GGUF\xff\xff\xff\xff" + b"\x00" * 64
        self.assertFalse(self.oracle.validate_gguf(bad))

    def test_no_container_runtime_returns_false(self):
        oracle = ValidityOracle(container_backend="definitely-not-a-runtime-xyz")
        self.assertFalse(oracle.validate_gguf(b"GGUF"))

    def test_non_json_stdout_counts_as_failure(self):
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch("pipeline.validity.subprocess.run",
                        return_value=_FakeProc(returncode=0, stdout="not json\nat all\n")):
            self.assertFalse(self.oracle.validate_gguf(b"GGUF"))

    def test_json_verdict_with_load_ok_true_passes(self):
        verdict = '{"summary": {"load_ok": true}, "errors": []}\n'
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch("pipeline.validity.subprocess.run",
                        return_value=_FakeProc(returncode=0, stdout=verdict)):
            self.assertTrue(self.oracle.validate_gguf(b"GGUF"))


if __name__ == "__main__":
    unittest.main()
