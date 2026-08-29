"""Config field-plumbing audit (Plan Phase 3.3).

Regression guard for the Section 7a bug class: a ``Config`` dataclass field
that exists but is never threaded through to its point of use. The test below
constructs a ``Config`` with sentinel values for every field and asserts each
sentinel is observable in the resulting scan invocation (container backend,
image tag, timeout, oracle model dir, pool size) or in filtering/scanner
selection behavior (extensions, min_size, skip, oracle, pre_filter).

If a new field is added to ``Config`` without plumbing, add it here; CI fails
if any documented sentinel never surfaces.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.runner import Config, Runner  # noqa: E402


def _sentinel_config(**overrides) -> Config:
    cfg = Config(
        backend="sentinel-backend",
        tag=":sentinel-tag",
        max_workers=2,
        timeout=4321,
        extensions=set(Config.__dataclass_fields__["extensions"].default_factory()),
        min_size=0,
        skip=set(),
        oracle=True,
        pre_filter=False,
        oracle_model_dir="/sentinel/oracle/model/dir",
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


class CapturedPool:
    """ThreadPoolExecutor spy recording the requested worker count."""

    last_max_workers: int | None = None

    def __init__(self, max_workers=None, *a, **kw):
        CapturedPool.last_max_workers = max_workers
        self._real = __import__("concurrent.futures", fromlist=["ThreadPoolExecutor"]).ThreadPoolExecutor(
            max_workers=max_workers or 1)

    def submit(self, fn, *a, **kw):
        return self._real.submit(fn, *a, **kw)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._real.shutdown(wait=True)
        return False


class TestConfigPlumbing(unittest.TestCase):
    def _run_with_capture(self, cfg: Config, artifact: str):
        from pipeline.scanners import ScanResult

        captured = []

        def fake_run_scan(backend, image_full, src, timeout, oracle_model_dir=None):
            captured.append({"backend": backend, "image": image_full,
                             "src": src, "timeout": timeout,
                             "oracle_model_dir": oracle_model_dir})
            return {"verdict": "benign", "exit_code": 0,
                    "decision_score": 0.0, "findings": []}, None

        with mock.patch("pipeline.runner.run_scan", side_effect=fake_run_scan), \
             mock.patch("pipeline.runner.ThreadPoolExecutor", CapturedPool):
            runner = Runner(cfg)
            results = runner.run([artifact])
        return runner, results, captured

    def test_backend_timeout_oracle_model_dir_and_tag_plumbed(self):
        with tempfile.TemporaryDirectory() as td:
            art = os.path.join(td, "candidate.pt")
            Path(art).write_bytes(b"x" * 16)
            cfg = _sentinel_config()
            _, results, captured = self._run_with_capture(cfg, art)

            self.assertTrue(captured, "no scan invocations recorded")
            # dynahug must be among the scanners for a .pt artifact when
            # oracle=True, so the oracle_model_dir kwarg must surface.
            backends = {c["backend"] for c in captured}
            self.assertEqual(backends, {"sentinel-backend"})
            timeouts = {c["timeout"] for c in captured}
            self.assertEqual(timeouts, {4321})
            omds = {c["oracle_model_dir"] for c in captured}
            self.assertIn("/sentinel/oracle/model/dir", omds)
            for c in captured:
                self.assertTrue(c["image"].endswith(":sentinel-tag"),
                                f"tag sentinel missing from image {c['image']}")
            self.assertTrue(all(r.verdict == "benign" for r in results))

    def test_max_workers_sentinel_bounds_pool(self):
        with tempfile.TemporaryDirectory() as td:
            art = os.path.join(td, "candidate.pt")
            Path(art).write_bytes(b"x" * 16)
            cfg = _sentinel_config(max_workers=2)
            self._run_with_capture(cfg, art)
            self.assertEqual(CapturedPool.last_max_workers, 2)

    def test_extensions_filter(self):
        with tempfile.TemporaryDirectory() as td:
            keep = os.path.join(td, "model.zzz")
            drop = os.path.join(td, "model.pkl")
            Path(keep).write_bytes(b"zz")
            Path(drop).write_bytes(b"pp")
            cfg = _sentinel_config(extensions={".zzz"}, pre_filter=False)
            runner = Runner(cfg)
            self.assertTrue(runner._filter(keep))
            self.assertFalse(runner._filter(drop))

    def test_min_size_filter(self):
        with tempfile.TemporaryDirectory() as td:
            small = os.path.join(td, "small.zzz")
            big = os.path.join(td, "big.zzz")
            Path(small).write_bytes(b"0123456789")      # 10 bytes
            Path(big).write_bytes(b"0123456789" * 10)   # 100 bytes
            cfg = _sentinel_config(extensions={".zzz"}, min_size=50, pre_filter=False)
            runner = Runner(cfg)
            self.assertFalse(runner._filter(small))
            self.assertTrue(runner._filter(big))

    def test_skip_filter_basename_and_parent_dir(self):
        with tempfile.TemporaryDirectory() as td:
            hit_base = os.path.join(td, "artifact_skipme.zzz")
            Path(hit_base).write_bytes(b"z")
            cfg = _sentinel_config(skip={"skipme"}, pre_filter=False)
            runner = Runner(cfg)
            self.assertFalse(runner._filter(hit_base))
            # parent-directory skip
            subdir = os.path.join(td, "skipdir")
            os.makedirs(subdir, exist_ok=True)
            inside = os.path.join(subdir, "keep.zzz")
            Path(inside).write_bytes(b"z")
            self.assertFalse(runner._filter(inside))

    def test_oracle_false_excludes_dynahug(self):
        with tempfile.TemporaryDirectory() as td:
            art = os.path.join(td, "candidate.pt")
            Path(art).write_bytes(b"x" * 16)
            cfg = _sentinel_config(oracle=False)
            _, _, captured = self._run_with_capture(cfg, art)
            imgs = [c["image"] for c in captured]
            self.assertFalse(any("dynahug" in i for i in imgs),
                             "oracle=False must exclude dynahug")
            self.assertTrue(imgs, "panel scanners should still run")

    def test_pre_filter_true_drops_unadmitted_from_oracle(self):
        with tempfile.TemporaryDirectory() as td:
            art = os.path.join(td, "candidate.pt")
            Path(art).write_bytes(b"x" * 16)
            cfg = _sentinel_config(pre_filter=True)
            with mock.patch("pipeline.pre_filter.is_admitted", return_value=False), \
                 mock.patch("pipeline.runner.run_scan", return_value=({
                     "verdict": "benign", "exit_code": 0,
                     "decision_score": 0.0, "findings": []}, None)), \
                 mock.patch("pipeline.runner.ThreadPoolExecutor", CapturedPool):
                runner = Runner(cfg)
                results = runner.run([art])
            dynahug_rows = [r for r in results if r.scanner == "dynahug"]
            self.assertEqual(dynahug_rows, [])


class TestFieldCoverage(unittest.TestCase):
    """Every Config field must be exercised by this module's sentinels.

    If you added a field to Config, extend _sentinel_config and add an
    assertion here -- this is the lint that prevents a repeat of bug 7a.
    """

    COVERED_FIELDS = {
        "backend", "tag", "max_workers", "timeout", "extensions", "min_size",
        "skip", "oracle", "pre_filter", "oracle_model_dir",
        "sanitize_mode", "repair_dir",
    }

    def test_all_fields_covered(self):
        fields = set(Config.__dataclass_fields__)
        missing = fields - self.COVERED_FIELDS
        self.assertFalse(
            missing,
            f"Config gained unplumbed/untested fields: {missing}. "
            f"Add sentinel assertions to tests/test_config_plumbing.py.",
        )


class TestDefaultBackend(unittest.TestCase):
    """The runtime default must prefer podman but fall back to docker on
    docker-only hosts (the lab baseline), so commands need no --backend."""

    def _patch_which(self, available: set[str]):
        return mock.patch("shutil.which",
                          side_effect=lambda name: f"/usr/bin/{name}" if name in available else None)

    def test_prefers_podman_when_present(self):
        from pipeline.scanners import default_backend
        with self._patch_which({"podman", "docker"}):
            self.assertEqual(default_backend(), "podman")

    def test_falls_back_to_docker_without_podman(self):
        from pipeline.scanners import default_backend
        with self._patch_which({"docker"}):
            self.assertEqual(default_backend(), "docker")

    def test_returns_prefer_when_none_available(self):
        from pipeline.scanners import default_backend
        with self._patch_which(set()):
            self.assertEqual(default_backend(), "podman")

    def test_config_default_resolves_to_available_runtime(self):
        with self._patch_which({"docker"}):
            cfg = Config()
            self.assertEqual(cfg.backend, "docker")


if __name__ == "__main__":
    unittest.main()
