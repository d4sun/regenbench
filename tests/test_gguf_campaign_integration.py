"""GGUF campaign integration tests.

Verifies that GGUF families are properly integrated into the fuzzing campaign:
- GGUF families registered in templates.FAMILIES
- generate_candidate_gguf worker works
- PlausibilityOracle.confirm_gguf exists
- CoverageTracker handles GGUF (no opcode/callable tracking)
- FeedbackController samples GGUF families
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.templates import FAMILIES, GGUF_FAMILIES, FAMILY_LABELS, family_format  # noqa: E402
from pipeline.gguf_tools import generate_candidate_gguf  # noqa: E402
from pipeline.plausibility import PlausibilityOracle  # noqa: E402
from pipeline.validity import ValidityOracle  # noqa: E402
from pipeline.feedback import CoverageTracker, FeedbackController, NoveltyTracker  # noqa: E402


class TestGGUFTemplateRegistration:
    """Verify GGUF families are registered in the campaign template registry."""

    def test_gguf_families_in_families(self):
        for fam in GGUF_FAMILIES:
            assert fam in FAMILIES, f"{fam} not in FAMILIES"

    def test_gguf_family_labels_exist(self):
        for fam in GGUF_FAMILIES:
            assert fam in FAMILY_LABELS, f"{fam} missing from FAMILY_LABELS"
            assert FAMILY_LABELS[fam].startswith("gguf_"), f"Label for {fam} doesn't start with gguf_: {FAMILY_LABELS[fam]}"

    def test_family_format_gguf(self):
        for fam in GGUF_FAMILIES:
            assert family_format(fam) == "gguf", f"family_format({fam}) != 'gguf'"

    def test_family_format_pickle(self):
        pickle_families = ["gadget", "overwritten", "external", "indirect_chain", "pypi_injected"]
        for fam in pickle_families:
            assert family_format(fam) == "pt", f"family_format({fam}) != 'pt'"


class TestGGUFGenerationWorker:
    """Verify the GGUF generation worker function."""

    def test_generate_candidate_gguf_produces_bytes(self):
        for fam in GGUF_FAMILIES:
            with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
                trigger = f.name
            try:
                data = generate_candidate_gguf(fam, trigger)
                assert isinstance(data, bytes), f"{fam} did not return bytes"
                assert data[:4] == b"GGUF", f"{fam} does not start with GGUF magic"
            finally:
                os.unlink(trigger)


class TestPlausibilityOracleGGUF:
    """Verify PlausibilityOracle has GGUF confirmation method."""

    def test_confirm_gguf_exists(self):
        v = ValidityOracle(container_backend="docker", timeout=20)
        p = PlausibilityOracle(v)
        assert hasattr(p, "confirm_gguf"), "PlausibilityOracle missing confirm_gguf"
        assert callable(p.confirm_gguf), "confirm_gguf is not callable"


class TestCoverageTrackerGGUF:
    """Verify CoverageTracker handles GGUF files (no pickle parsing)."""

    def test_track_candidate_gguf_returns_early(self):
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(b"GGUF" + b"\x00" * 20)
            gguf_path = f.name
        try:
            t = CoverageTracker("/tmp/test.db", "test")
            initial_opcodes = len(t.seen_opcodes)
            initial_callables = len(t.seen_callables)
            t.track_candidate(gguf_path, family="ssti_chat_template", is_bypass=True)
            # GGUF should not add any opcodes or callables
            assert len(t.seen_opcodes) == initial_opcodes
            assert len(t.seen_callables) == initial_callables
            # But family should be tracked
            assert "ssti_chat_template" in t.seen_families
        finally:
            os.unlink(gguf_path)


class TestFeedbackControllerGGUF:
    """Verify FeedbackController includes GGUF families in sampling."""

    def test_families_include_gguf(self):
        c = FeedbackController(family_quota_min_pct=0.15, family_quota_max_frac=0.40, entropy_target=1.5)
        for fam in GGUF_FAMILIES:
            assert fam in c.families, f"{fam} not in FeedbackController.families"

    def test_sample_family_with_quota_includes_gguf(self):
        import random
        c = FeedbackController(family_quota_min_pct=0.15, family_quota_max_frac=0.40, entropy_target=1.5)
        families = set(c.families)
        counts = {f: 0 for f in families}
        # Sample many times - GGUF families should appear
        for _ in range(100):
            fam = c.sample_family_with_quota(random, families, counts, 20)
            counts[fam] += 1
        gguf_count = sum(counts[f] for f in GGUF_FAMILIES)
        assert gguf_count > 0, "No GGUF families sampled"

    def test_sample_with_novelty_returns_gguf_combos(self):
        import random
        c = FeedbackController(family_quota_min_pct=0.15, family_quota_max_frac=0.40, entropy_target=1.5)
        n = NoveltyTracker()
        families = set(c.families)
        # Sample combos - should get some GGUF families with empty strategy sets
        gguf_combos = 0
        for _ in range(50):
            combo = c.sample_with_novelty(random, families, n, fixed_strategies=None, fixed_transport="splice")
            if combo and combo[0] in GGUF_FAMILIES:
                gguf_combos += 1
                # GGUF combos should have empty strategy sets
                assert combo[2] == frozenset(), f"GGUF combo has non-empty strategies: {combo}"
        assert gguf_combos > 0, "No GGUF combos from sample_with_novelty"


if __name__ == "__main__":
    import unittest
    unittest.main()