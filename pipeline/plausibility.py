"""Deterministic bypass confirmation: payload executed + structurally valid.

Wraps :class:`pipeline.validity.ValidityOracle` — the primary ExecutionOracle
for bypass confirmation (container-sandboxed ``torch.load(weights_only=False)``
+ ``_trigger_exists`` sentinel poll, ``StraceOracle`` 0% FP). Unlike the
deprecated ``EnsembleOracle`` (``dynahug and anomaly and executed``), this
oracle does **not** gate on the statistical DynaHug decision_score; that
score is a supplementary signal only (see ``pipeline/comparator.py``).
"""
from __future__ import annotations

from pipeline.validity import ValidityOracle


class PlausibilityOracle:
    def __init__(self, validity_oracle: ValidityOracle):
        self.validity = validity_oracle

    def confirm(self, cand_bytes: bytes, trigger_file: str) -> bool:
        return self.validity.validate_torch(cand_bytes, trigger_file)