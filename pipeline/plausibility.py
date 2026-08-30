"""Deterministic bypass confirmation: payload executed + structurally valid."""
from __future__ import annotations

from pipeline.validity import ValidityOracle


class PlausibilityOracle:
    def __init__(self, validity_oracle: ValidityOracle):
        self.validity = validity_oracle

    def confirm(self, cand_bytes: bytes, trigger_file: str) -> bool:
        return self.validity.validate_torch(cand_bytes, trigger_file)