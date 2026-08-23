"""T3.2 — Dangerous-Callable Registry.

Loads and queries the registry of dangerous callable modules/targets.
"""

from __future__ import annotations

import os
import sys
import yaml
from typing import Any


class RegistryEntry:
    def __init__(self, module: str, name: str, category: str, description: str, genuine_code_exec: bool):
        self.module = module
        self.name = name
        self.category = category
        self.description = description
        self.genuine_code_exec = genuine_code_exec

    def __repr__(self) -> str:
        return f"RegistryEntry({self.module}.{self.name}, category={self.category})"


_REGISTRY: dict[tuple[str, str], RegistryEntry] = {}


def load_registry(yaml_path: str | None = None) -> None:
    """Load the dangerous callables registry from YAML."""
    global _REGISTRY
    _REGISTRY.clear()
    
    if yaml_path is None:
        # Resolve path relative to this file
        this_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_path = os.path.join(this_dir, "dangerous_callables.yaml")
        
    if not os.path.exists(yaml_path):
        raise FileNotFoundError(f"Dangerous callables registry file not found: {yaml_path}")
        
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
        
    for entry in data.get("dangerous_callables", []):
        # Skip platform-restricted entries that cannot load on this host
        # (e.g. Windows-only nt.system would fail with ModuleNotFoundError
        # when GLOBAL'd on Linux).
        platform = entry.get("platform")
        if platform == "windows" and not sys.platform.startswith("win"):
            continue
        if platform == "unix" and sys.platform.startswith("win"):
            continue
        reg_entry = RegistryEntry(
            module=entry["module"],
            name=entry["name"],
            category=entry["category"],
            description=entry.get("description", ""),
            genuine_code_exec=entry.get("genuine_code_exec", True),
        )
        _REGISTRY[(reg_entry.module, reg_entry.name)] = reg_entry


def is_dangerous(module: str, name: str) -> bool:
    """Check if a module and callable name pair is registered as dangerous."""
    if not _REGISTRY:
        load_registry()
    return (module, name) in _REGISTRY


def get_entry(module: str, name: str) -> RegistryEntry | None:
    """Get the registry entry details for a module and callable name pair."""
    if not _REGISTRY:
        load_registry()
    return _REGISTRY.get((module, name))


def get_all_entries() -> list[RegistryEntry]:
    """Get all registered dangerous callables."""
    if not _REGISTRY:
        load_registry()
    return list(_REGISTRY.values())


# Callables that cannot carry the inline trigger payload in this environment:
#   - runpy.run_module     : takes a module *name*, no inline code slot
#   - pandas.eval          : pandas expression engine rejects __import__ calls
#   - sympy.sympify        : raises SympifyError on the empty shell output
#   - yaml.unsafe_load     : parses YAML; a Python code string never constructs
#                            an object graph that executes it
# Plus the Phase-1 smuggling primitives (__import__/getattr/_pickle.loads):
# they ARE dangerous signatures (the evasion chains use them) and belong in
# coverage/pre-filter accounting, but selecting one as a *direct sink* would
# just pass payload_code as an argument to a non-executing primitive, so every
# such candidate would fail validity.
NON_ARMABLE: set[tuple[str, str]] = {
    ("runpy", "run_module"),
    ("pandas", "eval"),
    ("sympy", "sympify"),
    ("yaml", "unsafe_load"),
    ("builtins", "__import__"),
    ("builtins", "getattr"),
    ("_pickle", "loads"),
}


def get_armable_entries() -> list[RegistryEntry]:
    """Get registry entries that can carry the inline payload."""
    return [e for e in get_all_entries()
            if (e.module, e.name) not in NON_ARMABLE]
