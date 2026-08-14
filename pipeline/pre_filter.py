"""T4.1 — Static Pre-Filter Admission Gate.

Filters out benign/malformed candidates before dynamic container execution.
"""

from __future__ import annotations

import os
import zipfile
from pipeline.opcodes import parse_pickle
from pipeline.registry import is_dangerous


def is_admitted(file_path: str) -> bool:
    """Cheapest check: admits a candidate to the dynamic oracle only if it is syntactically
    valid and contains at least one dangerous import callable from the registry."""
    if not os.path.exists(file_path):
        return False
        
    # Magic bytes check
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
        
    if not magic:
        return False
        
    # If it is a PyTorch checkpoint, it is a ZIP archive starting with PK\x03\x04
    is_zip = magic.startswith(b"PK\x03\x04")
    is_raw_pickle = magic[0] == 0x80
    
    if not (is_zip or is_raw_pickle):
        return False

    try:
        if is_zip:
            # For zip, we read the embedded data.pkl file
            with zipfile.ZipFile(file_path) as z:
                # Find the pickle payload (usually archive/data.pkl in PyTorch format)
                pkl_name = [name for name in z.namelist() if name.endswith("data.pkl")]
                if not pkl_name:
                    return False
                pkl_bytes = z.read(pkl_name[0])
        else:
            with open(file_path, "rb") as f:
                pkl_bytes = f.read()

        parsed = parse_pickle(pkl_bytes)
        
        # Look for dangerous imports
        for op, arg in parsed:
            if op.name in ("GLOBAL", "INST"):
                parts = arg.decode("latin1").split("\n")
                if len(parts) >= 2:
                    module, name = parts[0], parts[1]
                    if is_dangerous(module, name):
                        return True  # Found dangerous import, admit to oracle!
    except Exception:
        # Fail-closed: a malformed/unparseable artifact must still reach the
        # dynamic oracle. Rejecting it here would silently let a crafted
        # payload bypass behavioral analysis entirely.
        return True
        
    return False
