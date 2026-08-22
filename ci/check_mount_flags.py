#!/usr/bin/env python3
"""Static check: forbid private-label SELinux mount flags on shared mounts.

The Section 7b bug (implementation report): artifact mounts used ``:ro,Z``
(uppercase = private per-container relabel). Under Enforcing SELinux and
concurrency >= 2, simultaneous relabels collide and scanners silently emit
``verdict: error`` (9.4%-43.8% error rate). All shared-artifact mounts must
use lowercase ``z`` (shared relabel) or run with ``--security-opt
label=disable``.

This script scans every Python/shell invocation site for uppercase-Z volume
flags and fails the build if one appears. Documentation files that describe
the historical bug are explicitly allowlisted.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Code files scanned for podman/docker invocations.
SCAN_GLOBS = ["pipeline/**/*.py", "scripts/**/*.py", "scripts/**/*.sh",
              "ci/**/*.py", "ci/**/*.sh", "containers/**/build.sh"]

# Matches a volume flag ending in a private SELinux label:
#   :Z  ,Z   :ro,Z   ,Z:...   e.g. "-v", f"{x}:/y:Z"
MOUNT_Z_RE = re.compile(r"""["']?[^"'\s]*:[^"'\s]*?(?:^|[,:])Z(?=["'\s:,]|$)""")

# Files documenting the historical bug rather than invoking Podman.
ALLOWLIST = {
    "ci/check_mount_flags.py",  # documents the forbidden pattern itself
}


def main() -> int:
    offenders: list[tuple[str, int, str]] = []
    for pattern in SCAN_GLOBS:
        for path in sorted(REPO_ROOT.glob(pattern)):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in ALLOWLIST:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for i, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue  # comments cannot invoke Podman
                if MOUNT_Z_RE.search(line):
                    offenders.append((rel, i, line.strip()))

    if offenders:
        print("FAIL: private-label ':Z' mount flag(s) found "
              "(shared mounts must use ':z' / ':ro,z'):\n")
        for rel, lineno, line in offenders:
            print(f"  {rel}:{lineno}: {line}")
        return 1

    print("OK: no private-label ':Z' mount flags in code paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
