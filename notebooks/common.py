"""Shared helpers for ReGenBench notebooks (thin subprocess wrappers).

Every notebook drives the *existing* CLI scripts (not new inline logic) so the
notebook output mirrors exactly what `python3 scripts/<name>.py` would print.
These helpers only handle subprocess plumbing and pretty-printing; the
pipeline logic lives in `scripts/` and `pipeline/`.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from typing import Sequence

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_argv(argv: Sequence[str]) -> list[str]:
    """Point a leading ``python3``/``python`` at the kernel interpreter.

    The notebooks wrap CLI scripts by name; resolving the interpreter to
    ``sys.executable`` (the running kernel's Python) removes PATH ambiguity, so
    a notebook keeps working regardless of which interpreter ``python3`` would
    otherwise resolve to on the host.
    """
    argv = [str(a) for a in argv]
    if argv and argv[0] in ("python3", "python"):
        argv[0] = sys.executable
    return argv


def run(argv: Sequence[str], cwd: str | None = None, check: bool = True) -> int:
    """Run a command in the repo root, streaming its output line by line.

    Prints the command first (so each cell shows exactly what it ran), then
    streams stdout/stderr as it arrives — required to see progress on long
    docker/network steps rather than a silent wait.
    """
    argv = _resolve_argv(argv)
    if cwd is None:
        cwd = REPO
    print(f"\n$ {shlex.join(str(a) for a in argv)}\n", flush=True)
    proc = subprocess.Popen(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="", flush=True)
    rc = proc.wait()
    if check and rc != 0:
        raise SystemExit(f"command failed with exit code {rc}: {shlex.join(str(a) for a in argv)}")
    return rc


def run_silent(argv: Sequence[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run a command and capture output (for small analytical queries)."""
    argv = _resolve_argv(argv)
    if cwd is None:
        cwd = REPO
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=True)


def sqlite(query: str, db: str = "data/regenbench_campaign.db") -> str:
    """Run a SQLite query against the campaign DB and return stdout."""
    out = run_silent(["sqlite3", os.path.join(REPO, db), query])
    return out.stdout.strip()


def show(path: str, max_lines: int = 200) -> None:
    """Print a generated report/JSON file (bounded) inside the notebook."""
    full = os.path.join(REPO, path)
    if not os.path.exists(full):
        print(f"[notebook] missing: {path}")
        return
    with open(full) as f:
        lines = f.read().splitlines()
    print(f"--- {path} ({len(lines)} lines) ---")
    print("\n".join(lines[:max_lines]))
    if len(lines) > max_lines:
        print(f"… {len(lines) - max_lines} more lines omitted (see {path})")


def summary_line(label: str, ok: bool) -> None:
    print(("OK  " if ok else "FAIL") + f"  {label}", flush=True)