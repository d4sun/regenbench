#!/usr/bin/env python3
"""Image pin verification (Plan Phase 3.4 / Phase 6 re-pin check).

Pins documented in a report are not self-verifying: this script reads what is
actually baked into each built image (.git HEAD of the vendored upstream tree,
the DYNAHUG_COMMIT env var, or installed package metadata) and optionally maps
git commits back to their upstream release tags via the GitHub API.

Usage:
    python3 scripts/verify_pins.py [--check-tags]

Exit code 1 if any image's baked-in identity does not match its expected pin.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request

# image -> (kind, locator, expected, upstream_repo_for_tag_lookup)
#   kind "git":  locator is the vendored .git checkout path in-image
#   kind "env":  locator is an environment variable name in-image
#   kind "meta": locator is a distribution name for importlib.metadata
EXPECTED_PINS = [
    ("regenbench/picklescan", "git", "/opt/picklescan",
     "f15d54da3dec9aa28a87ede82f87882bb80f1023", "mmaitre314/picklescan"),
    ("regenbench/modelscan", "git", "/opt/modelscan",
     "61fcec9c2a37c24c1fb12d84ede30fe248a364bd", "protectai/modelscan"),
    ("regenbench/modeltracer", "git", "/opt/model-tracer",
     "5725b26f62a1c0e4f22c793761cefb70ead64ee5", "s2e-lab/hf-model-analyzer"),
    ("regenbench/dynahug", "env", "DYNAHUG_COMMIT",
     "8ff8174eaf54175a7fc3b90730faf334fb767e0b", None),
    ("regenbench/gguf", "meta", "gguf",
     "0.19.0", None),
]


def run_in_image(image: str, entrypoint: str, args: list[str]) -> str:
    proc = subprocess.run(
        ["podman", "run", "--rm", "--entrypoint", entrypoint,
         f"localhost/{image}:latest", *args],
        capture_output=True, text=True, timeout=180)
    return (proc.stdout + proc.stderr).strip()


def baked_identity(image: str, kind: str, locator: str) -> str:
    if kind == "git":
        return run_in_image(image, "/bin/sh",
                            ["-c", f"cat {locator}/.git/HEAD"])
    if kind == "env":
        return run_in_image(image, "/bin/sh", ["-c", f"printenv {locator}"])
    if kind == "meta":
        code = (f"from importlib.metadata import version; print(version('{locator}'))")
        return run_in_image(image, "python3.13", ["-c", code])
    raise ValueError(kind)


def tag_for_commit(repo: str, commit: str) -> str | None:
    try:
        req = urllib.request.urlopen(
            f"https://api.github.com/repos/{repo}/tags?per_page=100", timeout=30)
        for t in json.load(req):
            if t["commit"]["sha"] == commit:
                return t["name"]
    except Exception as e:  # offline CI: tag lookup is best-effort
        return f"<lookup failed: {e}>"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-tags", action="store_true",
                    help="also map git commits to upstream release tags")
    args = ap.parse_args()

    failures = 0
    rows = []
    for image, kind, locator, expected, repo in EXPECTED_PINS:
        actual = baked_identity(image, kind, locator)
        ok = actual == expected
        failures += 0 if ok else 1
        note = ""
        if args.check_tags and repo and ok:
            note = f" -> {tag_for_commit(repo, actual)}"
        rows.append((image, kind, expected[:12], actual[:12], ok, note))

    w = max(len(r[0]) for r in rows) + 2
    print(f"{'IMAGE':<{w}}{'KIND':<6}{'EXPECTED':<15}{'IN-IMAGE':<15}OK{''}")
    for image, kind, exp, act, ok, note in rows:
        print(f"{image:<{w}}{kind:<6}{exp:<15}{act:<15}{'PASS' if ok else 'FAIL'}{note}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
