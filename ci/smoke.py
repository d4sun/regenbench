#!/usr/bin/env python3
"""Run the T0.8 smoke test: every scanner/oracle image against the corpus.

Reads ci/corpus/expected.json and, for each committed artifact, runs the
matching container image and compares the emitted (verdict, exit_code) to the
expected values. Emits a table and exits 0 on full pass, 1 on any mismatch.

Image tags default to the locally built :latest; override with
--tag foo (e.g. the published GHCR tag) or --image picklescan=regenbench/picklescan:0.9.0.

Runtime backend: podman (default) or docker (--backend docker).
"""

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(ROOT, "corpus")
MANIFEST = os.path.join(CORPUS, "expected.json")

# scanner -> default local image (build.sh tags). Overridable via --tag / map.
DEFAULT_IMAGES = {
    "picklescan": "regenbench/picklescan",
    "modelscan": "regenbench/modelscan",
    "fickling": "regenbench/fickling",
    "modeltracer": "regenbench/modeltracer",
    "dynahug": "regenbench/dynahug",
}


def run_image(backend, image, target, tag):
    full = f"{image}{tag}"
    # Mount the artifact read-only so payloads cannot write the host corpus.
    src = os.path.abspath(os.path.join(CORPUS, target))
    cmd = [
        backend, "run", "--rm",
        "-v", f"{src}:/artifact:ro,z",
        full, "/artifact",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return None, f"timeout running {full} on {target}"
    try:
        out = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return None, (proc.stdout or proc.stderr or "").strip()[-400:]
    return out, None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--tag", default=":latest",
                    help="image tag for ALL images (default :latest)")
    ap.add_argument("--image", action="append", default=[],
                    help="scanner=image:tag overrides, e.g. --image dynahug=ghcr.io/d4sun/regenbench/dynahug:0.7.0")
    ap.add_argument("--scanner", action="append", default=None,
                    help="restrict to given scanners (default all)")
    args = ap.parse_args()

    images = dict(DEFAULT_IMAGES)
    for kv in args.image:
        key, _, val = kv.partition("=")
        if key in images:
            images[key] = val
    if args.scanner:
        images = {k: v for k, v in images.items() if k in args.scanner}

    with open(MANIFEST) as f:
        expectations = json.load(f)

    results = []  # (scanner, artifact, expected, actual, ok, problem)
    any_error = False

    for artifact, exp in sorted(expectations.items()):
        fmt = exp.pop("_format", "pkl")
        for scanner, want in exp.items():
            if scanner not in images:
                continue
            actual, problem = run_image(args.backend, images[scanner], artifact, args.tag)
            if problem:
                results.append((scanner, artifact, want, None, False, problem))
                any_error = True
                continue
            got = {"verdict": actual.get("verdict"), "exit_code": actual.get("exit_code")}
            ok = got == want
            results.append((scanner, artifact, want, got, ok, None))
            if not ok:
                any_error = True

    # Report
    print(f"{'SCANNER':<12} {'ARTIFACT':<28} {'EXPECTED':<18} {'ACTUAL':<18} RESULT")
    print("-" * 88)
    for scanner, artifact, want, got, ok, problem in sorted(results):
        if problem:
            print(f"{scanner:<12} {artifact:<28} {'-':<18} {'FAIL':<18} {problem[:40]}")
        else:
            w = f"{want['verdict']}/{want['exit_code']}"
            g = f"{got['verdict']}/{got['exit_code']}"
            print(f"{scanner:<12} {artifact:<28} {w:<18} {g:<18} {'PASS' if ok else 'FAIL'}")
    passed = sum(1 for *_, ok, _ in [(r[0], r[1], r[2], r[3], r[4], r[5])
                                     for r in results] if ok)
    print(f"\n{passed}/{len(results)} assertions passed.")
    sys.exit(0 if (not any_error and results) else 1)


if __name__ == "__main__":
    main()