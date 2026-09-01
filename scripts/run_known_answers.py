#!/usr/bin/env python3
"""Phase 5 — Known-answer regression corpus + upstream cross-check.

Builds a deterministic corpus of hand-crafted artifacts (raw pickles and
PyTorch zip checkpoints, benign and malicious, including the nested-payload
evasion class), runs every panel scanner container against them, and compares
the resulting verdict matrix against a pinned baseline manifest.

Modes
-----
  (default)          Compare against reference/known_answers_manifest.json;
                     exit non-zero on any verdict drift or artifact hash drift.
  --update-baseline  Record current verdicts as the new baseline (use after an
                     intentional change; the diff must be reviewed).
  --gguf-holdout N   Additionally sample N crawled-benign GGUF models through
                     the ggufref oracle container and require load_ok=true,
                     plus two crafted malformed GGUFs requiring load_ok=false.

The upstream cross-check is always performed for picklescan and fickling: the
upstream CLI is invoked directly inside the same image (bypassing our
wrapper entrypoint) and its exit code must agree with the wrapper verdict.

Usage:
    python3 scripts/run_known_answers.py [--update-baseline] [--gguf-holdout N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from pipeline.scanners import SCANNERS, full_image, run_scan  # noqa: E402

TAG = ":latest"
BACKEND = "podman"
ART_DIR = REPO / "reference" / "known_answers"
MANIFEST = REPO / "reference" / "known_answers_manifest.json"
REPORT = REPO / "reference" / "known-answers-report.json"
GGUF_CORPUS = REPO / "data" / "gguf_benign_corpus"

PANEL = ["picklescan", "modelscan", "fickling", "modeltracer"]

# Crawled-benign GGUF files the reference reader (gguf==0.19.0) refuses.
# Verified 2026-08-22: stories260K-infill.gguf carries a duplicate
# 'GGUF.version' KV entry ("Duplicate GGUF.version already in list at
# offset 69"), so it cannot serve as loadable-benign ground truth.
GGUF_KNOWN_BAD = {
    "data/gguf_benign_corpus/tinyllamas/stories260K-infill.gguf",
}

# Fixed timestamp keeps zip archives byte-reproducible across runs.
_ZIP_DATE = (2026, 1, 1, 0, 0, 0)


# --------------------------------------------------------------------------
# Deterministic artifact builders
# --------------------------------------------------------------------------

def _zip_write(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    zi = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = 0o600 << 16
    zf.writestr(zi, data)


def _torch_zip(data_pkl: bytes) -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        _zip_write(z, "archive/version", b"3")
        _zip_write(z, "archive/data.pkl", data_pkl)
    return buf.getvalue()


def _reduce(module: str, func: str, arg: str) -> bytes:
    """PROTO-2 GLOBAL reduce leaving the call result on the stack."""
    return (
        b"\x80\x04"
        + f"c{module}\n{func}\n".encode()
        + b"(S'" + arg.encode() + b"'\ntR."
    )


def _nested_loads(inner: bytes) -> bytes:
    """Evasion-class artifact: GLOBAL(_pickle, loads)(BINBYTES(inner))."""
    return (
        b"\x80\x05c_pickle\nloads\n"
        + b"B" + struct.pack("<I", len(inner)) + inner
        + b"\x85R."
    )


def build_artifacts() -> dict[str, bytes]:
    evil_reduce = _reduce("os", "system", "true")
    return {
        # -- benign ---------------------------------------------------------
        "benign_dict.pkl": __import__("pickle").dumps(
            {"model": "tiny", "weights": [0.1, 0.2], "meta": {"ok": True}},
            protocol=4),
        "benign_strings.pkl": __import__("pickle").dumps(
            ["alpha", "beta", ""], protocol=2),
        "benign_torch.pt": _torch_zip(
            __import__("pickle").dumps({"layer.weight": [0.0] * 4}, protocol=2)),
        # -- plainly malicious ----------------------------------------------
        "evil_global_os_system.pkl": evil_reduce,
        "evil_builtins_eval.pkl": _reduce(
            "builtins", "eval", "__import__('os').system('true')"),
        "evil_inst_form.pkl": (
            b"\x80\x02ios\nsystem\n(S'true'\ntR."),
        "evil_stack_global.pkl": (
            b"\x80\x04"
            b"\x8c\x02os\x8c\x06system\x93"
            b"\x8c\x04true\x85R."),
        "evil_global_in_torch.pt": _torch_zip(evil_reduce),
        # -- evasion class: hidden nested payload ---------------------------
        "bypass_nested_loads.pkl": _nested_loads(evil_reduce),
        "bypass_nested_loads_in_torch.pt": _torch_zip(_nested_loads(evil_reduce)),
        # -- malformed --------------------------------------------------------
        "malformed_truncated.pkl": b"\x80\x04X\xff\xff\xff\xffab",
        "malformed_bad_opcode.pkl": b"\x80\x04\xff\x00\x01",
    }


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Upstream CLI cross-check (outside the wrapper)
# --------------------------------------------------------------------------

def _direct_cli(image_full: str, entrypoint: str, args: list[str]) -> int:
    src = ART_DIR
    cmd = [BACKEND, "run", "--rm",
           "-v", f"{src}:/artifact:ro,z",
           "--entrypoint", entrypoint, image_full] + args
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=315)
    return proc.returncode


def upstream_verdict(scanner: str, rel_path: str) -> tuple[str | None, int]:
    """Run the upstream CLI directly and translate rc -> unified verdict."""
    image = full_image(SCANNERS[scanner]["image"], TAG)
    target = f"/artifact/{rel_path}"
    rc = _direct_cli(image, scanner, ["--path", target]) \
        if scanner == "picklescan" \
        else _direct_cli(image, scanner, ["--check-safety", target])
    if rc == 0:
        return "benign", rc
    if rc == 1:
        return "malicious", rc
    return "error", rc


# --------------------------------------------------------------------------
# GGUF holdout
# --------------------------------------------------------------------------

def _gguf_run(path: Path) -> bool:
    from pipeline.scanners import run_scan
    out, err = run_scan(BACKEND, full_image(SCANNERS["ggufref"]["image"], TAG),
                        str(path), timeout=315, gguf_ref=True)
    if err or out is None:
        return False
    return bool((out.get("summary") or {}).get("load_ok"))


def gguf_holdout(n: int) -> list[dict]:
    files = sorted(f for f in GGUF_CORPUS.rglob("*.gguf")
                   if str(f.relative_to(REPO)) not in GGUF_KNOWN_BAD)
    skipped = len(list(GGUF_CORPUS.rglob("*.gguf"))) - len(files)
    if skipped:
        print(f"[known-answers] gguf holdout: {skipped} file(s) excluded "
              f"via GGUF_KNOWN_BAD")
    if not files:
        print(f"[known-answers] no GGUF corpus under {GGUF_CORPUS}", file=sys.stderr)
        return []
    rng = random.Random(20260822)
    sample = rng.sample(files, min(n, len(files)))
    results = [{"file": str(f.relative_to(REPO)), "expect": "load_ok",
                "observed": "load_ok" if _gguf_run(f) else "reject"}
               for f in sample]
    # Crafted malformed headers must be rejected by the reference reader:
    # the 6 vellaveto families (generated by pipeline/gguf_tools.py) plus two
    # ad-hoc malformed cases (bad magic / truncated header).
    from pipeline.gguf_tools import GGUF_ATTACKS, GGUF_ATTACK_LABELS, generate_candidate_gguf
    bad_dir = ART_DIR / "gguf_malformed"
    bad_dir.mkdir(parents=True, exist_ok=True)
    bad_cases = {
        "bad_magic.gguf": b"NOPE" + b"\x00" * 32,
        "truncated_header.gguf": b"GGUF\x03\x00\x00\x00\x01\x00\x00",
    }
    for fam in GGUF_ATTACKS:
        if fam == "ssti_chat_template":
            continue  # SSTI loads OK (render-time attack, not parse-time)
        bad_cases[GGUF_ATTACK_LABELS[fam] + ".gguf"] = generate_candidate_gguf(fam)
    for name, blob in bad_cases.items():
        p = bad_dir / name
        p.write_bytes(blob)
        results.append({"file": f"reference/known_answers/gguf_malformed/{name}",
                        "expect": "reject",
                        "observed": "load_ok" if _gguf_run(p) else "reject"})
    return results


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--gguf-holdout", type=int, metavar="N", default=0)
    ap.add_argument("--scanners", nargs="*", default=PANEL,
                    choices=PANEL, help="subset of panel scanners to run")
    args = ap.parse_args()

    ART_DIR.mkdir(parents=True, exist_ok=True)
    artifacts = build_artifacts()

    # Materialize + integrity-check against pinned hashes when a baseline exists.
    baseline = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else None
    hash_drift: list[str] = []
    for name, blob in sorted(artifacts.items()):
        path = ART_DIR / name
        path.write_bytes(blob)
        if baseline and name in baseline.get("artifacts", {}):
            pinned = baseline["artifacts"][name]["sha256"]
            if pinned != sha256(blob):
                hash_drift.append(name)

    images = {n: full_image(SCANNERS[n]["image"], TAG) for n in args.scanners}
    observed: dict[str, dict[str, str | None]] = {}
    durations: dict[str, float] = {}
    t_start = time.time()
    for name in sorted(artifacts):
        observed[name] = {}
        for scanner, image in images.items():
            out, err = run_scan(BACKEND, image, str(ART_DIR / name))
            observed[name][scanner] = None if (err or out is None) \
                else out.get("verdict")
            durations[f"{name}:{scanner}"] = round(time.time() - t_start, 1)

    # Upstream CLI agreement for the two wrappers that embed a real CLI.
    crosscheck: dict[str, dict] = {}
    raw_pkls = [n for n in sorted(artifacts) if n.endswith(".pkl")]
    for scanner in ("picklescan", "fickling"):
        if scanner not in images:
            continue
        rows = {}
        for name in raw_pkls:
            up, rc = upstream_verdict(scanner, name)
            wrap = observed[name].get(scanner)
            rows[name] = {"upstream": up, "upstream_rc": rc, "wrapper": wrap,
                          "agree": up == wrap}
        crosscheck[scanner] = rows

    failures: list[str] = []
    if hash_drift:
        failures += [f"artifact hash drift: {n}" for n in hash_drift]

    if args.update_baseline or baseline is None:
        manifest = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": "Pinned panel-verdict matrix for hand-built known-answer "
                    "corpus; regenerate via scripts/run_known_answers.py.",
            "artifacts": {
                name: {"sha256": sha256(blob), "expected": observed[name]}
                for name, blob in sorted(artifacts.items())
            },
        }
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"[known-answers] baseline written: {MANIFEST}")
    else:
        for name, rec in sorted(baseline["artifacts"].items()):
            for scanner, expected in rec["expected"].items():
                if scanner not in images:
                    continue
                got = observed[name].get(scanner)
                if got != expected:
                    failures.append(
                        f"verdict drift {name}/{scanner}: "
                        f"expected {expected!r}, got {got!r}")

    for scanner, rows in crosscheck.items():
        for name, row in rows.items():
            if not row["agree"]:
                failures.append(
                    f"upstream disagreement {scanner}/{name}: "
                    f"CLI={row['upstream']!r}(rc={row['upstream_rc']}) "
                    f"wrapper={row['wrapper']!r}")

    gguf_rows: list[dict] = []
    if args.gguf_holdout:
        gguf_rows = gguf_holdout(args.gguf_holdout)
        for r in gguf_rows:
            want = r["expect"]
            got = r["observed"]
            if got != want:
                failures.append(f"gguf holdout {r['file']}: want {want}, got {got}")

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "update-baseline" if args.update_baseline else "check",
        "scanners": list(images),
        "matrix": observed,
        "upstream_crosscheck": crosscheck,
        "gguf_holdout": gguf_rows,
        "failures": failures,
        "ok": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2) + "\n")

    status = "OK" if not failures else f"{len(failures)} FAILURES"
    print(f"[known-answers] {len(observed)} artifacts x {len(images)} scanners "
          f"-> {status}; report: {REPORT}")
    for f in failures:
        print(f"  FAIL {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
