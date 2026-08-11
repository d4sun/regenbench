#!/usr/bin/env python3
"""ModelTracer wrapper: normalize dynamic scanner output to the unified schema.

ModelTracer (Casey et al., arXiv:2410.04490; upstream s2e-lab/hf-model-analyzer
@ 5725b26) is a dynamic scanner: it executes the model load inside the sandbox
while tracing Python callbacks (sys.settrace) and system calls (strace), then
flags files that issue suspicious syscalls (execve/connect/socket/chmod after
the initial python execve).

This wrapper reimplements the upstream tracing + detection logic with corrected
loaders (upstream passes path strings to pickle.load/dill.load and does not
disable torch weights_only, both of which break the scan) and emits one JSON
object (docs/verdict-schema.md) to stdout. Exit codes 0 benign / 1 malicious /
2 error.
"""

import csv
import inspect
import json
import opcode
import os
import re
import subprocess
import sys

VERSION = "0.1.0"
COMMIT = "5725b26"

# Upstream commands_of_interest (scripts/parse_tracer.py).
SUSPICIOUS_SYSCALLS = {"execve", "connect", "socket", "chmod"}

# Corrected loaders. Upstream bugs fixed here:
#   * pickle.load/dill.load called with a path string (invalid) -> open() first.
#   * torch.load defaults to weights_only=True on torch >= 2.6, which blocks
#     execution -> pass weights_only=False so the payload runs and is traced.
#   * numpy.load defaults to allow_pickle=False on numpy 2.x -> pass True.
# The framework import happens OUTSIDE the traced region (importing torch under
# sys.settrace opcode tracing is pathologically slow / can deadlock); the traced
# region is just the load expression. P is the json.dumps'd target path.
LOADER_IMPORTS = {
    "pickle": "import pickle",
    "dill": "import dill",
    "joblib": "import joblib",
    "torch": "import torch",
    "numpy": "import numpy",
    "TorchScript": "import torch",
}
LOAD_EXPRS = {
    "pickle": "pickle.load(open(P, \"rb\"))",
    "dill": "dill.load(open(P, \"rb\"))",
    "joblib": "joblib.load(P)",
    "torch": "torch.load(P, map_location=torch.device(\"cpu\"), weights_only=False)",
    "numpy": "numpy.load(P, allow_pickle=True)",
    "TorchScript": "torch.jit.load(P)",
}
METHODS = list(LOAD_EXPRS)

WORKDIR = "/tmp/modeltracer"

# strace -f output lines are "<pid>\t<timestamp> <syscall>(...)".
SYSCALL_RE = re.compile(r"^(?:\d+\s+)?\d{2}:\d{2}:\d{2}(?:\.\d{6})?\s+([A-Za-z0-9_]+)\(")


def emit(record: dict) -> int:
    print(json.dumps(record))
    return record["exit_code"]


def detect_method(path: str) -> str:
    """Infer serialization method from magic bytes, else file extension."""
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
    except OSError:
        magic = b""
    if magic.startswith(b"\x93NUMPY"):
        return "numpy"
    if magic.startswith(b"PK\x03\x04"):
        return "torch"
    name = path.lower()
    if name.endswith((".pt", ".pth", ".bin", ".ckpt")):
        return "torch"
    if name.endswith((".npy", ".npz")):
        return "numpy"
    if name.endswith(".joblib"):
        return "joblib"
    return "pickle"


def tracer_callback(writer):
    """Mirror upstream scripts/model_tracer.py trace_with_csv()."""
    def analyze(frame, event, arg):
        frame.f_trace_opcodes = True
        try:
            function_code = frame.f_code
            offset = frame.f_lasti
            function_name = function_code.co_name
            if offset >= len(function_code.co_code):
                return analyze
            opcode_name = opcode.opname[function_code.co_code[offset]]
            if "CALL" not in opcode_name or "PRECALL" in opcode_name:
                return analyze
            lineno = frame.f_lineno
            if lineno is None:
                return analyze
            try:
                source_lines, start = inspect.getsourcelines(function_code)
                actual_line = source_lines[lineno - start]
            except (OSError, IndexError):
                actual_line = ""
            variables = []
            for name in frame.f_locals:
                try:
                    value = repr(frame.f_locals[name])
                    if len(value) > 80:
                        value = value[:80] + "..."
                except Exception:
                    value = "<unprintable>"
                variables.append(f"{name}={value}")
            writer.writerow([event, function_name, lineno, actual_line.strip(), variables])
        except Exception:
            pass
        return analyze
    return analyze


def trace_python_level(path: str, method: str, tracer_csv: str) -> str:
    """In-process sys.settrace load; best-effort evidence only (upstream analyze_files).

    The framework module is imported before tracing so opcode tracing covers
    only the load call, mirroring upstream model_tracer.py which imports all
    frameworks at module top.
    """
    if method not in LOAD_EXPRS:
        return "skipped"
    try:
        ns = {}
        exec(LOADER_IMPORTS[method], ns)
        expr = LOAD_EXPRS[method].replace("P", json.dumps(path))
        with open(tracer_csv, "w") as out:
            writer = csv.writer(out)
            writer.writerow(["event", "function_name", "line_number", "line", "variables"])
            sys.settrace(tracer_callback(writer))
            try:
                # Payloads may print during the inline load (including in
                # forked children, which write to fd 1/2 directly, bypassing
                # sys.stdout). Redirect at the fd level so the schema object
                # stays the only thing on stdout.
                sink_fd = os.open(os.devnull, os.O_WRONLY)
                saved_1, saved_2 = os.dup(1), os.dup(2)
                os.dup2(sink_fd, 1)
                os.dup2(sink_fd, 2)
                try:
                    result = eval(expr, ns)
                    del result
                finally:
                    os.dup2(saved_1, 1)
                    os.dup2(saved_2, 2)
                    os.close(saved_1)
                    os.close(saved_2)
                    os.close(sink_fd)
            finally:
                sys.settrace(None)
        return "traced"
    except Exception as e:
        sys.settrace(None)
        return f"failed ({type(e).__name__})"


def run_strace(path: str, method: str, out_file: str) -> str:
    """Trace syscalls of the load (upstream run_strace)."""
    expr = LOAD_EXPRS[method].replace("P", json.dumps(path))
    loader = f"{LOADER_IMPORTS[method]}; {expr}; print('LOAD_OK')"
    cmd = [
        "strace", "-f", "-tt", "-T", "-y", "-yy", "-s", "2048",
        "-o", out_file,
        "python3.13", "-c", loader,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "timed_out"
    # exit=0 means the loader succeeded; python -c exits 1 on uncaught exception.
    return f"exit={proc.returncode}"


def analyze_strace(out_file: str) -> tuple:
    """Parse strace output; drop the first execve; flag suspicious syscalls.

    Mirrors upstream parse_tracer.py analyse_files(): the first execve is the
    python launch (benign); any subsequent execve/connect/socket/chmod is
    suspicious.
    """
    suspicious = []
    lines = []
    first_execve_seen = False
    try:
        with open(out_file, encoding="utf-8") as f:
            for raw in f:
                line = raw.rstrip("\n")
                lines.append(line)
                m = SYSCALL_RE.match(line)
                if not m:
                    continue
                syscall = m.group(1)
                if syscall == "execve" and not first_execve_seen:
                    first_execve_seen = True
                    continue
                if syscall in SUSPICIOUS_SYSCALLS:
                    suspicious.append(line)
    except OSError:
        return [], []
    return suspicious, lines


def main() -> int:
    if len(sys.argv) < 2:
        return emit({
            "scanner": "modeltracer",
            "version": VERSION,
            "commit": COMMIT,
            "target": "",
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned_files": 0, "infected_files": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": "Missing required target path",
        })

    target = sys.argv[1]
    if not os.path.exists(target):
        return emit({
            "scanner": "modeltracer",
            "version": VERSION,
            "commit": COMMIT,
            "target": target,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned_files": 0, "infected_files": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": f"Path {target} does not exist",
        })

    os.makedirs(WORKDIR, exist_ok=True)

    if len(sys.argv) >= 3 and sys.argv[2] in METHODS:
        methods = [sys.argv[2]]
    else:
        detected = detect_method(target)
        methods = [detected] + [m for m in METHODS if m != detected]

    attempts = []
    selected = None  # (method, suspicious, lines, strace_status)
    for method in methods:
        strace_file = os.path.join(WORKDIR, f"strace_{method}.txt")
        tracer_csv = os.path.join(WORKDIR, f"tracer_{method}.csv")
        python_trace = trace_python_level(target, method, tracer_csv)
        strace_status = run_strace(target, method, strace_file)
        suspicious, lines = analyze_strace(strace_file)
        attempts.append({"method": method, "python_trace": python_trace, "strace": strace_status})
        if suspicious:
            selected = (method, suspicious, lines, strace_status)
            break
        if strace_status == "exit=0":
            selected = (method, suspicious, lines, strace_status)
            break

    method, suspicious, lines, strace_status = selected or (methods[0], [], [], "exit=1")

    findings = [
        {"syscall": m.group(1) if (m := SYSCALL_RE.match(line)) else "", "evidence": line}
        for line in suspicious
    ]

    if suspicious:
        verdict, exit_code = "malicious", 1
    elif strace_status == "exit=0":
        verdict, exit_code = "benign", 0
    else:
        verdict, exit_code = "error", 2

    raw = []
    for step in attempts:
        raw.append(f"[{step['method']}] python_level:{step['python_trace']} strace:{step['strace']}")
    if suspicious:
        raw.append(f"--- suspicious syscalls ({method}) ---")
        raw.extend(suspicious)
    if lines:
        raw.append(f"--- strace excerpt ({method}, {len(lines)} lines) ---")
        raw.extend(lines[:8])
    raw_output = "\n".join(raw)[:20000]

    return emit({
        "scanner": "modeltracer",
        "version": VERSION,
        "commit": COMMIT,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": findings,
        "summary": {
            "scanned_files": 1,
            "infected_files": 1 if verdict == "malicious" else 0,
            "dangerous": len(findings),
            "suspicious": 0,
        },
        "raw_output": raw_output,
    })


if __name__ == "__main__":
    sys.exit(main())