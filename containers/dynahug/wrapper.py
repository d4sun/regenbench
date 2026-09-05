#!/usr/bin/env python3
"""DynaHug behavioral-oracle wrapper: normalize oracle output to the unified
verdict schema.

DynaHug (Nambiar/Pradhan/Soremekun, arXiv:2604.19438; upstream
DynaHug-Detector/DynaHug @ 8ff8174) is a dynamic ML classifier for
pre-trained models. It executes the model load inside the sandbox, collects
system-call behavior with strace, extracts presence/frequency syscall features,
and flags files as anomalous with a One-Class SVM (decision_function < 0).

This wrapper reimplements the upstream pipeline
(main.py -> src/analysis.py -> src/inference.py -> src/strace_analyzer.py ->
classifier/svm.py) for a single target file, faithful to the paper's default
DynaHug model:

    text-generation/2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best/
    OneClassSVM/params-gamma_0.1_kernel_rbf_nu_0.01

  * Sandbox execution:  torch.no_grad(); torch.load(f, weights_only=False,
    map_location=cpu) -- the same deserialization the upstream training traces
    used (src/inference.py clean_mode).
  * strace collection:  strace -c -f (syscall count summary; upstream Run 2).
  * Feature extraction: parse_strace_count (syscall counts) -> presence_* /
    frequency_* features over classifier/syscalls.txt.
  * OCSVM inference:    vectorizer.transform -> scale frequency_* columns ->
    model.predict + model.decision_function.

Emits one JSON object (docs/verdict-schema.md) with a top-level
`decision_score` (signed OneClassSVM decision_function; benign > 0,
malicious < 0). Exit codes 0 benign / 1 malicious / 2 error.

Faithfulness caveat (accepted behaviour): the embedded text-generation OCSVM was
trained on 2000 real HuggingFace model loads. Arbitrary local artifacts trace
out-of-distribution syscall profiles (import-dominated), which land far from the
model's support region, so the RBF decision_function returns approximately -rho
(-1.35) and the verdict is `malicious` for most inputs. The decision_score is the
informative signal; only a clearly in-distribution benign trace yields a positive
score. This exactly reproduces the pretrained model's behaviour rather than
adding a heuristic bias toward "benign".
"""

import json
import os
import shlex
import subprocess
import sys

VERSION = "0.1.0"
COMMIT = "8ff8174"

TIMEOUT = 120  # upstream src/analysis.py TIMEOUT (seconds)

DYN_HUG_DIR = "/opt/dynahug"
SYSCALLS_FILE = os.path.join(DYN_HUG_DIR, "classifier", "syscalls.txt")
DEFAULT_MODEL_DIR = os.path.join(
    DYN_HUG_DIR,
    "classifier",
    "models",
    "text-generation",
    "2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best",
    "OneClassSVM",
    "params-gamma_0.1_kernel_rbf_nu_0.01",
)
# Overridable so a locally-recalibrated OCSVM (fit on this environment's
# strace profiles) can be used without rebuilding the image.
MODEL_DIR = os.environ.get("DYNAHUG_MODEL_DIR", DEFAULT_MODEL_DIR)
# Optional blank baseline for differential trace subtraction (P2.2 Option A).
# Mounted at /opt/dynahug/recalibrated/blank_baseline.json by run_scan.
BLANK_BASELINE_FILE = os.path.join(MODEL_DIR, "blank_baseline.json")
LOADER = "/usr/local/bin/dynahug-loader"
WORKDIR = "/tmp/dynahug"


def parse_strace_count(file_path):
    """Upstream StraceAnalyzer.parse_strace_count: syscall -> calls summary."""
    counts = {}
    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return counts
    for line in content.split("\n"):
        if (
            line.startswith("% time")
            or line.startswith("------")
            or line.startswith("100.00")
            or line.endswith("...>")
        ):
            continue
        if not line.strip():
            continue
        parts = line.split()
        try:
            calls = int(parts[3])
            syscall = parts[-1]
        except (ValueError, IndexError):
            continue
        counts[syscall] = calls
    return counts


def extract_features(syscall_names, syscall_counts):
    """Upstream SyscallAnomalyDetector.extract_features with
    feature_types=["presence", "frequency"]: produces the feature dict the
    embedded DictVectorizer was trained on."""
    feature_dict = {}
    for syscall in syscall_names:
        value = syscall_counts.get(syscall, 0)
        feature_dict[f"presence_{syscall}"] = 1 if value > 0 else 0
        feature_dict[f"frequency_{syscall}"] = value
    return feature_dict


def run_oracle(target):
    """Run sandbox exec + strace + feature extraction + OCSVM inference.

    Returns (verdict, exit_code, decision_score, details) where details
    carries evidence/raw output for the schema. verdict 'error' when the
    deserialization did not complete (unreadable/invalid artifact)."""
    details = {"count_summary": "", "strace_status": "exit=0", "syscall_hits": []}

    try:
        import joblib  # noqa: F401  (sklearn loaded via joblib-load'd artifacts)
    except ImportError as e:
        return "error", 2, None, {**details, "load_failure": str(e)}

    # 1. Sandbox execution + strace collection (upstream Run 2, count pass).
    os.makedirs(WORKDIR, exist_ok=True)
    count_log = os.path.join(WORKDIR, "dynahug_count.log")
    try:
        os.unlink(count_log)
    except OSError:
        pass

    cmd = (
        f"timeout --preserve-status --signal=TERM {TIMEOUT}s "
        f"strace -c -f -o {count_log} python3.13 {LOADER} "
        f"{shlex.quote(target)}"
    )
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    status = "exit=0" if proc.returncode == 0 else f"exit={proc.returncode}"
    details["strace_status"] = status

    try:
        with open(count_log, "r", errors="replace") as f:
            details["count_summary"] = f.read()
    except OSError:
        details["count_summary"] = ""

    # A non-zero child exit means torch.load failed: the artifact cannot be
    # deserialized, so there is no behavioral signal to score.
    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip().splitlines()[-3:]
        details["deserialization_error"] = "\n".join(stderr_tail) or str(proc.returncode)
        return "error", 2, None, details

    syscall_counts = parse_strace_count(count_log)
    if not syscall_counts:
        return "error", 2, None, {**details, "load_failure": "empty strace count summary"}

    # Differential trace: subtract blank baseline (Python/torch startup noise)
    # to match the feature space the recalibrated OCSVM was trained on.
    if os.path.exists(BLANK_BASELINE_FILE):
        try:
            with open(BLANK_BASELINE_FILE, "r") as f:
                blank_counts = json.load(f)
            diff_counts = {}
            for sc, cnt in syscall_counts.items():
                base = blank_counts.get(sc, 0)
                diff = cnt - base
                diff_counts[sc] = max(0, diff)
            # Also include syscalls only in blank (should be 0 diff)
            syscall_counts = diff_counts
            details["differential"] = True
        except Exception:  # noqa: BLE001
            details["differential"] = False
    else:
        details["differential"] = False

    # 2/3. Load OCSVM artifacts + build features.
    try:
        model = joblib.load(os.path.join(MODEL_DIR, "oneclass_svm_model.pkl"))
        vectorizer = joblib.load(os.path.join(MODEL_DIR, "vectorizer.pkl"))
        scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    except Exception as e:  # noqa: BLE001
        return "error", 2, None, {**details, "load_failure": f"model artifacts: {e}"}

    with open(SYSCALLS_FILE, "r") as f:
        syscall_names = [ln.strip() for ln in f if ln.strip()]

    feature_dict = extract_features(syscall_names, syscall_counts)

    # 4. OCSVM inference (upstream SyscallAnomalyDetector.predict).
    try:
        X_counts = vectorizer.transform([feature_dict])
        feature_names = vectorizer.get_feature_names_out()
        frequency_indices = [i for i, n in enumerate(feature_names) if n.startswith("frequency_")]
        X_scaled = X_counts.copy()
        if frequency_indices:
            X_scaled[:, frequency_indices] = scaler.transform(X_counts[:, frequency_indices])
        prediction = int(model.predict(X_scaled)[0])
        decision_score = float(model.decision_function(X_scaled)[0])
    except Exception as e:  # noqa: BLE001
        return "error", 2, None, {**details, "load_failure": f"inference: {e}"}

    present = sorted(
        ((sc, n) for sc, n in syscall_counts.items() if n > 0),
        key=lambda kv: (-kv[1], kv[0]),
    )
    details["syscall_hits"] = [{"syscall": sc, "calls": n} for sc, n in present]

    if prediction == -1:
        verdict, exit_code = "malicious", 1
    else:
        verdict, exit_code = "benign", 0

    return verdict, exit_code, decision_score, details


def emit(obj) -> int:
    print(json.dumps(obj))
    return obj.get("exit_code", 2)


def main() -> int:
    base = {
        "scanner": "dynahug",
        "version": VERSION,
        "commit": COMMIT,
        "target": "",
        "verdict": "error",
        "exit_code": 2,
        "decision_score": None,
        "findings": [],
        "summary": {"scanned_files": 0, "infected_files": 0, "dangerous": 0, "suspicious": 0},
        "raw_output": "",
    }

    if len(sys.argv) < 2:
        return emit({**base, "raw_output": "Missing required target path"})

    target = sys.argv[1]
    if not os.path.exists(target):
        return emit({**base, "target": target, "raw_output": f"Path {target} does not exist"})

    verdict, exit_code, decision_score, details = run_oracle(target)

    raw = [
        f"dynahug {VERSION} (commit {COMMIT}) | strace status: {details.get('strace_status')}",
    ]
    if "deserialization_error" in details:
        raw.append("--- deserialization failed (no behavioral signal) ---")
        raw.append(details["deserialization_error"])
    if "load_failure" in details:
        raw.append(f"--- analysis error: {details['load_failure']} ---")
    count_summary = details.get("count_summary", "")
    if count_summary:
        raw.append("--- strace -c -f summary ---")
        raw.append(count_summary.strip())
    hits = details.get("syscall_hits", [])
    if hits:
        raw.append("--- syscalls observed ---")
        raw.extend(f"{h['calls']} {h['syscall']}" for h in hits)
    raw_output = "\n".join(raw)[:20000]

    return emit({
        **base,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "decision_score": decision_score,
        "findings": hits,
        "summary": {
            "scanned_files": 1,
            "infected_files": 1 if verdict == "malicious" else 0,
            "dangerous": 1 if verdict == "malicious" else 0,
            "suspicious": 0,
        },
        "raw_output": raw_output,
    })


if __name__ == "__main__":
    sys.exit(main())