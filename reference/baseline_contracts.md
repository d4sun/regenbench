# ReGenBench — Specification of Record & Module Contracts

**Date**: 2026-08-22  
**Baseline Tag**: `v1.0-verified-pending`  
**Purpose**: Formal specification of inputs, outputs, invariants, and failure modes for all modules under `pipeline/`. This document serves as the ground truth contract for component-level, container, oracle, and integration testing.

---

## 1. `pipeline/runner.py`

### Contract
- **Inputs**:
  - `Config`: dataclass specifying `backend` (str, e.g. `"podman"`), `tag` (str, e.g. `":latest"`), `max_workers` (int), `timeout` (int seconds), `extensions` (set of admitted file extensions), `min_size` (int bytes), `skip` (set of substring patterns/directory names to exclude), `oracle` (bool enabling dynamic behavioral oracle), `pre_filter` (bool enabling static pre-filter before oracle execution), and `oracle_model_dir` (optional host path to recalibrated DynaHug model directory).
  - `artifacts`: iterable of host artifact paths.
  - `db_path`: optional SQLite database filepath for logging results.
- **Outputs**:
  - List of `ScanResult` dataclass instances sorted by `(artifact, scanner)`. Each `ScanResult` carries `scanner`, `artifact`, `verdict` (`"benign" | "malicious" | "error" | None`), `exit_code` (0, 1, 2, or None), `decision_score` (float or None), `findings` (list), `error` (str or None), `duration` (float seconds).
- **Invariants**:
  - All configuration fields in `Config` are plumbed through to artifact filtering, worker dispatch, and container invocation.
  - If `pre_filter` is True, artifacts lacking registered dangerous callables bypass DynaHug container execution; a synthetic `ScanResult("dynahug", src, "benign", 0, decision_score=0.0, duration=0.0)` is logged to ensure balanced evaluation tables.
  - When `db_path` is specified, `candidates`, `panel_results`, and `oracle_results` records are written transactionally.
- **Failure Modes & Exceptions**:
  - Container execution timeout: returns `ScanResult` with `verdict=None`, `exit_code=None`, `error="timeout running <image> on <src>"`.
  - Non-JSON container output: returns `ScanResult` with `error` set to raw output tail.

---

## 2. `pipeline/scanners.py`

### Contract
- **Inputs**:
  - `run_scan(backend, image_full, src, timeout, oracle_model_dir)`: container backend name, fully qualified image name, host artifact path, timeout integer, optional oracle model directory.
- **Outputs**:
  - Tuple `(parsed_json, error_message)`: `parsed_json` is a dictionary conforming to the unified verdict schema (`docs/verdict-schema.md`); `error_message` is None on success or str on failure.
- **Invariants**:
  - The host artifact path is mounted read-only with the shared SELinux flag (`-v <abs_path>:/artifact:ro,z`).
  - Container-level hard timeout `--timeout <timeout>` is passed to Podman to prevent container orphaning.
  - If `oracle_model_dir` (or `REGENBENCH_ORACLE_MODEL_DIR`) is provided, it is mounted read-only at `/opt/dynahug/recalibrated:ro,z` and `DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated` is set in the container environment.
- **Failure Modes & Exceptions**:
  - Non-existent oracle model dir: returns `(None, "oracle model dir does not exist: ...")`.
  - Subprocess timeout: returns `(None, "timeout running ...")`.
  - Non-zero exit with invalid JSON: returns `(None, "<raw stderr/stdout tail>")`.

---

## 3. `pipeline/comparator.py`

### Contract
- **Inputs**:
  - `check_bypass(panel_verdicts: list[str], oracle_verdict: str) -> bool`: list of string verdicts from panel scanners, single string verdict from dynamic oracle.
- **Outputs**:
  - Boolean flag indicating whether the candidate is a confirmed scanner bypass.
- **Invariants**:
  - Returns `True` if and only if `all(v == "benign" for v in panel_verdicts)` AND `oracle_verdict == "malicious"`.
  - Returns `False` if `panel_verdicts` is empty, if any panel scanner returns `"malicious"` or `"error"`, or if `oracle_verdict` is not `"malicious"`.
- **Failure Modes & Exceptions**:
  - Empty panel list returns `False`. Does not raise exceptions.

---

## 4. `pipeline/fitness.py`

### Contract
- **Inputs**:
  - `compute_fitness(detected_count: int, total_scanners: int, decision_score: float | None) -> float`: number of panel scanners flagging malicious, total panel scanners, DynaHug OCSVM decision score.
- **Outputs**:
  - Continuous float fitness score.
- **Invariants**:
  - Fitness strictly monotonically decreases as `detected_count` increases for any fixed `decision_score`.
  - Formula: `fitness = (total_scanners - detected_count) + 1.0 / (1.0 + abs(decision_score))`.
  - If `decision_score` is None, boundary bonus defaults to `1.0 / (1.0 + 1.0) = 0.5`.
  - Range: for $S$ scanners, fitness lies in $[0.0, S + 1.0]$.
- **Failure Modes & Exceptions**:
  - Pure arithmetic; handles `None` decision scores gracefully without raising.

---

## 5. `pipeline/validity.py`

### Contract
- **Inputs**:
  - `ValidityOracle(container_backend, container_image, timeout)`: class methods `validate_pickle(pkl_bytes, trigger_file)` and `validate_torch(pt_bytes, trigger_file)`.
- **Outputs**:
  - Boolean `True` if candidate artifact (a) unpickles/loads cleanly without exception in the sandbox container and (b) triggers the execution sentinel file within the timeout.
- **Invariants**:
  - Payload execution is always tested inside an isolated container sandbox (`regenbench/base`), never executed directly on the host.
  - Temporary files and sentinel trigger files are cleaned up before and after validation.
  - Uses shared volume mounting (`:ro,z` or `:z`) to prevent SELinux relabel collisions.
- **Failure Modes & Exceptions**:
  - Unpickling crash, missing trigger file, or container timeout returns `False`. Catches all internal subprocess exceptions and returns `False`.

---

## 6. `pipeline/pre_filter.py`

### Contract
- **Inputs**:
  - `is_admitted(file_path: str) -> bool`: path to pickle or PyTorch `.pt` file.
- **Outputs**:
  - Boolean: `True` if candidate contains at least one registered dangerous callable import or is malformed/unparseable (fail-closed); `False` if artifact is provably benign and free of dangerous callables.
- **Invariants**:
  - Inspects both top-level pickle opcodes (`GLOBAL`, `INST`, `STACK_GLOBAL`) and nested payloads (`_pickle.loads(BINBYTES(...))`) up to depth 16.
  - PyTorch `.pt` Zip archives are opened and `data.pkl` is extracted for opcode inspection.
  - Fail-closed: unparseable or corrupted files return `True` to ensure they are analyzed by behavioral dynamic containers.
- **Failure Modes & Exceptions**:
  - Non-existent path returns `False`. Any parsing exception inside `is_admitted` returns `True` (fail-closed).

---

## 7. `pipeline/opcodes.py`

### Contract
- **Inputs**:
  - `parse_pickle(data: bytes) -> list[tuple[OpcodeClassification, bytes]]`: raw pickle byte stream.
- **Outputs**:
  - List of classified `(OpcodeClassification, argument_bytes)` tuples.
- **Invariants**:
  - Opcode taxonomy classifies every CPython opcode into one of 4 categories: `NO_ARG`, `FIXED_ARG`, `LENGTH_PREFIXED`, `DELIMITED`.
  - Reconstruction invariant: `b"".join(op.code + arg for op, arg in parse_pickle(data)) == data` for all valid pickle byte streams.
- **Failure Modes & Exceptions**:
  - Raises `ValueError` on unrecognized opcode bytes or truncated argument streams.

---

## 8. `pipeline/dangerous_callables.yaml` & `pipeline/registry.py`

### Contract
- **Inputs**:
  - `load_registry(yaml_path)`: loads YAML schema of dangerous callables.
  - `is_dangerous(module: str, name: str) -> bool`: query module and callable.
  - `get_armable_entries() -> list[RegistryEntry]`: returns callables suitable for automated candidate generation.
- **Outputs**:
  - Boolean or `RegistryEntry` containing `module`, `name`, `category`, `description`, `genuine_code_exec`.
- **Invariants**:
  - Platform-specific callables (e.g. `nt.*` on Linux) are filtered out at load time.
  - Non-armable sinks (`runpy.run_module`, `pandas.eval`, `sympy.sympify`, `yaml.unsafe_load`) are registered as dangerous sinks but excluded from candidate generator selection to prevent guaranteed validity failures.
- **Failure Modes & Exceptions**:
  - Missing YAML file raises `FileNotFoundError`.

---

## 9. `pipeline/mutators.py`

### Contract
- **Inputs**:
  - `PickleMutator`: methods `mutate_opcode_swap`, `mutate_callable_substitution`, `mutate_argument_fuzz`, `mutate_structural_stacking`, and `mutate`.
- **Outputs**:
  - Mutated pickle `bytes`.
- **Invariants**:
  - `mutate_opcode_swap` restricts swaps to semantically equivalent value opcodes (`NONE`, `NEWTRUE`, `NEWFALSE`) to prevent stack corruption.
  - `mutate_callable_substitution` replaces `GLOBAL`/`INST` targets with callables from the registry.
  - `mutate_argument_fuzz` respects opcode argument width boundaries (e.g. 1-byte, 4-byte, 8-byte ints/floats).
  - All reconstructed mutated streams parse cleanly without truncation.
- **Failure Modes & Exceptions**:
  - Any mutation error falls back safely to returning the original opcode/argument without raising.

---

## 10. `pipeline/templates.py`

### Contract
- **Inputs**:
  - Attack templates: `OverwrittenModuleTemplate`, `PyPIInjectedTemplate`, `ExternalModuleTemplate`.
  - Helpers: `inject_payload_into_pickle`, `inject_payload_into_torch`.
- **Outputs**:
  - Standalone pickle bytes or mutated `.pkl` / `.pt` files with embedded payloads.
- **Invariants**:
  - Generated payload triggers the side effect code upon unpickling and leaves a valid object on the deserialization stack.
  - `inject_payload_into_torch` preserves the PyTorch Zip archive structure, modifies `data.pkl`, and updates PyTorch protocol 4 frame length descriptors if present.
- **Failure Modes & Exceptions**:
  - Invalid source file raises `FileNotFoundError` or `zipfile.BadZipFile`.

---

## 11. `pipeline/generator.py`

### Contract
- **Inputs**:
  - `CandidateGenerator`: `generate_candidate_pickle`, `generate_candidate_pt`.
- **Outputs**:
  - Binary bytes and metadata tuple `(data_bytes, template_name, depth, callables_used)`.
- **Invariants**:
  - Injected payload incorporates a unique trigger sentinel path.
  - Mutation depth governs the number of sequential mutator passes applied.
- **Failure Modes & Exceptions**:
  - Handles seed loading errors by falling back to base synthetic templates.

---

## 12. `pipeline/feedback.py` & `pipeline/coverage.py`

### Contract
- **Inputs**:
  - `CoverageTracker`: tracks discovered opcode bytes and dangerous callable combinations across campaign rounds.
- **Outputs**:
  - Opcode coverage fraction, callable coverage fraction, and mutation priority weights for the next round.
- **Invariants**:
  - Cumulative coverage metrics are monotonically non-decreasing over successive rounds.
- **Failure Modes & Exceptions**:
  - Handles unseen opcodes and malformed inputs gracefully.

---

## 13. `pipeline/db.py`

### Contract
- **Inputs**:
  - Functions: `init_db`, `log_candidate`, `log_campaign_run`, `complete_campaign_run`, `log_panel_result`, `log_oracle_result`, `log_fitness`, `log_coverage`, `get_candidate_summary`.
- **Outputs**:
  - SQLite database records and structured dictionary representations.
- **Invariants**:
  - Foreign key enforcement is enabled (`PRAGMA foreign_keys = ON`).
  - `candidates.candidate_id` is the primary key and foreign key parent for `panel_results`, `oracle_results`, and `campaign_fitness`.
  - Upsert semantics (`ON CONFLICT DO UPDATE`) prevent duplicate insertion errors while preserving previously written metadata.
- **Failure Modes & Exceptions**:
  - Database constraint violations or disk errors trigger automatic transaction rollback.

---

## 14. `pipeline/gguf_tools.py`

### Contract
- **Inputs**:
  - GGUF attack generators for 7 families: `ssti_chat_template`, `tensor_offset_oob`, `kv_data_oob`, `kv_count_overflow`, `tensor_count_overflow`, `string_length_overflow`, `invalid_magic`.
- **Outputs**:
  - Binary GGUF file bytes.
- **Invariants**:
  - Synthesized models follow the GGUF v3 binary specification with little-endian encoding.
  - The `ssti_chat_template` payload embeds a Jinja2 SSTI expression (`os.popen(...)`) targeting CVE-2024-34359.
- **Failure Modes & Exceptions**:
  - Pure binary generation; deterministic without exceptions.
