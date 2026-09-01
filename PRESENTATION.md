# ReGenBench — Presentation Defense Prep

Standalone rehearsal doc for the 10-minute presentation and the Q&A that
follows. It assumes the reviewer can see the repo (`RESULTS.md`,
`ARCHITECTURE.md`, `IMPLEMENTATION.md`) and can run the live DB queries in
§6. Numbers here are the **corrected, verified** ones (post-Fickling
investigation, Phase 0 of the format-unification).

---

## 1. Thesis (the one-sentence reframe)

> **"ReGenBench is a format-agnostic scanner benchmark: it ingests ML-artifact
> formats (currently PyTorch pickles and GGUF), routes each to the
> format-capable scanner subset, confirms payload execution via format-specific
> sandbox oracles, and measures per-scanner evasion and attack-primitive
> coverage. In this pilot we fully exercised the pickle surface and validated
> the GGUF surface; the confirmed-bypass results are genuine against the
> format-native static panel."**

Do **not** claim: "coverage-guided fuzzing discovers novel attack families."
Claim instead: "it identifies which attack families the scanners have *actually
patched* versus which remain exploitable at scale" (see §3, weakness 1).

---

## 2. Key numbers (memorize these)

| Metric | Value |
|--------|-------|
| Corpus | 100 real HF checkpoints, 5 clusters × 20, SHA-256 dedup, no synthetics |
| Pickle panel (format-native) | **PickleScan + ModelScan** (Fickling excluded: torch-zip format gap) |
| Guided confirmed bypasses | 223 / 473 (47.1%) |
| Unguided confirmed bypasses | 74 / 401 (18.5%) |
| ShadowPickle baseline | 20 / 80 (25.0%) |
| **H1** | **Supported**: fuzzing 34.0% vs baseline 25.0% |
| **H2** | **Valid negative**: uncorroborated == confirmed (297 == 297) |
| **H3** | **Supported**: ~99.3–100% retention × 6 historical versions |
| PickleScan evasion | 34.0% (297/874) |
| ModelScan evasion | 51.5% (450/874) |
| Fickling | **N/A on torch** (`fickling --trace` → "No pickle files detected") |
| GGUF surface | 10 attack families: ggufref detects **7/10** (baseline SSTI + 6 malformed); **3 obfuscated-SSTI confirmed bypasses**; real-corpus FP **0/24** |
| Cross-format | `pt` 973/874/**297** (34.0%); `gguf` 35/28/**3** (10.7%) |
| Bypass-family entropy | guided 0.0, unguided ~0.30 (all `pypi_injected` except 4 gadget) |
| GGUF execution oracle | **strace-based** (`execve` syscall observation), decoupled from static detection |
| FP over 100 benign | PickleScan 0%, ModelScan 0%, DynaHug 94% (supplementary), Fickling N/A |
| Monitor | detection 100%, false-alarm 0% |
| Pre-filter | ~1.3–1.9× throughput (host/timing-dependent, see `docs/perf-report.md`) |

---

## 3. The five weaknesses and how to answer them

### Weakness 1 — "One-trick pony": all bypasses are `pypi_injected`
**Q:** *"If you removed `pypi_injected`, would your bypass rate drop to ~0%? Is this really discovering novel bypasses?"*

**A (honest, turns it into a finding):**
- Yes — 293/297 confirmed bypasses are `pypi_injected` via `splice`; the other 4 are `gadget`. Bypass-family Shannon entropy is 0.0 (guided) / 0.30 (unguided).
- That is **not** a generator failure — it is a **scanner-bias finding**: the panel has patched ShadowPickle's `overwritten`, `gadget`, `external`, and `indirect_chain` vectors, but `pypi_injected` callables (`IPython.utils.process.system`) remain a residual blind spot.
- *"Our benchmark's value is identifying which attack families the scanners have actually patched versus which remain exploitable at scale."* (Per-scanner: PickleScan 34%, ModelScan 51.5% — the panel as a whole misses only via the `pypi_injected` vector.)

### Weakness 2 — H2 framed defensively
**Q:** *"What does the dual-oracle actually buy you?"*

**A:**
- The static panel already catches all non-executing candidates (uncorroborated == confirmed, 297 == 297), so DynaHug adds no *filtering* precision — and it has a 94% FP rate on benign traces anyway.
- The value of dynamic analysis is **execution confirmation**: the ExecutionOracle (trigger polling / StraceOracle, 0% FP) proves the payload *executed*, turning "scanner says benign" into "benign **and** executed".
- *"Future work should invest in deterministic sandbox traces, not statistical ML oracles."*

### Weakness 3 — Coverage vs diversity
**Q:** *"You report 100% callable coverage but one family dominates. Contradiction?"*

**A:**
- Coverage tracks **exploration** (the generator mutated many distinct callables — callable coverage reached 100%); confirmed bypasses track **exploitation** (what the panel permits to evade — only `pypi_injected`).
- Sampling family entropy (quota-driven) was 1.43–1.57; **bypass-family** entropy is ~0. These are different axes. The divergence is the finding: high exploration, but the panel gates evasion to one vector.

### Weakness 4 — Fickling
**Q:** *"Why does Fickling 'evade' everything? Did you verify it parses your files?"*

**A (we did the diagnostic — this is now a strength):**
- `fickling --trace` on a confirmed bypass `.pt` returns `No pickle files detected` (RC 2) — **Fickling cannot parse torch-zip checkpoints natively**.
- Fickling is a **raw-pickle AST analyzer**, so it is a **format-coverage-gap scanner for torch**, not a 100%-evaded scanner. It is excluded from the `.pt` panel (`SCANNERS` exts → `{.pkl}`) and reports `unsupported-format:torch-zip` when handed a `.pt` directly. It still detects malicious raw `.pkl` (verified on `ci/corpus/pkl/malicious`).
- This is the same class of wrapper/normalization bug the review warned about; we root-caused it, fixed the allowlist over-suppression, and re-measured. The 297 pickle bypasses are genuine against PickleScan + ModelScan.

### Weakness 5 — "Self-regenerating"
**Q:** *"Is this self-regenerating, or feedback-guided fuzzing?"*

**A:**
- Use **"coverage-guided, feedback-driven fuzzing"**. The system adjusts family/callable sampling weights from round feedback; it does not invent new templates autonomously. Be precise; don't overclaim.

---

## 3.5 Methodological correction — GGUF oracle decoupling (Slide 8.5)

> **Problem.** Initial GGUF results showed **0 confirmed bypasses**. Root cause: the GGUF execution-confirmation mechanism (trigger-file polling) was **coupled** to ggufref's static `triggered` detection — any payload that executed was automatically caught. A confirmed bypass was structurally impossible.
>
> **Fix.** Decoupled execution confirmation from static detection by adding a **strace-based GGUF execution oracle** (`containers/gguf/loader.py --strace-mode`): execution is confirmed by observing `execve` syscalls during the Jinja2 render, independent of `SSTI_SIGNALS` / trigger polling. This mirrors the pickle-side StraceOracle (the same lesson that demoted DynaHug's 94%-FP statistical oracle).
>
> **Result.** Obfuscated SSTI payloads (Jinja2 `attr` + string-split — a real Flask/Jinja2 RCE technique) avoid all 13 static signals while staying execution-confirmed via `execve`. **3 confirmed GGUF bypasses** (ggufref benign + modelscan benign + executed). Baseline SSTI + 6 malformed are still detected (ggufref **7/10**).
>
> **Lesson.** Benchmarks must not couple their validity oracle with their detection oracle. This correction strengthens both the pickle and GGUF pipelines.

**Rehearse the line:** *"We corrected a benchmark design flaw by decoupling execution confirmation from static detection, consistent with our pickle-side methodology."*

---

## 3.6 GGUF Q&A (rehearsed answers)

**Q1 — "Why is the GGUF yield (10.7%) so much lower than pickle (34%)?"**
> The GGUF surface is narrower (10 attack families vs the pickle pipeline's 5
> families + 11 evasion strategies). More importantly, `ggufref` is a **reference
> oracle designed for correctness**, not a production scanner with heuristic
> shortcuts. The 3 bypasses are significant because they prove that even a
> correct reference implementation can miss obfuscated SSTI when relying on
> static substring detection. The yield difference reflects surface breadth,
> not pipeline weakness.

**Q2 — "Did you just move the goalposts to get non-zero GGUF bypasses?"**
> No. The initial 0-bypass result exposed a benchmark design flaw: execution
> confirmation and static detection shared the same mechanism. We fixed it by
> applying the same architectural lesson learned on the pickle side — demoting
> DynaHug's statistical oracle in favor of deterministic strace confirmation.
> The strace oracle was already part of our pickle pipeline; extending it to
> GGUF is **methodological consistency, not goalpost movement**.

**Q3 — "Is 3 bypasses statistically significant?"**
> In isolation, 3 is a small absolute number. But these are confirmed bypasses
> against a reference oracle that was catching 100% before the fix. The
> significance is architectural: decoupling execution confirmation from static
> detection enables the benchmark to find bypasses that would otherwise be
> structurally impossible. The number validates the design correction, not the
> attack-surface breadth.

**Q4 — "Why is GGUF less important than pickle?"**
> The pickle surface is mature and widely deployed (1M+ models on HF), so
> scanner evasion is critical. The GGUF surface is emerging; our benchmark
> proves the architecture can ingest it and already finds bypasses against
> reference-grade detection.

## 3.7 One pipeline, two surfaces (cross-format slide)

| Metric | PyTorch Pickle | GGUF |
|--------|---------------|------|
| Candidates | 973 | 35 |
| Valid | 874 (89.8%) | 28 (80.0%) |
| Confirmed bypasses | 297 (34.0%) | 3 (10.7%) |
| Panel | PickleScan + ModelScan | ggufref + modelscan |
| Oracle | Strace + trigger poll | Strace + reference reader |
| FP on real corpus | 0% (StraceOracle) | 0% (24 real GGUFs) |

This proves the architecture is **format-agnostic** and honest about per-format
yields — GGUF's lower yield is surface breadth, not pipeline weakness.

---

## 4. Slide outline (13 slides)

| # | Slide | Key message |
|---|-------|-------------|
| 1–2 | Problem | Pickle = code execution; 1M+ HF models; scanners trust names, not behavior |
| 3 | Gap in 3 papers | ShadowPickle (handcrafted), PickleFuzzer (no runtime truth), DynaHug (fixed sandbox) |
| 4 | Your insight | **Execution-gated confirmation**, not just scanner disagreement |
| 5 | Architecture | 5-stage pipeline; containers; deterministic campaigns; **format-agnostic** (SCANNERS ext routing, unified DB `format` column) |
| 6 | RQs (reframed) | RQ1 scale known families + per-scanner evasion; RQ2 execution-confirmation vs anomaly scoring; RQ3 bypass survival across patches |
| 7 | H1 | Guided 47.1% vs unguided 18.5% vs baseline 25% — **honest**: driven by `pypi_injected` dominance (a scanner-bias finding) |
| 8 | Scanner breakdown | PickleScan 34%, ModelScan 51.5%, **Fickling N/A (torch format gap)**; GGUF: ggufref 7/10 (baseline SSTI + 6 malformed), modelscan 0/10, **3 obfuscated-SSTI confirmed bypasses** |
| 9 | H2 | DynaHug 94% FP → statistical oracles fail on benign loader noise; ExecutionOracle 0% FP → deterministic trigger polling is the viable path |
| 8.5 | **Methodological correction (GGUF)** | Initial GGUF: 0 bypasses because execution confirmation (trigger poll) was coupled to ggufref's `triggered` detection. Fix: **strace-based GGUF execution oracle** (decouple confirmation from static detection, mirroring the pickle-side StraceOracle). Result: 3 obfuscated-SSTI confirmed bypasses. Lesson: **benchmarks must not couple their validity oracle with their detection oracle** |
| 10 | H3 | 99.3–100% retention × 6 versions → scanners not patching `pypi_injected` effectively |
| 11 | Cross-format | One DB, two surfaces: `pt` 297 bypasses (34%), `gguf` **3** bypasses (obfuscated SSTI), FP 0/24 |
| 12 | Defense | Sanitizer + quarantine; 30% escapes quarantined, not sanitized |
| 13 | Limitations | One-family dominance, bounded pilot, DynaHug environment-specific, Fickling torch gap |

---

## 5. Unified-architecture talking point

**Q:** *"Why is GGUF second-class?"*

**A:** *"GGUF is not second-class; it is the second format surface our unified pipeline ingests. The scanner panel is format-capable by extension routing, the validation oracle is format-dispatched, and the DB schema is format-agnostic (`candidates.format`, `attack_primitives`). We scoped the pilot to the pickle surface where the panel is richest (973 candidates), and validated the GGUF surface (35 candidates, 3 confirmed bypasses) in the same database and report. Scaling both surfaces under the same feedback loop is scoped follow-on work."*

---

## 6. Demo-day cheat sheet (run these live)

```bash
# Cross-format summary (the money query)
sqlite3 data/regenbench_campaign.db \
  "SELECT COALESCE(format,'pt') f, COUNT(*), SUM(f.is_valid) FROM candidates c \
   JOIN campaign_fitness f ON f.candidate_id=c.candidate_id GROUP BY 1;"

# Pickle confirmed bypasses by run (format-native panel = PickleScan + ModelScan)
sqlite3 data/regenbench_campaign.db \
  "SELECT c.run_id, COUNT(*) FROM candidates c \
   JOIN campaign_fitness f ON f.candidate_id=c.candidate_id \
   JOIN panel_results p1 ON p1.candidate_id=c.candidate_id AND p1.scanner='picklescan' \
   JOIN panel_results p2 ON p2.candidate_id=c.candidate_id AND p2.scanner='modelscan' \
   WHERE f.is_valid=1 AND COALESCE(c.format,'pt')='pt' AND p1.verdict='benign' AND p2.verdict='benign' \
   GROUP BY c.run_id;"   # -> guided 223, unguided 74

# Bypass-family concentration (transparency beats concealment)
sqlite3 data/regenbench_campaign.db \
  "SELECT c.run_id, c.mutation_template, COUNT(*) FROM candidates c \
   JOIN campaign_fitness f ON f.candidate_id=c.candidate_id \
   JOIN panel_results p1 ON p1.candidate_id=c.candidate_id AND p1.scanner='picklescan' \
   JOIN panel_results p2 ON p2.candidate_id=c.candidate_id AND p2.scanner='modelscan' \
   WHERE f.is_valid=1 AND COALESCE(c.format,'pt')='pt' AND p1.verdict='benign' AND p2.verdict='benign' \
   GROUP BY 1,2;"

# Fickling torch-format-gap diagnostic (the Phase 0 proof)
CANDIDATE=$(sqlite3 data/regenbench_campaign.db "SELECT filepath FROM candidates WHERE panel_verdict='all_benign' LIMIT 1;")
docker run --rm -v "$(pwd)/$CANDIDATE:/mnt/model.pt:ro,z" --entrypoint python3.13 \
  regenbench/fickling:latest -m fickling --trace /mnt/model.pt   # -> "No pickle files detected"

# GGUF bypass family diversity (the money query for Q&A)
sqlite3 data/regenbench_campaign.db \
  "SELECT c.mutation_template, f.is_valid, c.panel_verdict, COUNT(*) FROM candidates c \
   JOIN campaign_fitness f ON f.candidate_id=c.candidate_id \
   WHERE c.format='gguf' AND c.attack_primitives != '[]' GROUP BY 1,2,3;"
#   -> 3 rows all_benign (ssti_obfuscated_1/2/3); all others flagged

# strace execution proof for one obfuscated SSTI candidate (have this ready)
ls /tmp/gguf_strace.log   # produced in-container by --strace-mode; show execve( lines
```

### Demo-day pre-flight checklist

- [ ] **Slide 8.5 rehearsed** — explain the confirmation/detection coupling in 30 s.
- [ ] **Strace log ready** — a `--strace-mode` run of an obfuscated SSTI candidate (shows `execve(`).
- [ ] **DB query ready** — the GGUF family-diversity query above.
- [ ] **pytest output** — `193 passed` (host-only) + the container-gated obfuscation tests.
- [ ] **Cross-format report** — `docs/evaluation-report.md` with the 35/28/3 table.
- [ ] **Container rebuild proof** — `docker images | grep regenbench/gguf` shows a fresh timestamp.

---

## 7. What NOT to say

- ❌ "Fickling was 100% evaded." → It was a wrapper/normalization bug; Fickling is N/A on torch.
- ❌ "~0 confirmed bypasses for both formats." → Wrong; pickle confirmed bypasses are **297** (against the format-native panel).
- ❌ "We discovered novel bypass families." → One family dominates.
- ❌ "Self-regenerating." → Use "coverage-guided, feedback-driven".
- ❌ "GGUF is a separate system." → One DB, one report, two surfaces.