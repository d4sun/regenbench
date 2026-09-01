# ReGenBench -- Task 3 Unified Demo

Backend: `docker`; seed subset: `ci/corpus`.

## 4b. LoadTimeMonitor

| candidate | verdict | suspicious syscalls | files created | network |
| :--- | :---: | :---: | :---: | :---: |
| gadget | suspicious | 4 | 0 | False |
| overwritten | clean | 0 | 0 | False |
| external | clean | 0 | 0 | False |
| indirect_chain | suspicious | 2 | 0 | False |
| pypi_injected | suspicious | 2 | 0 | False |

## 1. Generated candidates (one per attack family)

- **gadget** -> `inject_payload_into_torch.pt`
- **overwritten** -> `shadowpickle_overwritten.pt`
- **external** -> `shadowpickle_external.pt`
- **indirect_chain** -> `shadowpickle_indirect_chain.pt`
- **pypi_injected** -> `shadowpickle_pypi_injected.pt`

## 2. Static scanner panel verdicts

| candidate | picklescan | modelscan | fickling | confirmed bypass |
| :--- |:---: | :---: | :---: | :---: |
| gadget | malicious | malicious | err | False |
| overwritten | malicious | malicious | err | False |
| external | malicious | benign | err | False |
| indirect_chain | malicious | malicious | err | False |
| pypi_injected | benign | benign | err | False |

## 3. ExecutionOracle confirmation

| candidate | executed |
| :--- | :---: |
| gadget | True |
| overwritten | True |
| external | True |
| indirect_chain | True |
| pypi_injected | True |

## 4. ModelDefense prototype

| candidate | verdict | reason |
| :--- | :---: | :--- |
| gadget | quarantined | Dangerous callables or malicious scanner verdicts: [('subprocess', 'call')] |
| overwritten | quarantined | Dangerous callables or malicious scanner verdicts: [('builtins', 'exec')] |
| external | quarantined | Dangerous callables or malicious scanner verdicts: [('numpy.testing._private.utils', 'runstring')] |
| indirect_chain | quarantined | Dangerous callables or malicious scanner verdicts: [('builtins', 'getattr'), ('builtins', '__import__')] |
| pypi_injected | quarantined | Dangerous callables or malicious scanner verdicts: [('IPython.utils.process', 'system')] |

## 5. GGUF attack surface (ggufref oracle vs modelscan)

| artifact | ggufref | modelscan |
| :--- | :---: | :---: |
| gguf_ssti_chat_template.gguf | malicious | benign |
| gguf_malformed_nkv_overflow.gguf | malicious | benign |
| gguf_malformed_ntensors_overflow.gguf | malicious | benign |
| gguf_malformed_string_overflow.gguf | malicious | benign |
| gguf_malformed_path_traversal.gguf | malicious | benign |
| gguf_malformed_negative_dims.gguf | malicious | benign |
| gguf_malformed_version_zero.gguf | malicious | benign |
| gguf_ssti_obfuscated_1.gguf | benign | benign |
| gguf_ssti_obfuscated_2.gguf | benign | benign |
| gguf_ssti_obfuscated_3.gguf | benign | benign |
| benign-synth.gguf | benign | benign |

## 6. Baseline comparison

ShadowPickle baseline (reproduced by `scripts/run_shadowpickle_baseline.py`): 10/40 valid candidates bypassed (25.0%). Fuzzing campaigns: pt 297/874 (34.0%) + gguf 3/28 (10.7%).

In this demo subset, 0/5 generated candidates evaded the full panel while still executing (ExecutionOracle-confirmed). See `docs/evaluation-report.md` for the scaled campaign numbers and `reference/baseline_snapshot/results-20260818-141227/comparison-methodology.md` for how these compare to ShadowPickle / PickleFuzzer / DynaHug.

## Note on safety

No untrusted artifact is ever deserialized on the host. Payload execution confirmation happens inside the sandboxed base container; the defense prototype quarantines dangerous artifacts and only reserializes via `torch.load(weights_only=True)` inside the container.