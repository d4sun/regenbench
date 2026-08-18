# ReGenBench -- Task 3 Demo: The GGUF Attack Surface

## Detection matrix (live scan)

verdict legend: `MAL` malicious, `BEN` benign, `ERR` error / no verdict.

| artifact | modelscan | picklescan | fickling | modeltracer | dynahug | ggufref |
| :--- |:---: | :---: | :---: | :---: | :---: | :---: |
| benign-synth.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-aquila.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-baichuan.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-bert-bge.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-command-r.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-deepseek-coder.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-deepseek-llm.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-falcon.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-gemma-4.gguf | BEN | BEN | MAL | ERR | ERR | ERR |
| ggml-vocab-gpt-2.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-gpt-neox.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-llama-bpe.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-llama-spm.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-mpt.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-nomic-bert-moe.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-phi-3.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-qwen2.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-qwen35.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-refact.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-starcoder.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| gguf_malformed_negative_dims.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| gguf_malformed_nkv_overflow.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| gguf_malformed_ntensors_overflow.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| gguf_malformed_path_traversal.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| gguf_malformed_string_overflow.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| gguf_malformed_version_zero.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| gguf_ssti_chat_template.gguf | BEN | BEN | MAL | ERR | ERR | MAL |
| stories15M-q4_0.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| stories15M-q8_0.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| stories260K-be.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| stories260K-infill.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| stories260K.gguf | BEN | BEN | MAL | ERR | ERR | BEN |

## Findings by family

### benign-synth.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-aquila.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-baichuan.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-bert-bge.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-command-r.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-deepseek-coder.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-deepseek-llm.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-falcon.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-gemma-4.gguf
- ggufref verdict: `error` findings: ['reference-loader-timeout']
- modelscan verdict: `benign` findings: []

### ggml-vocab-gpt-2.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-gpt-neox.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-llama-bpe.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-llama-spm.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-mpt.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-nomic-bert-moe.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-phi-3.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-qwen2.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-qwen35.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-refact.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### ggml-vocab-starcoder.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### gguf_malformed_negative_dims.gguf
- ggufref verdict: `malicious` findings: ['negative-dims', 'reference-error:ValueError: Maximum allowed dimension exceeded']
- modelscan verdict: `benign` findings: []

### gguf_malformed_nkv_overflow.gguf
- ggufref verdict: `malicious` findings: ['nkv-overflow', 'reference-error:IndexError: index 0 is out of bounds for axis 0 with size 0']
- modelscan verdict: `benign` findings: []

### gguf_malformed_ntensors_overflow.gguf
- ggufref verdict: `malicious` findings: ['ntensors-overflow', 'reference-error:IndexError: index 0 is out of bounds for axis 0 with size 0']
- modelscan verdict: `benign` findings: []

### gguf_malformed_path_traversal.gguf
- ggufref verdict: `malicious` findings: ['path-traversal', 'reference-error:ValueError: cannot reshape array of size 0 into shape (4,)']
- modelscan verdict: `benign` findings: []

### gguf_malformed_string_overflow.gguf
- ggufref verdict: `malicious` findings: ['string-overflow', 'reference-error:IndexError: index 0 is out of bounds for axis 0 with size 0']
- modelscan verdict: `benign` findings: []

### gguf_malformed_version_zero.gguf
- ggufref verdict: `malicious` findings: ['version-zero', 'reference-error:ValueError: Sorry, file appears to be version 0 which we cannot handle']
- modelscan verdict: `benign` findings: []

### gguf_ssti_chat_template.gguf
- ggufref verdict: `malicious` findings: ['ssti:__class__', 'ssti:__subclasses__', 'ssti:__builtins__', 'ssti:__import__', 'ssti:popen', 'ssti:_module', 'ssti:triggered']
- modelscan verdict: `benign` findings: []

### stories15M-q4_0.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### stories15M-q8_0.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### stories260K-be.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

### stories260K-infill.gguf
- ggufref verdict: `benign` findings: ["reference-error:KeyError: 'Duplicate GGUF.version already in list at offset 69'"]
- modelscan verdict: `benign` findings: []

### stories260K.gguf
- ggufref verdict: `benign` findings: []
- modelscan verdict: `benign` findings: []

## Detection rates

| scanner | malicious detected | attack count | rate |
| :--- | :---: | :---: | :---: |
| **modelscan** | 0 | 7 | 0% |
| **picklescan** | 0 | 7 | 0% |
| **fickling** | 7 | 7 | 100% |
| **modeltracer** | 0 | 7 | 0% |
| **dynahug** | 0 | 7 | 0% |
| **ggufref** | 7 | 7 | 100% |

## False positives on real benign GGUFs

| scanner | benign flagged | benign scanned | FP rate |
| :--- | :---: | :---: | :---: |
| **modelscan** | 0 | 24 | 0% |
| **picklescan** | 0 | 24 | 0% |
| **fickling** | 24 | 24 | 100% |
| **modeltracer** | 0 | 24 | 0% |
| **dynahug** | 0 | 24 | 0% |
| **ggufref** | 0 | 24 | 0% |

## Narrative

**1. Format-coverage gap.** picklescan, modeltracer and the DynaHug oracle either error out or emit no verdict on `.gguf` inputs; the pickle/checkpoint-oriented panel has no GGUF surface. Fickling is worse than useless here: it reads GGUF bytes as a pickle stream, finds "invalid opcodes", and labels every file -- including all 12 real benign models -- LIKELY_UNSAFE (7/7 detection at 100% false positives). A model-safety pipeline restricted to pickle/torch scanners thus has zero *reliable* visibility into the most common open-weight distribution format.

**2. ModelScan does not actually parse GGUF.** The `ggufref` oracle classifies all 6 malformed-header families as malicious (each is rejected by the ggml-org reference reader, mirroring the public vellaveto/gguf-scanner-bypass-poc results) yet modelscan 0.8.8 reports benign on every one of them. Its `gguf` branch inspects the archive/metadata superficially (extension + metadata fields, no header/type validation) and misses the header-level attacks entirely.

**3. Jinja2 SSTI is a runtime, not a bytes-level, attack.** The `tokenizer.chat_template` payload (JFrog CVE-2024-34359) is byte-level indistinguishable from a legitimate template; static scanners cannot see it. The ggufref oracle renders the template through the same unsandboxed Jinja2 environment llama-cpp-python uses and observes the `os.popen` side effect (a trigger file is created), turning the library-level vulnerability into an observable execution signal.

**4. Oracle design.** ggufref is signature-driven for the six malformed-header families and render-driven for the SSTI family; it does not flag a file merely because the reference reader rejects it (the reader has bugs on some legitimate vocab GGUFs), keeping FP=0 on the 12-file real benign corpus.