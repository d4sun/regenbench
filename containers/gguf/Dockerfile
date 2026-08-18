# ReGenBench GGUF reference-oracle image (Task 3, GGUF attack surface).
#
# FROM the shared base image (T0.2). Installs the reference GGUF reader
# (ggml-org/gguf) plus Jinja2 (used by llama-cpp-python to render
# `tokenizer.chat_template`, the CVE-2024-34359 "Llama Drama" surface) and
# normalizes output to the unified verdict schema (docs/verdict-schema.md).
#
# The oracle classifies a .gguf artifact as:
#   * malicious  - the reference parser rejects the header (malformed-header
#                  attacks: n_kv/n_tensors overflow, string-length overflow,
#                  negative dims, tensor-name path traversal, version 0), or
#                  `tokenizer.chat_template` is a Jinja2 SSTI payload that
#                  executes when rendered (JFrog "Llama Drama").
#   * benign     - parses cleanly with no dangerous chat template.
#   * error      - the file could not be read at all.

FROM regenbench/base:0.2.0

RUN python3.13 -m pip install --no-cache-dir \
        gguf==0.19.0 \
        jinja2==3.1.4

COPY loader.py /usr/local/bin/gguf-loader
COPY validator.py /usr/local/bin/gguf-validator

ENTRYPOINT ["python3.13", "/usr/local/bin/gguf-validator"]