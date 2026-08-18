#!/usr/bin/env python3
"""Crawl a small corpus of real, benign GGUF files for the Task-3 demo.

Sources (small files only, ~70 MB total):
  * huggingface.co/ggml-org/models   -- TinyLlama "stories" series (1.2 MB up
    to 26.7 MB) and the BGE-small checkpoint used by llama.cpp's tests.
  * raw.githubusercontent.com/ggerganov/llama.cpp -- vocab-only GGUFs
    (0.6-4 MB) used for tokenizer regression tests.

Downloads use the stdlib only (no extra tooling); each file is streamed and
written to ``--out`` (default data/gguf_benign_corpus). Files already present
with the expected size are skipped.

Usage:
    python3 scripts/crawl_gguf.py [--out data/gguf_benign_corpus] [--limit 0]
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.request

# (url, local name)
SOURCES: list[tuple[str, str]] = [
    ("https://huggingface.co/ggml-org/models/resolve/main/tinyllamas/stories260K.gguf",
     "tinyllamas/stories260K.gguf"),
    ("https://huggingface.co/ggml-org/models/resolve/main/tinyllamas/stories260K-infill.gguf",
     "tinyllamas/stories260K-infill.gguf"),
    ("https://huggingface.co/ggml-org/models/resolve/main/tinyllamas/stories260K-be.gguf",
     "tinyllamas/stories260K-be.gguf"),
    ("https://huggingface.co/ggml-org/models/resolve/main/tinyllamas/stories15M-q4_0.gguf",
     "tinyllamas/stories15M-q4_0.gguf"),
    ("https://huggingface.co/ggml-org/models/resolve/main/tinyllamas/stories15M-q8_0.gguf",
     "tinyllamas/stories15M-q8_0.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-aquila.gguf",
     "vocab/ggml-vocab-aquila.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-baichuan.gguf",
     "vocab/ggml-vocab-baichuan.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-bert-bge.gguf",
     "vocab/ggml-vocab-bert-bge.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-command-r.gguf",
     "vocab/ggml-vocab-command-r.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-deepseek-coder.gguf",
     "vocab/ggml-vocab-deepseek-coder.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-deepseek-llm.gguf",
     "vocab/ggml-vocab-deepseek-llm.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-falcon.gguf",
     "vocab/ggml-vocab-falcon.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-gemma-4.gguf",
     "vocab/ggml-vocab-gemma-4.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-gpt-2.gguf",
     "vocab/ggml-vocab-gpt-2.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-gpt-neox.gguf",
     "vocab/ggml-vocab-gpt-neox.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-llama-bpe.gguf",
     "vocab/ggml-vocab-llama-bpe.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-llama-spm.gguf",
     "vocab/ggml-vocab-llama-spm.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-mpt.gguf",
     "vocab/ggml-vocab-mpt.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-nomic-bert-moe.gguf",
     "vocab/ggml-vocab-nomic-bert-moe.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-phi-3.gguf",
     "vocab/ggml-vocab-phi-3.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-qwen2.gguf",
     "vocab/ggml-vocab-qwen2.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-qwen35.gguf",
     "vocab/ggml-vocab-qwen35.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-refact.gguf",
     "vocab/ggml-vocab-refact.gguf"),
    ("https://raw.githubusercontent.com/ggml-org/llama.cpp/master/models/ggml-vocab-starcoder.gguf",
     "vocab/ggml-vocab-starcoder.gguf"),
]


def fetch(url: str, dest: str, expected: int | None = None) -> str:
    if os.path.exists(dest) and expected and os.path.getsize(dest) == expected:
        return "skip"
    req = urllib.request.Request(url, headers={"User-Agent": "regenbench-crawl"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            f.write(chunk)
    return "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/gguf_benign_corpus")
    ap.add_argument("--limit", type=int, default=0, help="0 = download all")
    args = ap.parse_args()

    sources = SOURCES
    if args.limit:
        sources = sources[:args.limit]

    total = 0
    for url, rel in sources:
        dest = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        status = fetch(url, dest)
        size = os.path.getsize(dest) if os.path.exists(dest) else 0
        total += size
        print(f"{status:4s} {rel:40s} {size/1e6:7.2f} MB")
    print(f"corpus: {args.out}  ({total/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())