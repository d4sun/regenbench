#!/usr/bin/env python3
"""Generate the committed torch smoke-corpus artifacts (DynaHug oracle inputs).

Dynahug deserializes via torch.load, so its smoke coverage uses real torch
checkpoints. This script runs inside the regenbench/base image (PyTorch) and
writes into the mounted repo path ci/corpus/torch/.

    benign/benign.pt        a plain state_dict dict of tensors (loads safely)
    malicious/malicious.pt  a __reduce__ payload invoking os.system (flagged)

Run (from repo root), using the base image that ships torch:
    podman run --rm -v "$PWD:/repo:Z" --entrypoint python3.13 \
        regenbench/base:0.2.0 /repo/ci/generate_corpus_torch.py /repo/ci/corpus/torch

The oracle asserts `malicious` (exit 1) on both, because the corpus is
out-of-distribution relative to its 2000-real-model training set (accepted
T0.7 semantics); the goal here is to exercise the oracle's read+score path.
"""

import os
import sys
import torch

# Deterministic regeneration: the committed .pt bytes must be reproducible
# (torch.randn below is seeded), so CI and local runs produce identical files.
torch.manual_seed(1337)

OUT = sys.argv[1] if len(sys.argv) > 1 else "ci/corpus/torch"
BEN = os.path.join(OUT, "benign")
MAL = os.path.join(OUT, "malicious")
os.makedirs(BEN, exist_ok=True)
os.makedirs(MAL, exist_ok=True)


def clean(d):
    os.makedirs(d, exist_ok=True)
    for old in os.listdir(d):
        if old.endswith(".pt"):
            os.remove(os.path.join(d, old))


class _Danger:
    def __reduce__(self):
        import os
        return (os.system, ("echo oracle_corpus > /dev/null",))


def main():
    clean(BEN)
    clean(MAL)
    state = {
        "embed.weight": torch.ones(32, 16),
        "layer0.weight": torch.randn(16, 16) * 0.02,
        "layer0.bias": torch.zeros(16),
        "config": {"layers": 1, "hidden": 16},
    }
    torch.save(state, os.path.join(BEN, "benign.pt"))
    torch.save(_Danger(), os.path.join(MAL, "malicious.pt"))
    print("wrote torch corpus under", OUT)
    print("  benign/benign.pt      ", os.path.getsize(os.path.join(BEN, "benign.pt")), "bytes")
    print("  malicious/malicious.pt", os.path.getsize(os.path.join(MAL, "malicious.pt")), "bytes")


if __name__ == "__main__":
    main()