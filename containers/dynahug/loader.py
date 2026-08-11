#!/usr/bin/env python3
"""DynaHug oracle deserialization loader.

Replicates the upstream src/inference.py deserialization step (clean_mode):
torch.load with weights_only=False and map_location=cpu under torch.no_grad().
The payload's behavior unfolds here; the wrapper traces this process with
strace -c -f. Exits non-zero if torch.load raises (artifact not deserializable).
"""

import sys
import torch


def main() -> int:
    target = sys.argv[1]
    with torch.no_grad():
        with open(target, "rb") as f:
            torch.load(f, weights_only=False, map_location=torch.device("cpu"))
    return 0


if __name__ == "__main__":
    sys.exit(main())