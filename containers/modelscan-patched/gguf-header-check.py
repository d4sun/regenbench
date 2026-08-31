# P5.2 gguf header check for modelscan-patched
import struct
def is_splice_malicious(data: bytes) -> bool:
    # Detect STACK_GLOBAL with _pickle string (splice transport)
    return b"_pickle" in data and b"STACK_GLOBAL" in data
