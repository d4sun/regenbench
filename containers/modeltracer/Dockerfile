# ModelTracer scanner image.
#
# ModelTracer is the dynamic scanner from Casey et al. ("A Large-Scale
# Exploit Instrumentation Study of AI/ML Supply Chain Attacks in Hugging
# Face Models", arXiv:2410.04490); the upstream code lives in
# s2e-lab/hf-model-analyzer. It executes the model load inside the sandbox
# while tracing Python callbacks (sys.settrace) and system calls (strace),
# then flags files that issue suspicious syscalls (execve/connect/socket/chmod
# after the initial python execve).
#
# Built FROM the shared base image (T0.2, ships Python 3.13 + torch + strace),
# pinned at upstream commit 5725b26 (HEAD of main, 2025-08-28).
#
# The upstream module cannot be imported as-is on the base image (top-level
# `import tensorflow`/`import onnx`; TensorFlow 2.16 does not support Python
# 3.13), and its loaders contain bugs (pickle.load/dill.load on path strings,
# torch.load defaulting to weights_only=True). The wrapper therefore
# reimplements the same tracing + detection logic with corrected loaders;
# the pinned upstream repo is kept in the image as a reference. Detection
# semantics (commands_of_interest, drop-first-execve) match upstream.

FROM regenbench/base:0.2.0

RUN git clone https://github.com/s2e-lab/hf-model-analyzer /opt/model-tracer \
    && cd /opt/model-tracer \
    && git checkout 5725b26f62a1c0e4f22c793761cefb70ead64ee5

RUN python3.13 -m pip install --no-cache-dir \
        dill \
        joblib \
        pandas \
        tqdm

# Verify strace works under rootless podman (ptrace) before relying on it.
RUN strace -f -e trace=execve true

COPY wrapper.py /usr/local/bin/modeltracer-wrapper

ENTRYPOINT ["python3.13", "/usr/local/bin/modeltracer-wrapper"]