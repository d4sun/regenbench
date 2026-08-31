FROM regenbench/modelscan:latest
# P4.2 synthetic patch: splice transport detection
COPY gguf-header-check.py /opt/modelscan/gguf_patch.py
ENV MODELSCAN_GGUF_PATCH=/opt/modelscan/gguf_patch.py
