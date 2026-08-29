# Fickling scanner image.
#
# Built FROM the shared base image (T0.2), pins trailofbits/fickling at
# release v0.1.12 (commit c3c695c) per the PickleFuzzer/ShadowPickle pinning
# practice, and normalizes output to the unified verdict schema
# (docs/verdict-schema.md). Fickling requires Python >=3.10 (no upper bound),
# so it runs on the base image's Python 3.13.15 without override.
#
# SCANNER_COMMIT lets historical releases be built for H3 shelf-life rescans:
#   docker build --build-arg SCANNER_COMMIT=<full-commit-sha> .

FROM regenbench/base:0.2.0

ARG SCANNER_COMMIT=c3c695cdcce451c04dfe892802675161614287a2

RUN git clone https://github.com/trailofbits/fickling /opt/fickling \
    && cd /opt/fickling \
    && git checkout ${SCANNER_COMMIT}

RUN python3.13 -m pip install --no-cache-dir /opt/fickling \
    && fickling --version

COPY wrapper.py /usr/local/bin/fickling-wrapper

ENTRYPOINT ["python3.13", "/usr/local/bin/fickling-wrapper"]