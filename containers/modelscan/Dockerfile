# ModelScan scanner image.
#
# Built FROM the shared base image (T0.2), pins protectai/modelscan at release
# v0.8.8 (commit 61fcec9) per the PickleFuzzer/ShadowPickle pinning practice,
# and normalizes output to the unified verdict schema
# (docs/verdict-schema.md).
#
# NOTE: ModelScan declares requires-python '<3.13,>=3.10', but the base image
# ships Python 3.13. The package is pure Python and is installed with
# --ignore-requires-python; import/scan behavior is smoke-tested during the
# build and at runtime.
#
# SCANNER_COMMIT lets historical releases be built for H3 shelf-life rescans:
#   docker build --build-arg SCANNER_COMMIT=<full-commit-sha> .

FROM regenbench/base:0.2.0

ARG SCANNER_COMMIT=61fcec9c2a37c24c1fb12d84ede30fe248a364bd

RUN git clone https://github.com/protectai/modelscan /opt/modelscan \
    && cd /opt/modelscan \
    && git checkout ${SCANNER_COMMIT} \
    && python3.13 -m pip install --no-cache-dir --ignore-requires-python /opt/modelscan \
    && modelscan --version

COPY wrapper.py /usr/local/bin/modelscan-wrapper

ENTRYPOINT ["python3.13", "/usr/local/bin/modelscan-wrapper"]