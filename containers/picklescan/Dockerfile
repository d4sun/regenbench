# PickleScan scanner image.
#
# Built FROM the shared base image (T0.2), pins mmaitre314/picklescan at
# release v1.0.5 (commit f15d54d) per the PickleFuzzer/ShadowPickle pinning
# practice, and normalizes output to the unified verdict schema
# (docs/verdict-schema.md).
#
# SCANNER_COMMIT lets historical releases be built for H3 shelf-life rescans:
#   docker build --build-arg SCANNER_COMMIT=<full-commit-sha> .

FROM regenbench/base:0.2.0

ARG SCANNER_COMMIT=f15d54da3dec9aa28a87ede82f87882bb80f1023

RUN git clone https://github.com/mmaitre314/picklescan /opt/picklescan \
    && cd /opt/picklescan \
    && git checkout ${SCANNER_COMMIT}

RUN python3.13 -m pip install --no-cache-dir /opt/picklescan

COPY wrapper.py /usr/local/bin/picklescan-wrapper

ENTRYPOINT ["python3.13", "/usr/local/bin/picklescan-wrapper"]
