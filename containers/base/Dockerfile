# ReGenBench shared base image.
#
# Ubuntu 24.04 (noble) + Python 3.13 + common dependencies
# (CPU-only PyTorch, pickletools, strace).
#
# Reproducibility: apt packages and pip packages are version-pinned.
# Note: Python 3.13 is not in Ubuntu 24.04's default repos; it comes from
# the deadsnakes PPA (https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa).

FROM docker.io/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Base tooling needed to bootstrap the PPA and Python installation.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-transport-https=2.8.3 \
        ca-certificates=20260601~24.04.1 \
        curl=8.5.0-2ubuntu10.11 \
        gnupg \
        software-properties-common=0.99.49.4 \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F23C5A6CF475977595C89F51BA6932366A755776 \
    && add-apt-repository -y "deb https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu noble main" \
    && apt-get update

# Python 3.13 (deadsnakes) + common dependencies.
RUN apt-get install -y --no-install-recommends \
        python3.13=3.13.15-1+noble1 \
        python3.13-venv=3.13.15-1+noble1 \
        python3.13-dev=3.13.15-1+noble1 \
        git=1:2.43.0-1ubuntu7.3 \
        strace=6.8-0ubuntu2 \
    && python3.13 -m ensurepip \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.13 1 \
    && rm -rf /var/lib/apt/lists/*

# CPU-only PyTorch (scanner inference does not require a GPU).
RUN python3.13 -m pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        torch==2.13.0+cpu \
        numpy==2.3.5

# Verify the base surface: torch + pickletools import, strace present.
RUN python3.13 -c "import torch, pickletools; print('torch', torch.__version__)" \
    && strace --version | head -n1