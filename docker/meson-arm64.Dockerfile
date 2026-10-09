# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
#
# Toolchain image for building the blint-db meson (wrapdb) corpus on
# linux/arm64 with glibc. Mirrors .github/workflows/build-meson.yml.
#
#   docker build -f docker/meson-arm64.Dockerfile -t blintdb-builder-meson-arm64:latest .
#   docker run -d --name meson-arm64 blintdb-builder-meson-arm64:latest
#   docker exec meson-arm64 bash -c "git clone --depth 1 https://github.com/AppThreat/blint-db /app/blint-db && cd /app/blint-db && uv sync --all-extras --all-groups --all-packages -p 3.13"

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    NYXSTONE_LLVM_PREFIX=/usr/lib/llvm-18 \
    LLVM_CONFIG=/usr/lib/llvm-18/bin/llvm-config \
    CC=/usr/lib/llvm-18/bin/clang \
    CXX=/usr/lib/llvm-18/bin/clang++ \
    CXXFLAGS=-std=c++17

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git openssh-client \
        llvm-18 llvm-18-dev clang-18 lld-18 \
        build-essential gcc g++ pkg-config cmake ninja-build \
        nasm yasm flex bison doxygen \
        gcc-avr avr-libc \
        libxi-dev libudev-dev libssl-dev libzmq3-dev libboost-dev libgmock-dev \
        libdbus-1-dev libproxy-dev libglu1-mesa-dev libegl1-mesa-dev libgles-dev libgles1 \
        libgtk2.0-dev qtbase5-dev libavfilter-dev \
        unzip zip xz-utils autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

CMD ["sleep", "infinity"]
