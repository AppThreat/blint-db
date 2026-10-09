# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
#
# Toolchain image for building the blint-db meson (wrapdb) corpus on
# linux/arm64 with musl. The wrapdb corpus is developed against glibc, so
# expect more build_failed outcomes here; the successful subset is still
# valuable for symbol matching on musl systems.
#
#   docker build -f docker/meson-musl-arm64.Dockerfile -t blintdb-builder-meson-musl:latest .
#   docker run -d --name meson-musl blintdb-builder-meson-musl:latest
#   docker exec meson-musl sh -c "git clone --depth 1 https://github.com/AppThreat/blint-db /app/blint-db && cd /app/blint-db && uv sync --all-extras --all-groups --all-packages -p 3.13"

FROM alpine:3.21

ENV LANG=C.UTF-8 \
    NYXSTONE_LLVM_PREFIX=/usr/lib/llvm18 \
    LLVM_CONFIG=/usr/lib/llvm18/bin/llvm-config \
    CC=/usr/lib/llvm18/bin/clang \
    CXX=/usr/lib/llvm18/bin/clang++ \
    CXXFLAGS=-std=c++17

RUN apk add --no-cache \
        bash ca-certificates curl git openssh-client perl \
        clang18 llvm18-dev lld18 \
        build-base gcc g++ pkgconf ninja samurai \
        nasm yasm flex bison doxygen \
        linux-headers libtool autoconf automake gettext \
        eudev-dev openssl-dev zeromq-dev boost-dev gtest-dev \
        dbus-dev libproxy-dev mesa-dev glu-dev \
        libxi-dev gtk+2.0-dev qt5-qtbase-dev ffmpeg-dev \
        util-linux-dev zlib-dev libffi-dev pcre2-dev \
        unzip zip tar xz

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

CMD ["sleep", "infinity"]
