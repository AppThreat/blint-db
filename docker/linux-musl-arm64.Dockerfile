# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
#
# Toolchain image for building blint-db corpora (meson/wrapdb, conan,
# vcpkg) on linux/arm64 with musl. Upstream corpora are developed against
# glibc, so expect more build_failed outcomes here; the successful subset
# is still valuable for symbol matching on musl systems.
#
#   docker build -f docker/linux-musl-arm64.Dockerfile -t blintdb-builder-linux-musl-arm64:latest .
#   docker run -d --name linux-musl-arm64 blintdb-builder-linux-musl-arm64:latest
#   docker exec linux-musl-arm64 sh -c "git clone --depth 1 https://github.com/AppThreat/blint-db /app/blint-db && cd /app/blint-db && uv sync --all-extras --all-groups --all-packages -p 3.13"

FROM alpine:3.21

ENV LANG=C.UTF-8 \
    PATH=/usr/lib/llvm18/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
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
        cmake zip unzip \
        linux-headers libtool autoconf automake gettext \
        eudev-dev openssl-dev zeromq-dev boost-dev gtest-dev \
        dbus-dev libproxy-dev mesa-dev glu-dev \
        libxi-dev gtk+2.0-dev qt5-qtbase-dev ffmpeg-dev \
        util-linux-dev zlib-dev libffi-dev pcre2-dev \
        unzip zip tar xz

# Alpine 3.21's compiler-rt package installs under the llvm19 resource dir
# while clang18 looks in its own; bridge it so nyxstone links.
RUN mkdir -p /usr/lib/llvm18/lib/clang/18/lib/linux \
    && ln -sf /usr/lib/llvm19/lib/clang/19/lib/aarch64-alpine-linux-musl/libclang_rt.builtins-aarch64.a \
        /usr/lib/llvm18/lib/clang/18/lib/linux/libclang_rt.builtins-aarch64.a

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

CMD ["sleep", "infinity"]
