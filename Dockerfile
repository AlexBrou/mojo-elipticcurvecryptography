# The library, and nothing else. No interpreters, no reference library, no
# toolchain in the result.
#
#   docker build -t secp256k1-mojo .                    # the library image
#   docker run --rm secp256k1-mojo                      # known-answer smoke test
#
#   docker build --target builder -t secp256k1-mojo-dev .
#   docker run --rm secp256k1-mojo-dev ./run_tests.sh   # the full suite
#
# The other two images are separate files, so that what they drag in stays out
# of this one:
#   Dockerfile.examples  adds Python and Node to run the demos
#   Dockerfile.bench     adds the C and Rust toolchains to compare against
#
# The GPU path is not exercised: Metal is not available to Linux containers, so
# SECP256K1_SKIP_GPU is set. On a CUDA host, drop it and pass --gpus all.

# ---------------------------------------------------------------- builder
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git clang make \
    && rm -rf /var/lib/apt/lists/*

ENV PIXI_HOME=/opt/pixi
ENV PATH=/opt/pixi/bin:$PATH
RUN curl -fsSL https://pixi.sh/install.sh | bash

WORKDIR /app

# Resolve the environment before copying sources, so source edits do not
# invalidate this layer.
COPY pixi.toml pixi.lock ./
RUN pixi install

# The reference C library: it generates the test vectors and the interop
# example links against it.
RUN git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git \
        reference/secp256k1 \
    && cd reference/secp256k1 \
    && pixi run --manifest-path /app/pixi.toml cmake -B build \
        -DSECP256K1_BUILD_BENCHMARK=ON -DSECP256K1_BUILD_TESTS=OFF \
        -DSECP256K1_ENABLE_MODULE_RECOVERY=ON -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang -DCMAKE_MAKE_PROGRAM=make \
    && pixi run --manifest-path /app/pixi.toml cmake --build build -j"$(nproc)"

COPY . .

# The sha256 dependency is a git submodule. `docker build` copies the working
# tree, so an uninitialised submodule gives an empty directory and a confusing
# compile error rather than a clear one.
RUN test -f vendor/mojo-sha256/src/sha256/__init__.mojo \
    || (echo "vendor/mojo-sha256 is empty; run: git submodule update --init --recursive" >&2; exit 1)

ENV SECP256K1_SKIP_GPU=1

RUN mkdir -p /out \
    && pixi run mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \
        -o /out/libsecp256k1_mojo.so ffi/capi.mojo \
    && cp -a reference/secp256k1/build/lib/libsecp256k1.so* /out/

# A Mojo shared library is not standalone: it links against a handful of Mojo
# runtime libraries (libKGENCompilerRTShared, the AsyncRT pair, ...). Collect
# exactly the ones it resolves, so the runtime image can stay small instead of
# carrying the whole ~900 MB toolchain lib directory.
RUN mkdir -p /out/runtime \
    && ldd /out/libsecp256k1_mojo.so \
       | awk '/=> \/app\/.pixi/ {print $3}' \
       | xargs -I{} cp -L {} /out/runtime/

# Fail the build if the library disagrees with libsecp256k1 anywhere.
RUN ./run_tests.sh

# The smoke test needs only the Mojo library; the interop example needs both.
RUN clang -O2 -o /out/smoke_test examples/smoke_test.c \
        -Iinclude -L/out -lsecp256k1_mojo -Wl,-rpath,/usr/local/lib \
    && clang -O2 -o /out/use_from_c examples/use_from_c.c \
        -Iinclude -Ireference/secp256k1/include \
        -L/out -lsecp256k1_mojo -lsecp256k1 -Wl,-rpath,/usr/local/lib

# ---------------------------------------------------------------- runtime
# The shared library, the Mojo runtime libraries it links against, the header,
# and a known-answer smoke test.
FROM debian:bookworm-slim AS runtime

COPY --from=builder /out/libsecp256k1_mojo.so /usr/local/lib/
COPY --from=builder /out/runtime/ /usr/local/lib/
COPY --from=builder /out/smoke_test /usr/local/bin/smoke_test
COPY --from=builder /app/include/secp256k1_mojo.h /usr/local/include/
RUN ldconfig

# Consume this from another image with:
#   COPY --from=secp256k1-mojo /usr/local/lib /usr/local/lib
#   COPY --from=secp256k1-mojo /usr/local/include /usr/local/include
CMD ["smoke_test"]
