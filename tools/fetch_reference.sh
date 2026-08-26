#!/usr/bin/env bash
# Clones and builds libsecp256k1 into reference/.
#
# Needed for two things, neither of which is required to use this library:
#   * regenerating tests/vectors/ with tools/gen_vectors.c
#   * the C interop example, which links both libraries and compares results
#
# The vectors themselves are committed, so the test suite runs without this.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

if [ -d reference/secp256k1/build/lib ]; then
    echo "reference/secp256k1 is already built"
    exit 0
fi

mkdir -p reference
if [ ! -d reference/secp256k1 ]; then
    git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git \
        reference/secp256k1
fi

cd reference/secp256k1
pixi run --manifest-path ../../pixi.toml cmake -B build \
    -DSECP256K1_BUILD_BENCHMARK=ON \
    -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$(command -v clang || echo cc)"
pixi run --manifest-path ../../pixi.toml cmake --build build -j"$(getconf _NPROCESSORS_ONLN)"
echo "reference/secp256k1 built"
