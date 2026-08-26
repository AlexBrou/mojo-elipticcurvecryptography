#!/usr/bin/env bash
# Builds the Mojo shared library and the C example, then runs it. The example
# links against libsecp256k1 too and cross-checks every result, so this doubles
# as an interop test.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

# Shared libraries are .dylib on macOS and .so everywhere else.
if [ "$(uname -s)" = "Darwin" ]; then
    EXT=dylib
else
    EXT=so
fi

OUT=${TMPDIR:-/tmp}/secp-mojo-ffi
mkdir -p "$OUT"

R=reference/secp256k1
if [ ! -d "$R/build/lib" ]; then
    echo "reference libsecp256k1 is not built; see the README" >&2
    exit 1
fi

echo "Building libsecp256k1_mojo.$EXT..."
pixi run mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \
    -o "$OUT/libsecp256k1_mojo.$EXT" ffi/capi.mojo

echo "Building the C example..."
clang -O2 -o "$OUT/use_from_c" examples/use_from_c.c \
    -Iinclude -I$R/include \
    -L"$OUT" -lsecp256k1_mojo \
    -L$R/build/lib -lsecp256k1 \
    -Wl,-rpath,"$OUT" -Wl,-rpath,"$PWD/$R/build/lib"

echo
"$OUT/use_from_c"
