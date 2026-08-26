#!/usr/bin/env bash
# Builds the Python extension module and runs the example against it.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

# CPython looks for a module named exactly `secp256k1_mojo`, so the file name,
# the PyInit_ suffix and the .so name all have to agree.
if [ "$(uname -s)" = "Darwin" ]; then EXT=so; else EXT=so; fi

echo "Building secp256k1_mojo.$EXT..."
pixi run mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \
    -o "secp256k1_mojo.$EXT" ffi/secp256k1_mojo.mojo

echo
python3 examples/use_from_python.py
