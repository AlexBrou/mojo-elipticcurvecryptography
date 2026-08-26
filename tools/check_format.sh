#!/usr/bin/env bash
# Fails if anything is not formatted the way `mojo format` would write it.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

targets="src/secp256k1 tests bench/bench.mojo bench/bench_gpu.mojo ffi"

before=$(find $targets -name '*.mojo' -exec shasum {} \; | sort | shasum)
pixi run mojo format -q $targets > /dev/null
after=$(find $targets -name '*.mojo' -exec shasum {} \; | sort | shasum)

if [ "$before" != "$after" ]; then
    echo "Formatting differences found. Run:" >&2
    echo "    pixi run mojo format $targets" >&2
    git --no-pager diff --stat 2>/dev/null || true
    exit 1
fi
echo "formatting is clean"
