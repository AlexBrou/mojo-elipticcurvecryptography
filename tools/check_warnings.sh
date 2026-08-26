#!/usr/bin/env bash
# Treats compiler warnings as failures.
#
# Mojo has no separate linter; the compiler is it. Warnings here mean unused
# assignments, deprecated APIs and similar — worth fixing before they land.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

OUT=${TMPDIR:-/tmp}/secp-warn
mkdir -p "$OUT"
INC="-I . -I src -I vendor/mojo-sha256/src"

found=0
check() {
    local f="$1"
    local log="$OUT/$(basename "$f").log"
    if ! pixi run mojo build $INC -o "$OUT/out.bin" "$f" > "$log" 2>&1; then
        echo "FAILED to build $f"
        tail -20 "$log"
        found=1
        return
    fi
    if grep -q "warning:" "$log"; then
        echo "warnings in $f:"
        grep -A2 "warning:" "$log" | head -30
        found=1
    fi
}

for f in tests/test_*.mojo bench/bench.mojo bench/bench_gpu.mojo; do
    check "$f"
done

# The FFI layer is not reachable from the tests, so build it separately.
log="$OUT/capi.log"
if ! pixi run mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \
        -o "$OUT/lib.so" ffi/capi.mojo > "$log" 2>&1; then
    echo "FAILED to build ffi/capi.mojo"; tail -20 "$log"; found=1
elif grep -q "warning:" "$log"; then
    echo "warnings in ffi/capi.mojo:"; grep -A2 "warning:" "$log" | head -20; found=1
fi

if [ $found -ne 0 ]; then
    echo "compiler warnings found" >&2
    exit 1
fi
echo "no compiler warnings"
