#!/usr/bin/env bash
# Runs every Mojo test module. Vector files are resolved relative to the repo
# root, so this must be run from there.
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.pixi/bin:$PATH"

# The GPU tests need a Metal/CUDA device. Set SECP256K1_SKIP_GPU=1 where there
# is none — inside a container on macOS, for instance, since Metal is not
# passed through to Linux guests.
if [ ! -f vendor/mojo-sha256/src/sha256/__init__.mojo ]; then
    echo "vendor/mojo-sha256 is missing. Run:" >&2
    echo "    git submodule update --init --recursive" >&2
    exit 1
fi

failed=0
for t in tests/test_*.mojo; do
    if [ "${SECP256K1_SKIP_GPU:-0}" = "1" ] && [ "$t" = "tests/test_gpu.mojo" ]; then
        echo "=== $t (skipped: SECP256K1_SKIP_GPU=1)"
        continue
    fi
    echo "=== $t"
    if ! pixi run mojo run -I . -I src -I vendor/mojo-sha256/src "$t" "$@"; then
        failed=1
    fi
done

# Secrets are wiped with volatile stores; check the optimizer keeps them.
echo "=== tools/check_scrub.sh (secret scrubbing)"
if ! ./tools/check_scrub.sh; then
    failed=1
fi

# The C ABI example cross-checks the shared library against libsecp256k1 in
# one process. Skipped when the reference library has not been built.
if [ -d reference/secp256k1/build/lib ]; then
    echo "=== examples/use_from_c.c (C ABI interop)"
    if ! ./examples/build_and_run.sh > /tmp/ffi_example.log 2>&1; then
        tail -20 /tmp/ffi_example.log
        failed=1
    else
        tail -3 /tmp/ffi_example.log
    fi
else
    echo "=== skipping the C ABI example (reference library not built)"
fi

if [ $failed -ne 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
