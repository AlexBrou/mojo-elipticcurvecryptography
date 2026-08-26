#!/usr/bin/env bash
# Runs the C and Mojo benchmarks and prints them side by side.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

C_BENCH=reference/secp256k1/build/bin
OUT=${TMPDIR:-/tmp}/secp-bench

mkdir -p "$OUT"

echo "Building the Mojo benchmarks..."
pixi run mojo build -I . -I src -I vendor/mojo-sha256/src -o "$OUT/mojo_bench" bench/bench.mojo || exit 1
if [ "${SECP256K1_SKIP_GPU:-0}" != "1" ]; then
    pixi run mojo build -I . -I src -I vendor/mojo-sha256/src -o "$OUT/mojo_bench_gpu" bench/bench_gpu.mojo || exit 1
fi

# Both suites are noisy on a busy machine, so run each a few times and take
# the per-row minimum.
RUNS=${RUNS:-3}
c_files=()
m_files=()
for i in $(seq 1 "$RUNS"); do
    echo "Run $i of $RUNS..."
    "$C_BENCH/bench" ecdsa ecdh keygen recover > "$OUT/c_$i.txt" 2>&1
    "$C_BENCH/bench_internal"   > "$OUT/ci_$i.txt" 2>&1
    "$OUT/mojo_bench"           > "$OUT/m_$i.txt" 2>&1
    c_files+=("$OUT/c_$i.txt" "$OUT/ci_$i.txt")
    m_files+=("$OUT/m_$i.txt")
done

python3 bench/compare.py "${c_files[@]}" --mojo "${m_files[@]}"

if [ "${SECP256K1_SKIP_GPU:-0}" = "1" ]; then
    echo
    echo "=== GPU: skipped (SECP256K1_SKIP_GPU=1) ==="
else
    echo
    echo "=== GPU ==="
    "$OUT/mojo_bench_gpu"
fi
