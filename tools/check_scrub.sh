#!/usr/bin/env bash
# Checks that Scalar.clear() survives optimization.
#
# Wiping a secret is a dead store — nothing reads the value afterwards — so an
# optimizer is entitled to delete it, and does. scrub.mojo writes through a
# volatile store to prevent that. This compiles two functions that differ only
# in how they wipe, and inspects the generated assembly: the naive one should
# contain no stores, the volatile one should contain four.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

OUT=${TMPDIR:-/tmp}/secp-scrub
mkdir -p "$OUT"

cat > "$OUT/probe.mojo" <<'MOJO'
from secp256k1.scalar import Scalar


@no_inline
def naive_wipe() -> UInt64:
    var s = Scalar.from_limbs(
        0x1111111111111111, 0x2222222222222222,
        0x3333333333333333, 0x4444444444444444,
    )
    var out = s.d0 ^ s.d3
    s = Scalar.zero()
    return out


@no_inline
def volatile_wipe() -> UInt64:
    var s = Scalar.from_limbs(
        0x1111111111111111, 0x2222222222222222,
        0x3333333333333333, 0x4444444444444444,
    )
    var out = s.d0 ^ s.d3
    s.clear()
    return out


def main():
    print(naive_wipe(), volatile_wipe())
MOJO

pixi run mojo build --emit asm -I . -I src -I vendor/mojo-sha256/src -o "$OUT/probe.s" "$OUT/probe.mojo" 2>/dev/null

body() {
    awk -v start="$1" '
        index($0, start) > 0 { f = 1; next }
        f && /^\t?ret/ { exit }
        f { print }
    ' "$OUT/probe.s"
}

naive=$(body 'probe::naive_wipe()' | grep -cE '^\s*(str|stp|stur)' || true)
vol=$(body 'probe::volatile_wipe()' | grep -cE '^\s*(str|stp|stur)' || true)

echo "  naive wipe    : $naive store instructions (expected 0 - deleted by the optimizer)"
echo "  Scalar.clear(): $vol store instructions (expected 4 - one per limb)"

if [ "$naive" -ne 0 ]; then
    echo "  unexpected: the naive wipe was not optimized away; the probe is no"
    echo "  longer testing what it thinks it is" >&2
    exit 1
fi
if [ "$vol" -lt 4 ]; then
    echo "  FAILED: Scalar.clear() was optimized away - secrets are not wiped" >&2
    exit 1
fi
echo "  scrubbing survives optimization"
