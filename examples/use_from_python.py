#!/usr/bin/env python3
"""Uses the Mojo secp256k1 library from Python as a native extension module.

This is not ctypes: `ffi/secp256k1_mojo.mojo` builds a real CPython extension,
so `Context` is an ordinary Python class, arguments and results are `bytes`,
and failures raise exceptions rather than returning status codes.

Build it first (or run examples/build_python.sh, which does this and then runs
this file):

    mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \
        -o secp256k1_mojo.so ffi/secp256k1_mojo.mojo
"""

import os
import sys

# The .so is usually left at the repository root by build_python.sh.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.getcwd())

try:
    import secp256k1_mojo
except ImportError:
    sys.exit(
        "secp256k1_mojo is not built. Run examples/build_python.sh, or:\n"
        "    mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \\\n"
        "        -o secp256k1_mojo.so ffi/secp256k1_mojo.mojo"
    )


def main():
    # One context, reused: building it precomputes the generator table.
    ctx = secp256k1_mojo.Context()

    seckey = bytes((1 + i * 7) & 0xFF for i in range(32))
    msg = bytes((200 - i * 3) & 0xFF for i in range(32))
    tweak = bytes((i * 3 + 5) & 0xFF for i in range(32))

    assert ctx.seckey_verify(seckey)
    assert not ctx.seckey_verify(bytes(32))  # all zeros is not a valid key

    pub = ctx.public_key(seckey, True)
    print("pubkey      ", pub.hex())
    print("uncompressed", ctx.public_key(seckey, False).hex())

    sig = ctx.sign(msg, seckey)
    print("signature   ", sig.hex())
    print("verify      ", ctx.verify(sig, msg, pub))

    tampered = bytearray(msg)
    tampered[0] ^= 0xFF
    print("tampered    ", ctx.verify(sig, bytes(tampered), pub))

    sig_r, recovery_id = ctx.sign_recoverable(msg, seckey)
    recovered = ctx.recover(sig_r, recovery_id, msg)
    print("recovered   ", recovered.hex())

    print("ecdh        ", ctx.shared_secret(pub, seckey).hex())

    tweaked = ctx.seckey_tweak_add(seckey, tweak)
    print("tweaked key ", tweaked.hex())

    # Errors are exceptions, not return codes.
    try:
        ctx.sign(b"too short", seckey)
    except Exception as exc:
        print("short input ", f"rejected ({exc})")

    assert ctx.verify(sig, msg, pub)
    assert not ctx.verify(sig, bytes(tampered), pub)
    assert recovered == pub
    assert tweaked != seckey and ctx.seckey_verify(tweaked)
    print("\nall checks passed")


if __name__ == "__main__":
    main()
