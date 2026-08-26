#!/usr/bin/env python3
"""Uses the Mojo library from Python through ctypes.

Nothing here is Mojo-aware: the shared library exports plain C symbols, so any
language with an FFI can call it the same way.

Build the library first:
    pixi run mojo build --emit shared-lib -I src -o libsecp256k1_mojo.dylib ffi/capi.mojo
then point LIBSECP256K1_MOJO at it, or leave it next to this script.
"""

import ctypes
import os
import sys
from ctypes import POINTER, c_char, c_int, c_void_p


def load():
    override = os.environ.get("LIBSECP256K1_MOJO")
    if override:
        return ctypes.CDLL(override)
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("libsecp256k1_mojo.dylib", "libsecp256k1_mojo.so"):
        for directory in (here, os.path.dirname(here), os.getcwd()):
            path = os.path.join(directory, name)
            if os.path.exists(path):
                return ctypes.CDLL(path)
    sys.exit(
        "could not find libsecp256k1_mojo; set LIBSECP256K1_MOJO to its path\n"
        "(build it with: pixi run mojo build --emit shared-lib -I src "
        "-o libsecp256k1_mojo.dylib ffi/capi.mojo)"
    )


lib = load()
buf = POINTER(c_char)

# Declaring argtypes/restype is not optional: without them ctypes assumes int
# arguments and truncates the 64-bit context pointer on the way in.
_SIGS = {
    "secp256k1_mojo_context_create": ([], c_void_p),
    "secp256k1_mojo_context_destroy": ([c_void_p], None),
    "secp256k1_mojo_ec_seckey_verify": ([c_void_p, buf], c_int),
    "secp256k1_mojo_ec_pubkey_create": ([c_void_p, buf, buf], c_int),
    "secp256k1_mojo_ec_pubkey_create_uncompressed": ([c_void_p, buf, buf], c_int),
    "secp256k1_mojo_ecdsa_sign": ([c_void_p, buf, buf, buf], c_int),
    "secp256k1_mojo_ecdsa_sign_recoverable": (
        [c_void_p, buf, POINTER(c_int), buf, buf],
        c_int,
    ),
    "secp256k1_mojo_ecdsa_verify": ([c_void_p, buf, buf, buf, c_int], c_int),
    "secp256k1_mojo_ecdsa_recover": ([c_void_p, buf, buf, c_int, buf], c_int),
    "secp256k1_mojo_ecdsa_signature_to_der": (
        [c_void_p, buf, POINTER(c_int), buf],
        c_int,
    ),
    "secp256k1_mojo_ecdh": ([c_void_p, buf, buf, c_int, buf], c_int),
    "secp256k1_mojo_ec_seckey_tweak_add": ([c_void_p, buf, buf], c_int),
    "secp256k1_mojo_ec_seckey_tweak_mul": ([c_void_p, buf, buf], c_int),
}
for _name, (_args, _ret) in _SIGS.items():
    _fn = getattr(lib, _name)
    _fn.argtypes = _args
    _fn.restype = _ret


class Secp256k1:
    """A thin, Pythonic wrapper over the C ABI."""

    def __init__(self):
        self._ctx = lib.secp256k1_mojo_context_create()

    def close(self):
        if self._ctx:
            lib.secp256k1_mojo_context_destroy(self._ctx)
            self._ctx = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def seckey_verify(self, seckey: bytes) -> bool:
        return bool(lib.secp256k1_mojo_ec_seckey_verify(self._ctx, seckey))

    def pubkey(self, seckey: bytes, compressed: bool = True) -> bytes:
        size = 33 if compressed else 65
        fn = (
            lib.secp256k1_mojo_ec_pubkey_create
            if compressed
            else lib.secp256k1_mojo_ec_pubkey_create_uncompressed
        )
        out = ctypes.create_string_buffer(size)
        if not fn(self._ctx, out, seckey):
            raise ValueError("invalid secret key")
        return out.raw[:size]

    def sign(self, msg32: bytes, seckey: bytes) -> bytes:
        out = ctypes.create_string_buffer(64)
        if not lib.secp256k1_mojo_ecdsa_sign(self._ctx, out, msg32, seckey):
            raise ValueError("signing failed")
        return out.raw[:64]

    def sign_recoverable(self, msg32: bytes, seckey: bytes):
        out = ctypes.create_string_buffer(64)
        recid = c_int(0)
        if not lib.secp256k1_mojo_ecdsa_sign_recoverable(
            self._ctx, out, ctypes.byref(recid), msg32, seckey
        ):
            raise ValueError("signing failed")
        return out.raw[:64], recid.value

    def verify(self, sig64: bytes, msg32: bytes, pubkey: bytes) -> bool:
        return bool(
            lib.secp256k1_mojo_ecdsa_verify(
                self._ctx, sig64, msg32, pubkey, len(pubkey)
            )
        )

    def recover(self, sig64: bytes, recid: int, msg32: bytes) -> bytes:
        out = ctypes.create_string_buffer(33)
        if not lib.secp256k1_mojo_ecdsa_recover(
            self._ctx, out, sig64, recid, msg32
        ):
            raise ValueError("recovery failed")
        return out.raw[:33]

    def to_der(self, sig64: bytes) -> bytes:
        out = ctypes.create_string_buffer(72)
        n = c_int(0)
        if not lib.secp256k1_mojo_ecdsa_signature_to_der(
            self._ctx, out, ctypes.byref(n), sig64
        ):
            raise ValueError("DER encoding failed")
        return out.raw[: n.value]

    def shared_secret(self, pubkey: bytes, seckey: bytes) -> bytes:
        """The raw shared point. Hash it before using it as a key."""
        out = ctypes.create_string_buffer(33)
        if not lib.secp256k1_mojo_ecdh(
            self._ctx, out, pubkey, len(pubkey), seckey
        ):
            raise ValueError("ecdh failed")
        return out.raw[:33]

    def seckey_tweak_add(self, seckey: bytes, tweak: bytes) -> bytes:
        """Returns (seckey + tweak) mod n; the C call tweaks in place, so the
        input is copied into a mutable buffer first."""
        work = ctypes.create_string_buffer(seckey, 32)
        if not lib.secp256k1_mojo_ec_seckey_tweak_add(self._ctx, work, tweak):
            raise ValueError("tweak failed")
        return work.raw[:32]


def main():
    seckey = bytes((1 + i * 7) & 0xFF for i in range(32))
    msg = bytes((200 - i * 3) & 0xFF for i in range(32))
    tweak = bytes((i * 3 + 5) & 0xFF for i in range(32))

    with Secp256k1() as ctx:
        assert ctx.seckey_verify(seckey)
        assert not ctx.seckey_verify(bytes(32))  # all zeros is not a valid key

        pub = ctx.pubkey(seckey)
        sig = ctx.sign(msg, seckey)

        print("pubkey      ", pub.hex())
        print("uncompressed", ctx.pubkey(seckey, compressed=False).hex())
        print("signature   ", sig.hex())
        print("der         ", ctx.to_der(sig).hex())
        print("verify      ", ctx.verify(sig, msg, pub))

        tampered = bytearray(msg)
        tampered[0] ^= 0xFF
        print("tampered    ", ctx.verify(sig, bytes(tampered), pub))

        rsig, recid = ctx.sign_recoverable(msg, seckey)
        recovered = ctx.recover(rsig, recid, msg)
        print("recovered   ", recovered.hex())

        print("ecdh        ", ctx.shared_secret(pub, seckey).hex())

        tweaked = ctx.seckey_tweak_add(seckey, tweak)
        print("tweaked key ", tweaked.hex())

        assert ctx.verify(sig, msg, pub)
        assert not ctx.verify(sig, bytes(tampered), pub)
        assert recovered == pub
        assert tweaked != seckey and ctx.seckey_verify(tweaked)
        print("\nall checks passed")


if __name__ == "__main__":
    main()
