"""A constrained boundary over the secp256k1 API, for binding generation.

The library's own methods take `Span[UInt8, _]` and return tuples. That is the
right way to write them -- zero-copy, idiomatic -- but an unbound origin makes
each method *generic*, and a generic has no single symbol to reflect on.

This layer restates the same operations using only non-parametric types:
`List[UInt8]`, `Bool`, `Int`. Nothing here does marshalling, allocates, or
touches a raw pointer -- it is type simplification and error mapping only. The
C ABI shim is generated from it.

This is the same bargain uniffi strikes with Rust authors: write the boundary
in a supported type universe, get the FFI layer for free. The difference is
that here the universe is "types without unbound parameters", not a fixed list
a generator knows about.

Build the generated C ABI from it with
[mojo-bindgen](https://github.com/AlexBrou/mojo-bindgen); `ffi/capi.mojo` is
the equivalent layer written by hand.
"""

from secp256k1.api import Secp256k1
from secp256k1.ecdsa import Signature
from secp256k1.group import Ge


struct Secp(Movable):
    """An opaque handle exposed to foreign callers."""

    var inner: Secp256k1

    def __init__(out self):
        self.inner = Secp256k1()

    def seckey_verify(self, seckey32: List[UInt8]) raises -> Bool:
        return self.inner.seckey_verify(seckey32)

    def pubkey_create(self, seckey32: List[UInt8]) raises -> List[UInt8]:
        var r = self.inner.pubkey_create(seckey32)
        if not r[1]:
            raise Error("invalid secret key")
        return r[0].serialize33()

    def pubkey_create_uncompressed(
        self, seckey32: List[UInt8]
    ) raises -> List[UInt8]:
        var r = self.inner.pubkey_create(seckey32)
        if not r[1]:
            raise Error("invalid secret key")
        return r[0].serialize65()

    def sign(
        self, msg32: List[UInt8], seckey32: List[UInt8]
    ) raises -> List[UInt8]:
        var r = self.inner.sign(msg32, seckey32)
        if not r[2]:
            raise Error("signing failed")
        return r[0].serialize_compact()

    def verify(
        self, sig64: List[UInt8], msg32: List[UInt8], pubkey: List[UInt8]
    ) raises -> Bool:
        var pk = Ge.parse(pubkey)
        if not pk[1]:
            return False
        var sig = Signature.parse_compact(sig64)
        if not sig[1]:
            return False
        return self.inner.verify(sig[0], msg32, pk[0])

    def ecdh(
        self, pubkey: List[UInt8], seckey32: List[UInt8]
    ) raises -> List[UInt8]:
        var pk = Ge.parse(pubkey)
        if not pk[1]:
            raise Error("invalid public key")
        var r = self.inner.ecdh_point(pk[0], seckey32)
        if not r[1]:
            raise Error("ecdh failed")
        return r[0].serialize33()
