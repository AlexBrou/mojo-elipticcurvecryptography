"""The public, batteries-included entry point.

`Secp256k1` owns the precomputed generator table, so build one and keep it —
constructing it costs about a thousand point operations.
"""

from .ecdsa import Signature, sign, verify, recover
from .ecmult import EcmultGenContext, ecmult_const
from .group import Ge, Gej
from .scalar import Scalar


def _scalar32(
    b: Span[UInt8, _], what: StaticString
) raises -> Tuple[Scalar, Bool]:
    """Parse a 32-byte scalar, rejecting a wrong-length input.

    `Scalar.from_bytes` reads 32 bytes unconditionally. A shorter span aborts
    on a bounds check with assertions enabled, and reads past the end of the
    buffer under `-D ASSERT=none` -- where it returned a key derived from
    whatever followed the input. Every entry point that takes caller-supplied
    bytes checks the length first, as `sign()` and `verify()` already did.
    """
    if len(b) != 32:
        raise Error(String(what, " must be 32 bytes"))
    return Scalar.from_bytes(b)


struct Secp256k1(Movable):
    var gen: EcmultGenContext

    def __init__(out self):
        self.gen = EcmultGenContext()

    # ------------------------------------------------------------------ keys

    def seckey_verify(self, seckey32: Span[UInt8, _]) raises -> Bool:
        if len(seckey32) != 32:
            return False
        var s = Scalar.from_bytes(seckey32)
        return not s[1] and not s[0].is_zero()

    def pubkey_create(self, seckey32: Span[UInt8, _]) raises -> Tuple[Ge, Bool]:
        var s = _scalar32(seckey32, "secret key")
        if s[1] or s[0].is_zero():
            return (Ge.infinity_point(), False)
        return (self.gen.mult(s[0]).to_ge_var(), True)

    def pubkey_parse(self, pub: Span[UInt8, _]) -> Tuple[Ge, Bool]:
        return Ge.parse(pub)

    # ---------------------------------------------------------------- tweaks

    def seckey_tweak_add(
        self, seckey32: Span[UInt8, _], tweak32: Span[UInt8, _]
    ) raises -> Tuple[List[UInt8], Bool]:
        var s = _scalar32(seckey32, "secret key")
        var t = _scalar32(tweak32, "tweak")
        if s[1] or s[0].is_zero() or t[1]:
            return (List[UInt8](), False)
        var r = s[0] + t[0]
        if r.is_zero():
            return (List[UInt8](), False)
        return (r.to_bytes(), True)

    def seckey_tweak_mul(
        self, seckey32: Span[UInt8, _], tweak32: Span[UInt8, _]
    ) raises -> Tuple[List[UInt8], Bool]:
        var s = _scalar32(seckey32, "secret key")
        var t = _scalar32(tweak32, "tweak")
        if s[1] or s[0].is_zero() or t[1] or t[0].is_zero():
            return (List[UInt8](), False)
        return ((s[0] * t[0]).to_bytes(), True)

    def pubkey_tweak_add(
        self, pubkey: Ge, tweak32: Span[UInt8, _]
    ) raises -> Tuple[Ge, Bool]:
        var t = _scalar32(tweak32, "tweak")
        if t[1] or pubkey.infinity:
            return (Ge.infinity_point(), False)
        var r = Gej.from_ge(pubkey).add_var(self.gen.mult(t[0]))
        if r.is_infinity():
            return (Ge.infinity_point(), False)
        return (r.to_ge_var(), True)

    def pubkey_tweak_mul(
        self, pubkey: Ge, tweak32: Span[UInt8, _]
    ) raises -> Tuple[Ge, Bool]:
        var t = _scalar32(tweak32, "tweak")
        if t[1] or t[0].is_zero() or pubkey.infinity:
            return (Ge.infinity_point(), False)
        var r = ecmult_const(pubkey, t[0])
        if r.is_infinity():
            return (Ge.infinity_point(), False)
        return (r.to_ge_var(), True)

    # ----------------------------------------------------------------- ecdsa

    def sign(
        self, msg32: Span[UInt8, _], seckey32: Span[UInt8, _]
    ) raises -> Tuple[Signature, Int, Bool]:
        return sign(self.gen, msg32, seckey32)

    def verify(
        self, sig: Signature, msg32: Span[UInt8, _], pubkey: Ge
    ) raises -> Bool:
        return verify(self.gen, sig, msg32, pubkey)

    def recover(
        self, sig: Signature, msg32: Span[UInt8, _], recid: Int
    ) raises -> Tuple[Ge, Bool]:
        return recover(self.gen, sig, msg32, recid)

    # ------------------------------------------------------------------ ecdh

    def ecdh_point(
        self, pubkey: Ge, seckey32: Span[UInt8, _]
    ) raises -> Tuple[Ge, Bool]:
        """The raw shared point seckey * pubkey (hash it before use)."""
        var s = _scalar32(seckey32, "secret key")
        if s[1] or s[0].is_zero() or pubkey.infinity:
            return (Ge.infinity_point(), False)
        var r = ecmult_const(pubkey, s[0])
        if r.is_infinity():
            return (Ge.infinity_point(), False)
        return (r.to_ge_var(), True)
