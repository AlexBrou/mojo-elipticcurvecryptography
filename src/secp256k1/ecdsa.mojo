"""ECDSA signing, verification, recovery, and DER encoding."""

from .ecmult import EcmultGenContext, ecmult, ecmult_var
from .field import Fe
from .group import Ge, Gej
from sha256 import Rfc6979
from .scalar import Scalar
from .scrub import scrub_u8


@always_inline
def _order_as_fe() -> Fe:
    """The group order n, reduced into the field (n < p)."""
    return Fe.from_limbs(
        0x25E8CD0364141,
        0xE6AF48A03BBFD,
        0xFFFFFFEBAAEDC,
        0xFFFFFFFFFFFFF,
        0xFFFFFFFFFFFF,
    )


@always_inline
def _p_minus_order() -> Fe:
    return Fe.from_limbs(0xDA1722FC9BAEE, 0x1950B75FC4402, 0x1455123, 0, 0)


@fieldwise_init
struct Signature(Copyable, ImplicitlyCopyable, Movable):
    var r: Scalar
    var s: Scalar

    @staticmethod
    def parse_compact(sig: Span[UInt8, _]) raises -> Tuple[Signature, Bool]:
        """Parse 64 bytes as r||s; the Bool is False when either overflows n."""
        if len(sig) != 64:
            raise Error("compact signature must be 64 bytes")
        var r = Scalar.from_bytes(sig[0:32])
        var s = Scalar.from_bytes(sig[32:64])
        return (Signature(r[0], s[0]), not r[1] and not s[1])

    def serialize_compact(self) -> List[UInt8]:
        var out = self.r.to_bytes()
        out.extend(self.s.to_bytes())
        return out^

    def normalize(self) -> Signature:
        """Force s into the lower half of the range (BIP 62 low-S)."""
        return Signature(self.r, self.s.cond_negate(self.s.is_high()))

    def is_normalized(self) -> Bool:
        return not self.s.is_high()

    def serialize_der(self) -> List[UInt8]:
        var rb = _der_int(self.r.to_bytes())
        var sb = _der_int(self.s.to_bytes())
        var out = List[UInt8](capacity=6 + len(rb) + len(sb))
        out.append(0x30)
        out.append(UInt8(len(rb) + len(sb) + 4))
        out.append(0x02)
        out.append(UInt8(len(rb)))
        out.extend(rb^)
        out.append(0x02)
        out.append(UInt8(len(sb)))
        out.extend(sb^)
        return out^


def _der_int(b: List[UInt8]) -> List[UInt8]:
    """Minimal big-endian DER INTEGER content: strip leading zeros, then add
    one back if the top bit would make the value look negative."""
    var i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    var out = List[UInt8]()
    if b[i] & 0x80:
        out.append(0)
    for j in range(i, len(b)):
        out.append(b[j])
    return out^


def sign(
    ctx: EcmultGenContext, msg32: Span[UInt8, _], seckey32: Span[UInt8, _]
) raises -> Tuple[Signature, Int, Bool]:
    """Deterministic (RFC 6979) ECDSA signature.

    Returns (signature, recovery id, ok). `ok` is False for an invalid secret
    key or, astronomically unlikely, a nonce that yields a degenerate signature.
    """
    if len(msg32) != 32 or len(seckey32) != 32:
        raise Error("message and secret key must be 32 bytes each")

    var sk = Scalar.from_bytes(seckey32)
    if sk[1] or sk[0].is_zero():
        return (Signature(Scalar.zero(), Scalar.zero()), 0, False)
    var sec = sk[0]
    var msg = Scalar.from_bytes(msg32)[0]

    # RFC 6979 key material: seckey || message reduced mod n.
    var keydata = InlineArray[UInt8, 64](fill=0)
    var msg_bytes = msg.to_bytes()
    for i in range(32):
        keydata[i] = seckey32[i]
        keydata[32 + i] = msg_bytes[i]
    var rng = Rfc6979(keydata)
    # keydata holds a copy of the secret key; the DRBG has absorbed it.
    for i in range(64):
        scrub_u8(keydata[i])

    var attempt = 0
    while attempt < 1000:
        var nonce_bytes = rng.generate()
        var k = Scalar.from_bytes(nonce_bytes)
        var nonce = k[0]
        for i in range(32):
            scrub_u8(nonce_bytes[i])
        if not k[1] and not nonce.is_zero():
            var res = sign_with_nonce(ctx, msg, sec, nonce)
            nonce.clear()
            if res[2]:
                sec.clear()
                rng.clear()
                return res
        nonce.clear()
        attempt += 1

    sec.clear()
    rng.clear()
    return (Signature(Scalar.zero(), Scalar.zero()), 0, False)


def sign_with_nonce(
    ctx: EcmultGenContext, msg: Scalar, sec: Scalar, nonce: Scalar
) -> Tuple[Signature, Int, Bool]:
    """The core signing step for a caller-supplied nonce."""
    var rp = ctx.mult(nonce).to_ge_var()
    var rx = rp.x
    var ry = rp.y
    rx.normalize()
    ry.normalize()

    var rb = rx.to_bytes()
    var parsed = Scalar.from_bytes(rb)
    var sigr = parsed[0]
    var overflow = parsed[1]

    var recid = (Int(overflow) << 1) | Int(ry.is_odd_norm())

    var n = sigr * sec + msg
    var kinv = nonce.inverse()
    var sigs = kinv * n

    var high = sigs.is_high()
    sigs = sigs.cond_negate(high)
    if high:
        recid ^= 1

    # n and 1/k both reveal the secret key when combined with the signature;
    # rp is the nonce point. None of them are needed past this line.
    n.clear()
    kinv.clear()
    rp.clear()
    rx.clear()
    ry.clear()

    var ok = not sigr.is_zero() and not sigs.is_zero()
    return (Signature(sigr, sigs), recid, ok)


def verify(
    ctx: EcmultGenContext, sig: Signature, msg32: Span[UInt8, _], pubkey: Ge
) raises -> Bool:
    """Verify a signature. Signatures with high s are rejected (BIP 62)."""
    if len(msg32) != 32:
        raise Error("message must be 32 bytes")
    if pubkey.infinity:
        return False
    if sig.s.is_high():
        return False
    return verify_raw(ctx, sig, Scalar.from_bytes(msg32)[0], pubkey)


def verify_raw(
    ctx: EcmultGenContext, sig: Signature, msg: Scalar, pubkey: Ge
) -> Bool:
    """Verify without the low-s requirement."""
    if sig.r.is_zero() or sig.s.is_zero():
        return False

    var sn = sig.s.inverse_var()
    var u1 = sn * msg
    var u2 = sn * sig.r

    var pr = ecmult(ctx, Gej.from_ge(pubkey), u2, u1)
    if pr.is_infinity():
        return False

    # Compare sig.r (a scalar) with the x coordinate of pr without inverting z.
    var xr = Fe.from_bytes_mod(sig.r.to_bytes())
    if _gej_eq_x(xr, pr):
        return True
    # x could also be sig.r + n, but only when that still fits below p.
    if xr.cmp_var(_p_minus_order()) >= 0:
        return False
    xr.add_assign(_order_as_fe())
    return _gej_eq_x(xr, pr)


def _gej_eq_x(x: Fe, a: Gej) -> Bool:
    var r = a.z.sqr() * x
    return r.equal(a.x)


def recover(
    ctx: EcmultGenContext, sig: Signature, msg32: Span[UInt8, _], recid: Int
) raises -> Tuple[Ge, Bool]:
    """Recover the public key that produced a signature."""
    if len(msg32) != 32:
        raise Error("message must be 32 bytes")
    if recid < 0 or recid > 3:
        raise Error("recovery id must be in 0..3")
    if sig.r.is_zero() or sig.s.is_zero():
        return (Ge.infinity_point(), False)

    var msg = Scalar.from_bytes(msg32)[0]
    var fx = Fe.from_bytes_mod(sig.r.to_bytes())
    if recid & 2:
        if fx.cmp_var(_p_minus_order()) >= 0:
            return (Ge.infinity_point(), False)
        fx.add_assign(_order_as_fe())

    var xres = Ge.set_xo_var(fx, (recid & 1) != 0)
    if not xres[1]:
        return (Ge.infinity_point(), False)

    var rn = sig.r.inverse_var()
    var u1 = (rn * msg).negated()
    var u2 = rn * sig.s
    var qj = ecmult(ctx, Gej.from_ge(xres[0]), u2, u1)
    if qj.is_infinity():
        return (Ge.infinity_point(), False)
    return (qj.to_ge_var(), True)
