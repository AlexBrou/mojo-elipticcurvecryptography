"""Scalar arithmetic modulo the group order n.

Four 64-bit limbs, least significant first — the `scalar_4x64` representation
of libsecp256k1. Values are always kept fully reduced in [0, n).
"""

from .modinv import ModInfo, Signed62, modinv, modinv_var
from .scrub import scrub_u64

comptime N0: UInt64 = 0xBFD25E8CD0364141
comptime N1: UInt64 = 0xBAAEDCE6AF48A03B
comptime N2: UInt64 = 0xFFFFFFFFFFFFFFFE
comptime N3: UInt64 = 0xFFFFFFFFFFFFFFFF

# Limbs of 2^256 - n.
comptime NC0: UInt64 = ~N0 + 1
comptime NC1: UInt64 = ~N1
comptime NC2: UInt64 = 1

# Limbs of n // 2.
comptime NH0: UInt64 = 0xDFE92F46681B20A0
comptime NH1: UInt64 = 0x5D576E7357A4501D
comptime NH2: UInt64 = 0xFFFFFFFFFFFFFFFF
comptime NH3: UInt64 = 0x7FFFFFFFFFFFFFFF

comptime U64MAX = UInt128(0xFFFFFFFFFFFFFFFF)


@always_inline
def _lo(c: UInt128) -> UInt64:
    return UInt64(c & U64MAX)


@always_inline
def _hi(c: UInt128) -> UInt64:
    return UInt64(c >> 64)


@fieldwise_init
struct Scalar(Equatable, ImplicitlyCopyable):
    var d0: UInt64
    var d1: UInt64
    var d2: UInt64
    var d3: UInt64

    @staticmethod
    def zero() -> Scalar:
        return Scalar(0, 0, 0, 0)

    @staticmethod
    def one() -> Scalar:
        return Scalar(1, 0, 0, 0)

    @staticmethod
    def from_int(v: UInt64) -> Scalar:
        return Scalar(v, 0, 0, 0)

    @staticmethod
    def from_limbs(a0: UInt64, a1: UInt64, a2: UInt64, a3: UInt64) -> Scalar:
        return Scalar(a0, a1, a2, a3)

    # ---------------------------------------------------------- serialization

    @staticmethod
    def from_bytes(b: Span[UInt8, _]) -> Tuple[Scalar, Bool]:
        """Parse 32 big-endian bytes; the Bool reports whether it overflowed n.
        """
        var r = Scalar(
            _read_be64(b, 24),
            _read_be64(b, 16),
            _read_be64(b, 8),
            _read_be64(b, 0),
        )
        var over = r.check_overflow()
        r = _reduce(r, UInt64(over))
        return (r, over)

    def to_bytes(self) -> List[UInt8]:
        var out = List[UInt8](capacity=32)
        _push_be64(out, self.d3)
        _push_be64(out, self.d2)
        _push_be64(out, self.d1)
        _push_be64(out, self.d0)
        return out^

    # ---------------------------------------------------------------- queries

    def check_overflow(self) -> Bool:
        """Whether the raw limbs are >= n.

        Written with bitwise operators rather than `and`/`or`, which
        short-circuit: this runs on secret scalars, so the work must not depend
        on the value.
        """
        var yes = 0
        var no = 0
        no |= Int(self.d3 < N3)
        no |= Int(self.d2 < N2)
        yes |= Int(self.d2 > N2) & ~no
        no |= Int(self.d1 < N1)
        yes |= Int(self.d1 > N1) & ~no
        yes |= Int(self.d0 >= N0) & ~no
        return yes != 0

    def is_zero(self) -> Bool:
        return (self.d0 | self.d1 | self.d2 | self.d3) == 0

    def is_one(self) -> Bool:
        return ((self.d0 ^ 1) | self.d1 | self.d2 | self.d3) == 0

    def is_even(self) -> Bool:
        return (self.d0 & 1) == 0

    def is_high(self) -> Bool:
        """True when the scalar is greater than n // 2. Branch-free."""
        var yes = 0
        var no = 0
        no |= Int(self.d3 < NH3)
        yes |= Int(self.d3 > NH3) & ~no
        no |= Int(self.d2 < NH2) & ~yes
        no |= Int(self.d1 < NH1) & ~yes
        yes |= Int(self.d1 > NH1) & ~no
        yes |= Int(self.d0 > NH0) & ~no
        return yes != 0

    def __eq__(self, other: Scalar) -> Bool:
        return (
            (self.d0 ^ other.d0)
            | (self.d1 ^ other.d1)
            | (self.d2 ^ other.d2)
            | (self.d3 ^ other.d3)
        ) == 0

    def __ne__(self, other: Scalar) -> Bool:
        return not (self == other)

    def get_bits(self, offset: Int, count: Int) -> UInt32:
        """Extract `count` bits (<= 32) starting at bit `offset`."""
        var limb = offset >> 6
        var shift = offset & 0x3F
        var mask = UInt64(0xFFFFFFFF) >> UInt64(32 - count)
        var lo = self._limb(limb) >> UInt64(shift)
        if shift != 0 and (offset + count - 1) >> 6 != limb:
            lo |= self._limb(limb + 1) << UInt64(64 - shift)
        return UInt32(lo & mask)

    def _limb(self, i: Int) -> UInt64:
        if i == 0:
            return self.d0
        if i == 1:
            return self.d1
        if i == 2:
            return self.d2
        if i == 3:
            return self.d3
        return 0

    # ------------------------------------------------------------- arithmetic

    def __add__(self, b: Scalar) -> Scalar:
        var r = self.add_with_overflow(b)
        return r[0]

    @always_inline
    def add_with_overflow(self, b: Scalar) -> Tuple[Scalar, Bool]:
        var t = UInt128(self.d0) + UInt128(b.d0)
        var r0 = _lo(t)
        t >>= 64
        t += UInt128(self.d1) + UInt128(b.d1)
        var r1 = _lo(t)
        t >>= 64
        t += UInt128(self.d2) + UInt128(b.d2)
        var r2 = _lo(t)
        t >>= 64
        t += UInt128(self.d3) + UInt128(b.d3)
        var r3 = _lo(t)
        t >>= 64
        var r = Scalar(r0, r1, r2, r3)
        var over = _lo(t) + UInt64(r.check_overflow())
        return (_reduce(r, over), over != 0)

    @always_inline
    def negated(self) -> Scalar:
        var nonzero = UInt64(0xFFFFFFFFFFFFFFFF) * UInt64(not self.is_zero())
        var t = UInt128(~self.d0) + UInt128(N0 + 1)
        var r0 = _lo(t) & nonzero
        t >>= 64
        t += UInt128(~self.d1) + UInt128(N1)
        var r1 = _lo(t) & nonzero
        t >>= 64
        t += UInt128(~self.d2) + UInt128(N2)
        var r2 = _lo(t) & nonzero
        t >>= 64
        t += UInt128(~self.d3) + UInt128(N3)
        var r3 = _lo(t) & nonzero
        return Scalar(r0, r1, r2, r3)

    def cond_negate(self, flag: Bool) -> Scalar:
        """Negate when `flag`, without branching: both values are computed and
        one is selected, because `flag` is derived from a secret."""
        var r = self
        r.cmov(self.negated(), flag)
        return r

    def half(self) -> Scalar:
        """Divide by two modulo n."""
        var mask = UInt64(0) - (self.d0 & 1)
        var t = UInt128((self.d0 >> 1) | (self.d1 << 63)) + UInt128(
            (NH0 + 1) & mask
        )
        var r0 = _lo(t)
        t >>= 64
        t += UInt128((self.d1 >> 1) | (self.d2 << 63)) + UInt128(NH1 & mask)
        var r1 = _lo(t)
        t >>= 64
        t += UInt128((self.d2 >> 1) | (self.d3 << 63)) + UInt128(NH2 & mask)
        var r2 = _lo(t)
        t >>= 64
        var r3 = _lo(t) + (self.d3 >> 1) + (NH3 & mask)
        return Scalar(r0, r1, r2, r3)

    @always_inline
    def __mul__(self, b: Scalar) -> Scalar:
        var l = _mul_512(self, b)
        return _reduce_512(l)

    def cadd_bit(self, bit: Int, flag: Bool) -> Scalar:
        """Add 2^bit when flag is set."""
        var b = bit + ((Int(flag) - 1) & 0x100)
        var sh = UInt64(b & 0x3F)
        var t = UInt128(self.d0) + UInt128(UInt64((b >> 6) == 0) << sh)
        var r0 = _lo(t)
        t >>= 64
        t += UInt128(self.d1) + UInt128(UInt64((b >> 6) == 1) << sh)
        var r1 = _lo(t)
        t >>= 64
        t += UInt128(self.d2) + UInt128(UInt64((b >> 6) == 2) << sh)
        var r2 = _lo(t)
        t >>= 64
        t += UInt128(self.d3) + UInt128(UInt64((b >> 6) == 3) << sh)
        var r3 = _lo(t)
        return Scalar(r0, r1, r2, r3)

    def clear(mut self):
        """Wipe the value. For nonces and secret keys once they are finished
        with; see `scrub.mojo` for why this is not just `self = zero()`."""
        scrub_u64(self.d0)
        scrub_u64(self.d1)
        scrub_u64(self.d2)
        scrub_u64(self.d3)

    def cmov(mut self, a: Scalar, flag: Bool):
        var mask1 = UInt64(0) - UInt64(flag)
        var mask0 = ~mask1
        self.d0 = (self.d0 & mask0) | (a.d0 & mask1)
        self.d1 = (self.d1 & mask0) | (a.d1 & mask1)
        self.d2 = (self.d2 & mask0) | (a.d2 & mask1)
        self.d3 = (self.d3 & mask0) | (a.d3 & mask1)

    def inverse(self) -> Scalar:
        """Constant-time modular inverse. The inverse of zero is zero."""
        return _sc_from_signed62(
            modinv(_sc_to_signed62(self), ModInfo.scalar())
        )

    def inverse_var(self) -> Scalar:
        """Variable-time modular inverse — only for public values."""
        return _sc_from_signed62(
            modinv_var(_sc_to_signed62(self), ModInfo.scalar())
        )

    def inverse_pow(self) -> Scalar:
        """Inverse via a^(n-2) windowed exponentiation. Kept as an independent
        implementation to cross-check `inverse` in the tests."""
        return _inverse(self)

    # ------------------------------------------------------------- decomposing

    def split_128(self) -> Tuple[Scalar, Scalar]:
        return (Scalar(self.d0, self.d1, 0, 0), Scalar(self.d2, self.d3, 0, 0))

    def split_lambda(self) -> Tuple[Scalar, Scalar]:
        """Decompose k as k1 + k2*lambda with both halves about 128 bits."""
        var c1 = _mul_shift_384(self, G1)
        var c2 = _mul_shift_384(self, G2)
        c1 = c1 * MINUS_B1
        c2 = c2 * MINUS_B2
        var r2 = c1 + c2
        var r1 = (r2 * LAMBDA).negated() + self
        return (r1, r2)


comptime LAMBDA = Scalar(
    0xDF02967C1B23BD72,
    0x122E22EA20816678,
    0xA5261C028812645A,
    0x5363AD4CC05C30E0,
)
comptime MINUS_B1 = Scalar(0x6F547FA90ABFE4C3, 0xE4437ED6010E8828, 0, 0)
comptime MINUS_B2 = Scalar(
    0xD765CDA83DB1562C,
    0x8A280AC50774346D,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
)
comptime G1 = Scalar(
    0xE893209A45DBB031,
    0x3DAA8A1471E8CA7F,
    0xE86C90E49284EB15,
    0x3086D221A7D46BCD,
)
comptime G2 = Scalar(
    0x1571B4AE8AC47F71,
    0x221208AC9DF506C6,
    0x6F547FA90ABFE4C4,
    0xE4437ED6010E8828,
)


def _read_be64(b: Span[UInt8, _], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v = (v << 8) | UInt64(b[off + i])
    return v


def _push_be64(mut out: List[UInt8], v: UInt64):
    for i in range(8):
        out.append(UInt8((v >> UInt64(56 - 8 * i)) & 0xFF))


@always_inline
def _reduce(a: Scalar, overflow: UInt64) -> Scalar:
    """Conditionally add 2^256 - n, `overflow` times (0 or 1)."""
    var t = UInt128(a.d0) + UInt128(overflow * NC0)
    var r0 = _lo(t)
    t >>= 64
    t += UInt128(a.d1) + UInt128(overflow * NC1)
    var r1 = _lo(t)
    t >>= 64
    t += UInt128(a.d2) + UInt128(overflow * NC2)
    var r2 = _lo(t)
    t >>= 64
    t += UInt128(a.d3)
    var r3 = _lo(t)
    return Scalar(r0, r1, r2, r3)


def _mul_512(a: Scalar, b: Scalar) -> Array[UInt64, 8]:
    """Schoolbook 4x4 -> 8 limb product."""
    var av: Array[UInt64, 4] = [a.d0, a.d1, a.d2, a.d3]
    var bv: Array[UInt64, 4] = [b.d0, b.d1, b.d2, b.d3]
    var l = Array[UInt64, 8](fill=0)
    for i in range(4):
        var carry = UInt64(0)
        for j in range(4):
            var t = (
                UInt128(av[i]) * UInt128(bv[j])
                + UInt128(l[i + j])
                + UInt128(carry)
            )
            l[i + j] = _lo(t)
            carry = _hi(t)
        l[i + 4] = carry
    return l^


@always_inline
def _reduce_512(l: Array[UInt64, 8]) -> Scalar:
    """Reduce a 512-bit value modulo n, following scalar_4x64_impl.h."""
    var n0 = l[4]
    var n1 = l[5]
    var n2 = l[6]
    var n3 = l[7]

    # Round 1: fold the top 256 bits down, producing m0..m6.
    # muladd_fast(n0, NC0) then extract_fast(m0)
    var t = UInt128(n0) * UInt128(NC0) + UInt128(l[0])
    var m0 = _lo(t)
    var acc = _Acc(_hi(t), 0, 0)
    acc.sumadd(l[1])
    acc.muladd(n1, NC0)
    acc.muladd(n0, NC1)
    var m1 = acc.extract()
    acc.sumadd(l[2])
    acc.muladd(n2, NC0)
    acc.muladd(n1, NC1)
    acc.sumadd(n0)
    var m2 = acc.extract()
    acc.sumadd(l[3])
    acc.muladd(n3, NC0)
    acc.muladd(n2, NC1)
    acc.sumadd(n1)
    var m3 = acc.extract()
    acc.muladd(n3, NC1)
    acc.sumadd(n2)
    var m4 = acc.extract()
    acc.sumadd(n3)
    var m5 = acc.extract()
    var m6 = acc.c0

    # Round 2: fold m4..m6 down, producing p0..p4.
    acc = _Acc(m0, 0, 0)
    acc.muladd(m4, NC0)
    var p0 = acc.extract()
    acc.sumadd(m1)
    acc.muladd(m5, NC0)
    acc.muladd(m4, NC1)
    var p1 = acc.extract()
    acc.sumadd(m2)
    acc.muladd(m6, NC0)
    acc.muladd(m5, NC1)
    acc.sumadd(m4)
    var p2 = acc.extract()
    acc.sumadd(m3)
    acc.muladd(m6, NC1)
    acc.sumadd(m5)
    var p3 = acc.extract()
    var p4 = acc.c0 + m6

    # Round 3: fold the final 32-bit-ish carry p4 down.
    var c128 = UInt128(p0) + UInt128(NC0) * UInt128(p4)
    var r0 = _lo(c128)
    c128 >>= 64
    c128 += UInt128(p1) + UInt128(NC1) * UInt128(p4)
    var r1 = _lo(c128)
    c128 >>= 64
    c128 += UInt128(p2) + UInt128(p4)
    var r2 = _lo(c128)
    c128 >>= 64
    c128 += UInt128(p3)
    var r3 = _lo(c128)
    var c = _hi(c128)

    var r = Scalar(r0, r1, r2, r3)
    return _reduce(r, c + UInt64(r.check_overflow()))


@fieldwise_init
struct _Acc(ImplicitlyCopyable):
    """A 192-bit accumulator matching the muladd/sumadd/extract macros."""

    var c0: UInt64
    var c1: UInt64
    var c2: UInt64

    @always_inline
    def muladd(mut self, a: UInt64, b: UInt64):
        var t = UInt128(a) * UInt128(b)
        var tl = _lo(t)
        var th = _hi(t)
        self.c0 += tl
        th += UInt64(self.c0 < tl)
        self.c1 += th
        self.c2 += UInt64(self.c1 < th)

    @always_inline
    def sumadd(mut self, a: UInt64):
        self.c0 += a
        var over = UInt64(self.c0 < a)
        self.c1 += over
        self.c2 += UInt64(self.c1 < over)

    @always_inline
    def extract(mut self) -> UInt64:
        var n = self.c0
        self.c0 = self.c1
        self.c1 = self.c2
        self.c2 = 0
        return n


def _mul_shift_384(a: Scalar, b: Scalar) -> Scalar:
    """(a * b) >> 384, rounded to nearest."""
    var l = _mul_512(a, b)
    var r = Scalar(l[6], l[7], 0, 0)
    # round up when bit 383 of the product is set
    return r.cadd_bit(0, ((l[5] >> 63) & 1) != 0)


# n - 2, the Fermat inversion exponent, most significant limb first.
comptime _NM2_3: UInt64 = 0xFFFFFFFFFFFFFFFF
comptime _NM2_2: UInt64 = 0xFFFFFFFFFFFFFFFE
comptime _NM2_1: UInt64 = 0xBAAEDCE6AF48A03B
comptime _NM2_0: UInt64 = 0xBFD25E8CD036413F


def _inverse(a: Scalar) -> Scalar:
    """a^(n-2) mod n via a fixed 4-bit window. The exponent is public, so the
    window pattern leaks nothing about `a`."""
    # table[i] = a^i for i in 0..15
    var table = Array[Scalar, 16](fill=Scalar.one())
    table[1] = a
    for i in range(2, 16):
        table[i] = table[i - 1] * a

    var limbs: Array[UInt64, 4] = [_NM2_0, _NM2_1, _NM2_2, _NM2_3]
    var r = Scalar.one()
    var started = False
    for w in range(63, -1, -1):
        var limb = limbs[w >> 4]
        var nib = (limb >> UInt64((w & 15) * 4)) & 0xF
        if started:
            r = r * r
            r = r * r
            r = r * r
            r = r * r
        if nib != 0:
            r = r * table[Int(nib)]
            started = True
    return r


def _sc_to_signed62(a: Scalar) -> Signed62:
    var m = Int64(0xFFFFFFFFFFFFFFFF >> 2)
    return Signed62.of(
        Int64(a.d0) & m,
        Int64((a.d0 >> 62) | (a.d1 << 2)) & m,
        Int64((a.d1 >> 60) | (a.d2 << 4)) & m,
        Int64((a.d2 >> 58) | (a.d3 << 6)) & m,
        Int64(a.d3 >> 56),
    )


def _sc_from_signed62(a: Signed62) -> Scalar:
    var a0 = UInt64(a.v[0])
    var a1 = UInt64(a.v[1])
    var a2 = UInt64(a.v[2])
    var a3 = UInt64(a.v[3])
    var a4 = UInt64(a.v[4])
    return Scalar(
        a0 | (a1 << 62),
        (a1 >> 2) | (a2 << 60),
        (a2 >> 4) | (a3 << 58),
        (a3 >> 6) | (a4 << 56),
    )
