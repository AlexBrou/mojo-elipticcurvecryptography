"""Field arithmetic modulo p = 2^256 - 2^32 - 977.

Elements are held in 5 limbs of 52 bits (the top limb holds 48), matching the
`field_5x52` representation of libsecp256k1. Limbs are allowed to grow beyond
52 bits up to a "magnitude" bound; `normalize` brings a value back to the
unique canonical representative.
"""

from .modinv import ModInfo, Signed62, modinv, modinv_var
from .scrub import scrub_u64

comptime M52: UInt64 = 0xFFFFFFFFFFFFF
comptime M48: UInt64 = 0x0FFFFFFFFFFFF
# 2^256 mod p == 0x1000003D1; R is that value pre-shifted by 4 for the
# mul/sqr reduction, matching the reference implementation's constant.
comptime R: UInt64 = 0x1000003D10
comptime P0: UInt64 = 0xFFFFEFFFFFC2F


@fieldwise_init
struct Fe(Copyable, ImplicitlyCopyable, Movable):
    """Five 52-bit limbs, least significant first."""

    var n0: UInt64
    var n1: UInt64
    var n2: UInt64
    var n3: UInt64
    var n4: UInt64

    @staticmethod
    def zero() -> Fe:
        return Fe(0, 0, 0, 0, 0)

    @staticmethod
    def from_int(v: UInt64) -> Fe:
        return Fe(v, 0, 0, 0, 0)

    @staticmethod
    def from_limbs(
        a0: UInt64, a1: UInt64, a2: UInt64, a3: UInt64, a4: UInt64
    ) -> Fe:
        return Fe(a0, a1, a2, a3, a4)

    # ---------------------------------------------------------------- parsing

    @staticmethod
    def from_bytes_mod(b: Span[UInt8, _]) -> Fe:
        """Parse 32 big-endian bytes, reducing modulo 2^256 (not p)."""
        var l0 = (
            UInt64(b[31])
            | (UInt64(b[30]) << 8)
            | (UInt64(b[29]) << 16)
            | (UInt64(b[28]) << 24)
            | (UInt64(b[27]) << 32)
            | (UInt64(b[26]) << 40)
            | (UInt64(b[25] & 0xF) << 48)
        )
        var l1 = (
            UInt64((b[25] >> 4) & 0xF)
            | (UInt64(b[24]) << 4)
            | (UInt64(b[23]) << 12)
            | (UInt64(b[22]) << 20)
            | (UInt64(b[21]) << 28)
            | (UInt64(b[20]) << 36)
            | (UInt64(b[19]) << 44)
        )
        var l2 = (
            UInt64(b[18])
            | (UInt64(b[17]) << 8)
            | (UInt64(b[16]) << 16)
            | (UInt64(b[15]) << 24)
            | (UInt64(b[14]) << 32)
            | (UInt64(b[13]) << 40)
            | (UInt64(b[12] & 0xF) << 48)
        )
        var l3 = (
            UInt64((b[12] >> 4) & 0xF)
            | (UInt64(b[11]) << 4)
            | (UInt64(b[10]) << 12)
            | (UInt64(b[9]) << 20)
            | (UInt64(b[8]) << 28)
            | (UInt64(b[7]) << 36)
            | (UInt64(b[6]) << 44)
        )
        var l4 = (
            UInt64(b[5])
            | (UInt64(b[4]) << 8)
            | (UInt64(b[3]) << 16)
            | (UInt64(b[2]) << 24)
            | (UInt64(b[1]) << 32)
            | (UInt64(b[0]) << 40)
        )
        return Fe(l0, l1, l2, l3, l4)

    @staticmethod
    def from_bytes_limit(b: Span[UInt8, _]) -> Tuple[Fe, Bool]:
        """Parse 32 big-endian bytes; the Bool is False when the value was >= p.
        """
        var r = Fe.from_bytes_mod(b)
        var ok = not (
            (r.n4 == M48) and ((r.n3 & r.n2 & r.n1) == M52) and (r.n0 >= P0)
        )
        return (r, ok)

    def to_bytes(self) -> List[UInt8]:
        """Serialize a *normalized* element as 32 big-endian bytes."""
        var out = List[UInt8](capacity=32)
        _push_be64(out, (self.n4 << 16) | (self.n3 >> 36))
        _push_be64(out, (self.n3 << 28) | (self.n2 >> 24))
        _push_be64(out, (self.n2 << 40) | (self.n1 >> 12))
        _push_be64(out, (self.n1 << 52) | self.n0)
        return out^

    # ------------------------------------------------------------ normalizing

    def normalize(mut self):
        var t0 = self.n0
        var t1 = self.n1
        var t2 = self.n2
        var t3 = self.n3
        var t4 = self.n4

        var x = t4 >> 48
        t4 &= M48

        t0 += x * 0x1000003D1
        t1 += t0 >> 52
        t0 &= M52
        t2 += t1 >> 52
        t1 &= M52
        var m = t1
        t3 += t2 >> 52
        t2 &= M52
        m &= t2
        t4 += t3 >> 52
        t3 &= M52
        m &= t3

        x = (t4 >> 48) | (
            UInt64(t4 == M48) & UInt64(m == M52) & UInt64(t0 >= P0)
        )

        t0 += x * 0x1000003D1
        t1 += t0 >> 52
        t0 &= M52
        t2 += t1 >> 52
        t1 &= M52
        t3 += t2 >> 52
        t2 &= M52
        t4 += t3 >> 52
        t3 &= M52
        t4 &= M48

        self.n0 = t0
        self.n1 = t1
        self.n2 = t2
        self.n3 = t3
        self.n4 = t4

    @always_inline
    def normalize_weak(mut self):
        """Reduce limbs to magnitude 1 without a final conditional subtraction.
        """
        var t0 = self.n0
        var t1 = self.n1
        var t2 = self.n2
        var t3 = self.n3
        var t4 = self.n4

        var x = t4 >> 48
        t4 &= M48

        t0 += x * 0x1000003D1
        t1 += t0 >> 52
        t0 &= M52
        t2 += t1 >> 52
        t1 &= M52
        t3 += t2 >> 52
        t2 &= M52
        t4 += t3 >> 52
        t3 &= M52

        self.n0 = t0
        self.n1 = t1
        self.n2 = t2
        self.n3 = t3
        self.n4 = t4

    def normalized(self) -> Fe:
        var r = self
        r.normalize()
        return r

    def normalizes_to_zero(self) -> Bool:
        var t0 = self.n0
        var t1 = self.n1
        var t2 = self.n2
        var t3 = self.n3
        var t4 = self.n4

        var x = t4 >> 48
        t4 &= M48

        t0 += x * 0x1000003D1
        t1 += t0 >> 52
        t0 &= M52
        var z0 = t0
        var z1 = t0 ^ 0x1000003D0
        t2 += t1 >> 52
        t1 &= M52
        z0 |= t1
        z1 &= t1
        t3 += t2 >> 52
        t2 &= M52
        z0 |= t2
        z1 &= t2
        t4 += t3 >> 52
        t3 &= M52
        z0 |= t3
        z1 &= t3
        z0 |= t4
        z1 &= t4 ^ 0xF000000000000

        return (z0 == 0) or (z1 == M52)

    # ------------------------------------------------------------- predicates

    @always_inline
    def normalizes_to_zero_var(self) -> Bool:
        """Variable-time `normalizes_to_zero`.

        The fast path reads only limbs 0 and 4 and returns for the vast
        majority of inputs, which are not zero. Worth having because the
        variable-time group additions call this on every operation.
        """
        var t0 = self.n0
        var t4 = self.n4

        var x = t4 >> 48
        t0 += x * 0x1000003D1

        var z0 = t0 & M52
        var z1 = z0 ^ 0x1000003D0

        if (z0 != 0) and (z1 != M52):
            return False

        var t1 = self.n1
        var t2 = self.n2
        var t3 = self.n3
        t4 &= M48

        t1 += t0 >> 52
        t2 += t1 >> 52
        t1 &= M52
        z0 |= t1
        z1 &= t1
        t3 += t2 >> 52
        t2 &= M52
        z0 |= t2
        z1 &= t2
        t4 += t3 >> 52
        t3 &= M52
        z0 |= t3
        z1 &= t3
        z0 |= t4
        z1 &= t4 ^ 0xF000000000000

        return (z0 == 0) or (z1 == M52)

    def is_zero_norm(self) -> Bool:
        """True when a *normalized* element is zero."""
        return (self.n0 | self.n1 | self.n2 | self.n3 | self.n4) == 0

    def is_odd_norm(self) -> Bool:
        """Parity of a *normalized* element."""
        return (self.n0 & 1) != 0

    def equal(self, other: Fe) -> Bool:
        """Compare two elements of any magnitude (a: mag<=1, b: mag<=30)."""
        var na = self.negated(1)
        na.add_assign(other)
        return na.normalizes_to_zero()

    def cmp_var(self, other: Fe) -> Int:
        """Lexicographic compare of two *normalized* elements."""
        var a: InlineArray[UInt64, 5] = [
            self.n0,
            self.n1,
            self.n2,
            self.n3,
            self.n4,
        ]
        var b: InlineArray[UInt64, 5] = [
            other.n0,
            other.n1,
            other.n2,
            other.n3,
            other.n4,
        ]
        for i in range(4, -1, -1):
            if a[i] > b[i]:
                return 1
            if a[i] < b[i]:
                return -1
        return 0

    # ------------------------------------------------------------- arithmetic

    @always_inline
    def add_assign(mut self, other: Fe):
        self.n0 += other.n0
        self.n1 += other.n1
        self.n2 += other.n2
        self.n3 += other.n3
        self.n4 += other.n4

    def add_int(mut self, v: UInt64):
        self.n0 += v

    def __add__(self, other: Fe) -> Fe:
        var r = self
        r.add_assign(other)
        return r

    @always_inline
    def negated(self, magnitude: UInt64) -> Fe:
        """Negate an element whose magnitude is at most `magnitude`."""
        var m2 = 2 * (magnitude + 1)
        return Fe.from_limbs(
            P0 * m2 - self.n0,
            M52 * m2 - self.n1,
            M52 * m2 - self.n2,
            M52 * m2 - self.n3,
            M48 * m2 - self.n4,
        )

    def mul_int(mut self, v: UInt64):
        self.n0 *= v
        self.n1 *= v
        self.n2 *= v
        self.n3 *= v
        self.n4 *= v

    def half(mut self):
        var t0 = self.n0
        var t1 = self.n1
        var t2 = self.n2
        var t3 = self.n3
        var t4 = self.n4
        # mask is all-ones (shifted) when the value is odd, so p is added first
        var mask = (UInt64(0) - (t0 & 1)) >> 12

        t0 += P0 & mask
        t1 += mask
        t2 += mask
        t3 += mask
        t4 += mask >> 4

        self.n0 = (t0 >> 1) + ((t1 & 1) << 51)
        self.n1 = (t1 >> 1) + ((t2 & 1) << 51)
        self.n2 = (t2 >> 1) + ((t3 & 1) << 51)
        self.n3 = (t3 >> 1) + ((t4 & 1) << 51)
        self.n4 = t4 >> 1

    @always_inline
    def __mul__(self, b: Fe) -> Fe:
        return _mul_inner(self, b)

    @always_inline
    def sqr(self) -> Fe:
        return _sqr_inner(self)

    def clear(mut self):
        """Wipe the value; see `scrub.mojo`."""
        scrub_u64(self.n0)
        scrub_u64(self.n1)
        scrub_u64(self.n2)
        scrub_u64(self.n3)
        scrub_u64(self.n4)

    def cmov(mut self, a: Fe, flag: Bool):
        """Constant-time conditional move: self = a when flag."""
        var mask1 = UInt64(0) - UInt64(flag)
        var mask0 = ~mask1
        self.n0 = (self.n0 & mask0) | (a.n0 & mask1)
        self.n1 = (self.n1 & mask0) | (a.n1 & mask1)
        self.n2 = (self.n2 & mask0) | (a.n2 & mask1)
        self.n3 = (self.n3 & mask0) | (a.n3 & mask1)
        self.n4 = (self.n4 & mask0) | (a.n4 & mask1)

    # -------------------------------------------------- inversion / sqrt

    def inv(self) -> Fe:
        """Constant-time modular inverse. The inverse of zero is zero."""
        return _from_signed62(
            modinv(_to_signed62(self.normalized()), ModInfo.field())
        )

    def inv_var(self) -> Fe:
        """Variable-time modular inverse — only for public values."""
        return _from_signed62(
            modinv_var(_to_signed62(self.normalized()), ModInfo.field())
        )

    def inv_pow(self) -> Fe:
        """Inverse via the a^(p-2) addition chain. Kept as an independent
        implementation to cross-check `inv` in the tests."""
        return _fe_inv_chain(self)

    def sqrt(self) -> Tuple[Fe, Bool]:
        """Square root via a^((p+1)/4); Bool reports whether a is a square."""
        return _fe_sqrt_chain(self)

    def is_square_var(self) -> Bool:
        var t = self.sqrt()
        return t[1]


def _push_be64(mut out: List[UInt8], v: UInt64):
    for i in range(8):
        out.append(UInt8((v >> UInt64(56 - 8 * i)) & 0xFF))


@always_inline
def _lo(c: UInt128) -> UInt64:
    return UInt64(c & UInt128(0xFFFFFFFFFFFFFFFF))


@always_inline
def _mul_inner(a: Fe, b: Fe) -> Fe:
    var a0 = a.n0
    var a1 = a.n1
    var a2 = a.n2
    var a3 = a.n3
    var a4 = a.n4
    var b0 = b.n0
    var b1 = b.n1
    var b2 = b.n2
    var b3 = b.n3
    var b4 = b.n4

    var d = UInt128(a0) * UInt128(b3)
    d += UInt128(a1) * UInt128(b2)
    d += UInt128(a2) * UInt128(b1)
    d += UInt128(a3) * UInt128(b0)
    var c = UInt128(a4) * UInt128(b4)
    d += UInt128(R) * UInt128(_lo(c))
    c >>= 64
    var t3 = _lo(d) & M52
    d >>= 52

    d += UInt128(a0) * UInt128(b4)
    d += UInt128(a1) * UInt128(b3)
    d += UInt128(a2) * UInt128(b2)
    d += UInt128(a3) * UInt128(b1)
    d += UInt128(a4) * UInt128(b0)
    d += UInt128(R << 12) * UInt128(_lo(c))
    var t4 = _lo(d) & M52
    d >>= 52
    var tx = t4 >> 48
    t4 &= M52 >> 4

    c = UInt128(a0) * UInt128(b0)
    d += UInt128(a1) * UInt128(b4)
    d += UInt128(a2) * UInt128(b3)
    d += UInt128(a3) * UInt128(b2)
    d += UInt128(a4) * UInt128(b1)
    var u0 = _lo(d) & M52
    d >>= 52
    u0 = (u0 << 4) | tx
    c += UInt128(u0) * UInt128(R >> 4)
    var r0 = _lo(c) & M52
    c >>= 52

    c += UInt128(a0) * UInt128(b1)
    c += UInt128(a1) * UInt128(b0)
    d += UInt128(a2) * UInt128(b4)
    d += UInt128(a3) * UInt128(b3)
    d += UInt128(a4) * UInt128(b2)
    c += UInt128(_lo(d) & M52) * UInt128(R)
    d >>= 52
    var r1 = _lo(c) & M52
    c >>= 52

    c += UInt128(a0) * UInt128(b2)
    c += UInt128(a1) * UInt128(b1)
    c += UInt128(a2) * UInt128(b0)
    d += UInt128(a3) * UInt128(b4)
    d += UInt128(a4) * UInt128(b3)
    c += UInt128(R) * UInt128(_lo(d))
    d >>= 64
    var r2 = _lo(c) & M52
    c >>= 52

    c += UInt128(R << 12) * UInt128(_lo(d))
    c += UInt128(t3)
    var r3 = _lo(c) & M52
    c >>= 52
    var r4 = _lo(c) + t4

    return Fe.from_limbs(r0, r1, r2, r3, r4)


@always_inline
def _sqr_inner(a: Fe) -> Fe:
    var a0 = a.n0
    var a1 = a.n1
    var a2 = a.n2
    var a3 = a.n3
    var a4 = a.n4

    var d = UInt128(a0 * 2) * UInt128(a3)
    d += UInt128(a1 * 2) * UInt128(a2)
    var c = UInt128(a4) * UInt128(a4)
    d += UInt128(R) * UInt128(_lo(c))
    c >>= 64
    var t3 = _lo(d) & M52
    d >>= 52

    a4 *= 2
    d += UInt128(a0) * UInt128(a4)
    d += UInt128(a1 * 2) * UInt128(a3)
    d += UInt128(a2) * UInt128(a2)
    d += UInt128(R << 12) * UInt128(_lo(c))
    var t4 = _lo(d) & M52
    d >>= 52
    var tx = t4 >> 48
    t4 &= M52 >> 4

    c = UInt128(a0) * UInt128(a0)
    d += UInt128(a1) * UInt128(a4)
    d += UInt128(a2 * 2) * UInt128(a3)
    var u0 = _lo(d) & M52
    d >>= 52
    u0 = (u0 << 4) | tx
    c += UInt128(u0) * UInt128(R >> 4)
    var r0 = _lo(c) & M52
    c >>= 52

    a0 *= 2
    c += UInt128(a0) * UInt128(a1)
    d += UInt128(a2) * UInt128(a4)
    d += UInt128(a3) * UInt128(a3)
    c += UInt128(_lo(d) & M52) * UInt128(R)
    d >>= 52
    var r1 = _lo(c) & M52
    c >>= 52

    c += UInt128(a0) * UInt128(a2)
    c += UInt128(a1) * UInt128(a1)
    d += UInt128(a3) * UInt128(a4)
    c += UInt128(R) * UInt128(_lo(d))
    d >>= 64
    var r2 = _lo(c) & M52
    c >>= 52

    c += UInt128(R << 12) * UInt128(_lo(d))
    c += UInt128(t3)
    var r3 = _lo(c) & M52
    c >>= 52
    var r4 = _lo(c) + t4

    return Fe.from_limbs(r0, r1, r2, r3, r4)


def _sqr_n(a: Fe, times: Int) -> Fe:
    var r = a
    for _ in range(times):
        r = r.sqr()
    return r


def _pow_blocks(a: Fe) -> Tuple[Fe, Fe, Fe]:
    """Shared prefix of the inv/sqrt addition chains.

    Returns (x2, x22, x223) where xN == a^(2^N - 1). The binary expansion of
    both p-2 and (p+1)/4 is made of runs of ones with lengths in {2, 22, 223}.
    """
    var x2 = a.sqr() * a
    var x3 = x2.sqr() * a
    var x6 = _sqr_n(x3, 3) * x3
    var x9 = _sqr_n(x6, 3) * x3
    var x11 = _sqr_n(x9, 2) * x2
    var x22 = _sqr_n(x11, 11) * x11
    var x44 = _sqr_n(x22, 22) * x22
    var x88 = _sqr_n(x44, 44) * x44
    var x176 = _sqr_n(x88, 88) * x88
    var x220 = _sqr_n(x176, 44) * x44
    var x223 = _sqr_n(x220, 3) * x3
    return (x2, x22, x223)


def _fe_sqrt_chain(a: Fe) -> Tuple[Fe, Bool]:
    var blocks = _pow_blocks(a)
    var t1 = _sqr_n(blocks[2], 23) * blocks[1]
    t1 = _sqr_n(t1, 6) * blocks[0]
    t1 = _sqr_n(t1, 2)
    var check = t1.sqr()
    return (t1, check.equal(a))


def _fe_inv_chain(a: Fe) -> Fe:
    var blocks = _pow_blocks(a)
    var t1 = _sqr_n(blocks[2], 23) * blocks[1]
    t1 = _sqr_n(t1, 5) * a
    t1 = _sqr_n(t1, 3) * blocks[0]
    t1 = _sqr_n(t1, 2) * a
    return t1


def _to_signed62(a: Fe) -> Signed62:
    """A normalized field element as five signed 62-bit limbs."""
    var m = Int64(0xFFFFFFFFFFFFFFFF >> 2)
    return Signed62.of(
        Int64(a.n0 | (a.n1 << 52)) & m,
        Int64((a.n1 >> 10) | (a.n2 << 42)) & m,
        Int64((a.n2 >> 20) | (a.n3 << 32)) & m,
        Int64((a.n3 >> 30) | (a.n4 << 22)) & m,
        Int64(a.n4 >> 40),
    )


def _from_signed62(a: Signed62) -> Fe:
    var a0 = UInt64(a.v[0])
    var a1 = UInt64(a.v[1])
    var a2 = UInt64(a.v[2])
    var a3 = UInt64(a.v[3])
    var a4 = UInt64(a.v[4])
    return Fe.from_limbs(
        a0 & M52,
        ((a0 >> 52) | (a1 << 10)) & M52,
        ((a1 >> 42) | (a2 << 20)) & M52,
        ((a2 >> 32) | (a3 << 30)) & M52,
        (a3 >> 22) | (a4 << 40),
    )
