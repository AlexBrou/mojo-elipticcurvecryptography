"""GPU-compatible arithmetic using 32-bit limbs.

Metal's compiler rejects 128-bit integers, so the CPU implementation's 5x52
representation (which needs 64x64->128 products) cannot run on Apple GPUs. This
module mirrors it with eight 32-bit limbs and 64-bit accumulators, which Metal
handles natively.

Two further differences from the CPU code, both deliberate:

* Field elements are always kept **canonical** (fully reduced). That costs a
  conditional subtraction per addition but removes all magnitude bookkeeping,
  which matters when the code has to be obviously correct inside a kernel.
* The routines here are **variable time**. They are meant for batch work on
  public data — verifying signatures, deriving keys for scanning — not for
  operating on secrets. Use the CPU implementation for anything secret.

Everything is register/stack only: no heap, no raising, no `List`.
"""

# p = 2^256 - 2^32 - 977, little-endian 32-bit limbs
comptime P0: UInt32 = 0xFFFFFC2F
comptime P1: UInt32 = 0xFFFFFFFE

# 2^256 mod p
comptime RED_LOW: UInt64 = 977


@always_inline
def _lo32(v: UInt64) -> UInt32:
    return UInt32(v & 0xFFFFFFFF)


struct FeGpu(Copyable, ImplicitlyCopyable, Movable):
    """A canonical field element: eight 32-bit limbs, least significant first.
    """

    var n: Array[UInt32, 8]

    def __init__(out self, var n: Array[UInt32, 8]):
        self.n = n^

    def __init__(out self, *, copy: Self):
        self.n = copy.n.copy()

    def __init__(out self, *, deinit move: Self):
        self.n = move.n^

    @staticmethod
    def zero() -> FeGpu:
        return FeGpu(Array[UInt32, 8](fill=0))

    @staticmethod
    def one() -> FeGpu:
        var a = Array[UInt32, 8](fill=0)
        a[0] = 1
        return FeGpu(a^)

    @staticmethod
    def from_int(v: UInt32) -> FeGpu:
        var a = Array[UInt32, 8](fill=0)
        a[0] = v
        return FeGpu(a^)

    @staticmethod
    def modulus() -> FeGpu:
        var a = Array[UInt32, 8](fill=0xFFFFFFFF)
        a[0] = P0
        a[1] = P1
        return FeGpu(a^)

    @staticmethod
    def from_bytes(b: Array[UInt8, 32]) -> FeGpu:
        """Parse 32 big-endian bytes, reducing if the value is >= p."""
        var a = Array[UInt32, 8](fill=0)
        for i in range(8):
            var base = 28 - 4 * i
            a[i] = (
                (UInt32(b[base]) << 24)
                | (UInt32(b[base + 1]) << 16)
                | (UInt32(b[base + 2]) << 8)
                | UInt32(b[base + 3])
            )
        var r = FeGpu(a^)
        return _cond_sub_p(_cond_sub_p(r))

    def to_bytes(self) -> Array[UInt8, 32]:
        var out = Array[UInt8, 32](fill=0)
        for i in range(8):
            var base = 28 - 4 * i
            out[base] = UInt8(self.n[i] >> 24)
            out[base + 1] = UInt8((self.n[i] >> 16) & 0xFF)
            out[base + 2] = UInt8((self.n[i] >> 8) & 0xFF)
            out[base + 3] = UInt8(self.n[i] & 0xFF)
        return out^

    def is_zero(self) -> Bool:
        var acc = UInt32(0)
        for i in range(8):
            acc |= self.n[i]
        return acc == 0

    def is_odd(self) -> Bool:
        return (self.n[0] & 1) != 0

    def eq(self, b: FeGpu) -> Bool:
        var acc = UInt32(0)
        for i in range(8):
            acc |= self.n[i] ^ b.n[i]
        return acc == 0

    def cmp(self, b: FeGpu) -> Int:
        for i in range(7, -1, -1):
            if self.n[i] > b.n[i]:
                return 1
            if self.n[i] < b.n[i]:
                return -1
        return 0

    # ------------------------------------------------------------- arithmetic

    def __add__(self, b: FeGpu) -> FeGpu:
        var r = Array[UInt32, 8](fill=0)
        var carry = UInt64(0)
        for i in range(8):
            var v = UInt64(self.n[i]) + UInt64(b.n[i]) + carry
            r[i] = _lo32(v)
            carry = v >> 32
        var s = FeGpu(r^)
        # a, b < p so the sum is < 2p: one conditional subtraction suffices,
        # but the carry out of 2^256 has to be folded in first.
        if carry != 0:
            s = _add_small(s, RED_LOW)
            s = _add_at_limb(s, 1, 1)
        return _cond_sub_p(s)

    def __sub__(self, b: FeGpu) -> FeGpu:
        var r = Array[UInt32, 8](fill=0)
        var borrow = Int64(0)
        for i in range(8):
            var v = Int64(self.n[i]) - Int64(b.n[i]) - borrow
            r[i] = UInt32(UInt64(v) & 0xFFFFFFFF)
            borrow = 1 if v < 0 else 0
        var s = FeGpu(r^)
        if borrow != 0:
            s = _add_modulus(s)
        return s

    def neg(self) -> FeGpu:
        if self.is_zero():
            return FeGpu.zero()
        return FeGpu.modulus() - self

    def half(self) -> FeGpu:
        """Divide by two mod p: add p first when odd, then shift."""
        var t = self
        var carry = UInt32(0)
        if t.is_odd():
            var r = Array[UInt32, 8](fill=0)
            var c = UInt64(0)
            var m = FeGpu.modulus()
            for i in range(8):
                var v = UInt64(t.n[i]) + UInt64(m.n[i]) + c
                r[i] = _lo32(v)
                c = v >> 32
            t = FeGpu(r^)
            carry = UInt32(c)
        var out = Array[UInt32, 8](fill=0)
        for i in range(7):
            out[i] = (t.n[i] >> 1) | (t.n[i + 1] << 31)
        out[7] = (t.n[7] >> 1) | (carry << 31)
        return FeGpu(out^)

    def mul_int(self, k: UInt32) -> FeGpu:
        var l = Array[UInt32, 16](fill=0)
        var carry = UInt64(0)
        for i in range(8):
            var v = UInt64(self.n[i]) * UInt64(k) + carry
            l[i] = _lo32(v)
            carry = v >> 32
        l[8] = _lo32(carry)
        return _reduce512(l)

    def __mul__(self, b: FeGpu) -> FeGpu:
        var l = Array[UInt32, 16](fill=0)
        for i in range(8):
            var carry = UInt64(0)
            for j in range(8):
                var v = (
                    UInt64(self.n[i]) * UInt64(b.n[j])
                    + UInt64(l[i + j])
                    + carry
                )
                l[i + j] = _lo32(v)
                carry = v >> 32
            l[i + 8] = _lo32(carry)
        return _reduce512(l)

    def sqr(self) -> FeGpu:
        return self * self

    def inv(self) -> FeGpu:
        """Inverse via the a^(p-2) addition chain (no safegcd on the GPU)."""
        return _fe_inv(self)

    def sqrt(self) -> Tuple[FeGpu, Bool]:
        var r = _fe_sqrt(self)
        return (r, r.sqr().eq(self))


@always_inline
def _add_small(a: FeGpu, v: UInt64) -> FeGpu:
    var r = a
    var carry = v
    var i = 0
    while i < 8 and carry != 0:
        var t = UInt64(r.n[i]) + (carry & 0xFFFFFFFF)
        r.n[i] = _lo32(t)
        carry = (carry >> 32) + (t >> 32)
        i += 1
    return r


@always_inline
def _add_at_limb(a: FeGpu, pos: Int, v: UInt32) -> FeGpu:
    var r = a
    var carry = UInt64(v)
    var i = pos
    while i < 8 and carry != 0:
        var t = UInt64(r.n[i]) + carry
        r.n[i] = _lo32(t)
        carry = t >> 32
        i += 1
    return r


@always_inline
def _add_modulus(a: FeGpu) -> FeGpu:
    var m = FeGpu.modulus()
    var r = Array[UInt32, 8](fill=0)
    var carry = UInt64(0)
    for i in range(8):
        var v = UInt64(a.n[i]) + UInt64(m.n[i]) + carry
        r[i] = _lo32(v)
        carry = v >> 32
    return FeGpu(r^)


@always_inline
def _cond_sub_p(a: FeGpu) -> FeGpu:
    """Subtract p when a >= p, otherwise return a unchanged."""
    var m = FeGpu.modulus()
    var r = Array[UInt32, 8](fill=0)
    var borrow = Int64(0)
    for i in range(8):
        var v = Int64(a.n[i]) - Int64(m.n[i]) - borrow
        r[i] = UInt32(UInt64(v) & 0xFFFFFFFF)
        borrow = 1 if v < 0 else 0
    if borrow != 0:
        return a
    return FeGpu(r^)


@always_inline
def _acc_add(mut r: Array[UInt32, 10], pos: Int, value: UInt64):
    """Add `value` (a full 64-bit quantity) at limb `pos`, propagating carries.
    """
    var carry = value
    var j = pos
    while j < 10 and carry != 0:
        var v = UInt64(r[j]) + (carry & 0xFFFFFFFF)
        r[j] = _lo32(v)
        carry = (carry >> 32) + (v >> 32)
        j += 1


def _reduce512(l: Array[UInt32, 16]) -> FeGpu:
    """Reduce a 512-bit value modulo p.

    Uses 2^256 == 2^32 + 977 (mod p), folding the high half down repeatedly
    until nothing is left above limb 7, then subtracting p at most twice.
    """
    var r = Array[UInt32, 10](fill=0)
    for i in range(8):
        r[i] = l[i]

    # r += high * (2^32 + 977)
    for j in range(8):
        _acc_add(r, j, UInt64(l[8 + j]) * RED_LOW)
        _acc_add(r, j + 1, UInt64(l[8 + j]))

    # Collapse anything that spilled above limb 7. Three passes is more than
    # enough: each one shrinks the overflow from ~2^33 to a couple of bits.
    for _ in range(3):
        var h = UInt64(r[8]) | (UInt64(r[9]) << 32)
        if h == 0:
            break
        r[8] = 0
        r[9] = 0
        _acc_add(r, 0, h * RED_LOW)
        _acc_add(r, 1, h)

    var out = Array[UInt32, 8](fill=0)
    for i in range(8):
        out[i] = r[i]
    var f = FeGpu(out^)
    return _cond_sub_p(_cond_sub_p(f))


def _sqr_n(a: FeGpu, times: Int) -> FeGpu:
    var r = a
    for _ in range(times):
        r = r.sqr()
    return r


def _pow_blocks(a: FeGpu) -> Tuple[FeGpu, FeGpu, FeGpu]:
    """(x2, x22, x223) where xN == a^(2^N - 1); shared by inv and sqrt."""
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


def _fe_inv(a: FeGpu) -> FeGpu:
    var b = _pow_blocks(a)
    var t = _sqr_n(b[2], 23) * b[1]
    t = _sqr_n(t, 5) * a
    t = _sqr_n(t, 3) * b[0]
    t = _sqr_n(t, 2) * a
    return t


def _fe_sqrt(a: FeGpu) -> FeGpu:
    var b = _pow_blocks(a)
    var t = _sqr_n(b[2], 23) * b[1]
    t = _sqr_n(t, 6) * b[0]
    return _sqr_n(t, 2)


# ---------------------------------------------------------------- group ops


@fieldwise_init
struct GeGpu(Copyable, ImplicitlyCopyable, Movable):
    """An affine point, or infinity."""

    var x: FeGpu
    var y: FeGpu
    var infinity: Bool

    @staticmethod
    def infinity_point() -> GeGpu:
        return GeGpu(FeGpu.zero(), FeGpu.zero(), True)

    def neg(self) -> GeGpu:
        return GeGpu(self.x, self.y.neg(), self.infinity)

    def is_valid(self) -> Bool:
        if self.infinity:
            return False
        return self.y.sqr().eq(self.x.sqr() * self.x + FeGpu.from_int(7))


@fieldwise_init
struct GejGpu(Copyable, ImplicitlyCopyable, Movable):
    """A Jacobian point: the affine point is (x/z^2, y/z^3)."""

    var x: FeGpu
    var y: FeGpu
    var z: FeGpu
    var infinity: Bool

    @staticmethod
    def infinity_point() -> GejGpu:
        return GejGpu(FeGpu.zero(), FeGpu.zero(), FeGpu.zero(), True)

    @staticmethod
    def from_ge(a: GeGpu) -> GejGpu:
        return GejGpu(a.x, a.y, FeGpu.one(), a.infinity)

    def neg(self) -> GejGpu:
        return GejGpu(self.x, self.y.neg(), self.z, self.infinity)

    def double(self) -> GejGpu:
        """3 mul, 4 sqr — the same formula as the CPU implementation."""
        if self.infinity:
            return GejGpu.infinity_point()
        var z = self.z * self.y
        var s = self.y.sqr()
        var l = (self.x.sqr()).mul_int(3).half()
        var t = (s.neg()) * self.x
        var x = l.sqr() + t + t
        var s2 = s.sqr()
        var t2 = t + x
        var y = (t2 * l + s2).neg()
        return GejGpu(x, y, z, False)

    def add_ge(self, b: GeGpu) -> GejGpu:
        """Mixed addition (variable time)."""
        if self.infinity:
            return GejGpu.from_ge(b)
        if b.infinity:
            return self

        var z12 = self.z.sqr()
        var u1 = self.x
        var u2 = b.x * z12
        var s1 = self.y
        var s2 = b.y * z12 * self.z
        var h = u2 - u1
        var i = s1 - s2

        if h.is_zero():
            if i.is_zero():
                return self.double()
            return GejGpu.infinity_point()

        var z = self.z * h
        var h2 = (h.sqr()).neg()
        var h3 = h2 * h
        var t = u1 * h2

        var x = i.sqr() + h3 + t + t
        var t2 = t + x
        var y = t2 * i + h3 * s1
        return GejGpu(x, y, z, False)

    def add(self, b: GejGpu) -> GejGpu:
        """Full Jacobian addition (variable time)."""
        if self.infinity:
            return b
        if b.infinity:
            return self

        var z22 = b.z.sqr()
        var z12 = self.z.sqr()
        var u1 = self.x * z22
        var u2 = b.x * z12
        var s1 = self.y * z22 * b.z
        var s2 = b.y * z12 * self.z
        var h = u2 - u1
        var i = s1 - s2

        if h.is_zero():
            if i.is_zero():
                return self.double()
            return GejGpu.infinity_point()

        var t = h * b.z
        var z = self.z * t
        var h2 = (h.sqr()).neg()
        var h3 = h2 * h
        var tt = u1 * h2

        var x = i.sqr() + h3 + tt + tt
        var t2 = tt + x
        var y = t2 * i + h3 * s1
        return GejGpu(x, y, z, False)

    def to_ge(self) -> GeGpu:
        """Affine form. Costs a field inversion — prefer batching on the host.
        """
        if self.infinity:
            return GeGpu.infinity_point()
        var zi = self.z.inv()
        var zi2 = zi.sqr()
        return GeGpu(self.x * zi2, self.y * zi2 * zi, False)

    def eq_x(self, x: FeGpu) -> Bool:
        """Whether the affine x coordinate equals `x`, without inverting z."""
        return (self.z.sqr() * x).eq(self.x)


# ----------------------------------------------------------- scalar bits


struct ScalarBits(Copyable, ImplicitlyCopyable, Movable):
    """A 256-bit scalar as eight 32-bit limbs — read-only bit access.

    Scalar arithmetic (multiplication, inversion) stays on the host; a kernel
    only ever needs to walk the bits of an already-computed scalar.
    """

    var d: Array[UInt32, 8]

    def __init__(out self, var d: Array[UInt32, 8]):
        self.d = d^

    def __init__(out self, *, copy: Self):
        self.d = copy.d.copy()

    def __init__(out self, *, deinit move: Self):
        self.d = move.d^

    def bits(self, offset: Int, count: Int) -> UInt32:
        """Read `count` bits (<= 32) at `offset`; reads past bit 255 give zero,
        so a windowed loop may run past the end of the scalar."""
        var limb = offset >> 5
        if limb >= 8:
            return 0
        var shift = offset & 31
        var mask = (UInt32(1) << UInt32(count)) - 1
        var lo = self.d[limb] >> UInt32(shift)
        if shift != 0 and limb + 1 < 8:
            lo |= self.d[limb + 1] << UInt32(32 - shift)
        return lo & mask

    def is_zero(self) -> Bool:
        var acc = UInt32(0)
        for i in range(8):
            acc |= self.d[i]
        return acc == 0


# ------------------------------------------------------- scalar multiplication

comptime GEN_WINDOW = 4
comptime GEN_ENTRIES = 16
comptime GEN_BLOCKS = 64
# Each table entry is an affine point stored as 16 uint32 limbs (x then y).
comptime GEN_ENTRY_WORDS = 16
comptime GEN_TABLE_WORDS = GEN_BLOCKS * GEN_ENTRIES * GEN_ENTRY_WORDS


@always_inline
def load_ge(table: Pointer[UInt32, MutAnyOrigin], index: Int) -> GeGpu:
    """Read affine point `index` out of a flat uint32 table."""
    var base = index * GEN_ENTRY_WORDS
    var x = Array[UInt32, 8](fill=0)
    var y = Array[UInt32, 8](fill=0)
    for i in range(8):
        x[i] = table[unsafe_offset=base + i]
        y[i] = table[unsafe_offset=base + 8 + i]
    return GeGpu(FeGpu(x^), FeGpu(y^), False)


def mul_gen(table: Pointer[UInt32, MutAnyOrigin], k: ScalarBits) -> GejGpu:
    """k*G from the precomputed comb table: 64 window lookups, no doublings.

    Variable time — digits equal to zero are skipped.
    """
    var acc = GejGpu.infinity_point()
    for b in range(GEN_BLOCKS):
        var digit = Int(k.bits(b * GEN_WINDOW, GEN_WINDOW))
        if digit != 0:
            acc = acc.add_ge(load_ge(table, b * GEN_ENTRIES + digit))
    return acc


# Point multiplication inside a kernel deliberately uses **no lookup table**.
# A windowed method needs a dynamically indexed array of points, which Metal
# places in per-thread memory rather than registers; measured on an M2, the
# resulting traffic costs more than the additions a window saves. Plain
# double-and-add over the two GLV halves keeps everything in registers.


@always_inline
def _beta() -> FeGpu:
    """The cube root of unity used by the endomorphism lambda*(x,y)=(beta*x,y).
    """
    var d: Array[UInt32, 8] = [
        0x719501EE,
        0xC1396C28,
        0x12F58995,
        0x9CF04975,
        0xAC3434E9,
        0x6E64479E,
        0x657C0710,
        0x7AE96A2B,
    ]
    return FeGpu(d^)


# A GLV half is at most ~129 bits.
comptime SPLIT_BITS = 130
comptime FULL_BITS = 256


def mul_point_split(
    p: GeGpu, k1: ScalarBits, k2: ScalarBits, neg1: Bool, neg2: Bool
) -> GejGpu:
    """k1*P + k2*lambda*P, where k1 and k2 are the GLV halves of a scalar.

    The host splits the scalar and passes the two ~128-bit halves with their
    signs, so this runs half the doublings a 256-bit ladder would, and both
    halves share the same chain.
    """
    if p.infinity or (k1.is_zero() and k2.is_zero()):
        return GejGpu.infinity_point()

    var p1 = p.neg() if neg1 else p
    var lam = GeGpu(p.x * _beta(), p.y, False)
    var p2 = lam.neg() if neg2 else lam

    var acc = GejGpu.infinity_point()
    for i in range(SPLIT_BITS - 1, -1, -1):
        acc = acc.double()
        if k1.bits(i, 1) != 0:
            acc = acc.add_ge(p1)
        if k2.bits(i, 1) != 0:
            acc = acc.add_ge(p2)
    return acc


def mul_point(p: GeGpu, k: ScalarBits) -> GejGpu:
    """k*P over a full 256-bit scalar, without a GLV split."""
    if p.infinity or k.is_zero():
        return GejGpu.infinity_point()

    var acc = GejGpu.infinity_point()
    for i in range(FULL_BITS - 1, -1, -1):
        acc = acc.double()
        if k.bits(i, 1) != 0:
            acc = acc.add_ge(p)
    return acc
