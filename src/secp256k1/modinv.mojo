"""Constant-time modular inversion via the safegcd algorithm.

A port of libsecp256k1's `modinv64`: numbers are held as five signed 62-bit
limbs, and each round applies 59 (constant-time) or up to 62 (variable-time)
"divsteps" to a 2x2 transition matrix. Both the field modulus p and the group
order n are handled by passing the matching `ModInfo`.
"""

from std.bit import count_trailing_zeros

comptime M62: UInt64 = 0xFFFFFFFFFFFFFFFF >> 2


@fieldwise_init
struct Signed62(Copyable, Movable):
    """A number as five signed 62-bit limbs, least significant first."""

    var v: InlineArray[Int64, 5]

    @staticmethod
    def zero() -> Signed62:
        return Signed62(InlineArray[Int64, 5](fill=0))

    @staticmethod
    def of(a: Int64, b: Int64, c: Int64, d: Int64, e: Int64) -> Signed62:
        var arr: InlineArray[Int64, 5] = [a, b, c, d, e]
        return Signed62(arr^)


@fieldwise_init
struct ModInfo(Copyable, Movable):
    var modulus: Signed62
    var modulus_inv62: UInt64

    @staticmethod
    def field() -> ModInfo:
        """p = 2^256 - 2^32 - 977."""
        return ModInfo(
            Signed62.of(-0x1000003D1, 0, 0, 0, 256), 0x27C7F6E22DDACACF
        )

    @staticmethod
    def scalar() -> ModInfo:
        """n, the order of the group."""
        return ModInfo(
            Signed62.of(0x3FD25E8CD0364141, 0x2ABB739ABD2280EE, -0x15, 0, 256),
            0x34F20099AA774EC1,
        )


@fieldwise_init
struct Trans2x2(Copyable, ImplicitlyCopyable, Movable):
    var u: Int64
    var v: Int64
    var q: Int64
    var r: Int64


@always_inline
def _lo64(c: Int128) -> UInt64:
    return UInt64(UInt128(c) & UInt128(0xFFFFFFFFFFFFFFFF))


@always_inline
def _i64(c: Int128) -> Int64:
    return Int64(_lo64(c))


def _divsteps_59(
    zeta_in: Int64, f0: UInt64, g0: UInt64
) -> Tuple[Int64, Trans2x2]:
    """59 divsteps in constant time, tracking the 2x2 transition matrix.

    u/v/q/r start at 8 rather than 1 because the first three iterations are
    known in advance and folded into the initial value.
    """
    var zeta = zeta_in
    var u = UInt64(8)
    var v = UInt64(0)
    var q = UInt64(0)
    var r = UInt64(8)
    var f = f0
    var g = g0

    for _ in range(3, 62):
        var mask1 = UInt64(zeta >> 63)
        var mask2 = UInt64(0) - (g & 1)
        var x = (f ^ mask1) - mask1
        var y = (u ^ mask1) - mask1
        var z = (v ^ mask1) - mask1
        g += x & mask2
        q += y & mask2
        r += z & mask2
        mask1 &= mask2
        zeta = Int64(UInt64(zeta) ^ mask1) - 1
        f += g & mask1
        u += q & mask1
        v += r & mask1
        g >>= 1
        u <<= 1
        v <<= 1

    return (zeta, Trans2x2(Int64(u), Int64(v), Int64(q), Int64(r)))


# Inlined, but note the shared `_update_de_62` / `_update_fg_62` /
# `_normalize_62` below deliberately are not: inlining those as well made the
# variable-time path slightly faster again but cost the constant-time one 50%
# (1.72 -> 2.63 us), which signing pays on every call.
@always_inline
def _divsteps_62_var(
    eta_in: Int64, f0: UInt64, g0: UInt64
) -> Tuple[Int64, Trans2x2]:
    """Up to 62 divsteps, skipping trailing zeros of g — variable time."""
    var eta = eta_in
    var u = UInt64(1)
    var v = UInt64(0)
    var q = UInt64(0)
    var r = UInt64(1)
    var f = f0
    var g = g0
    var i = 62

    while True:
        var zeros = Int(
            count_trailing_zeros(g | (UInt64(0xFFFFFFFFFFFFFFFF) << UInt64(i)))
        )
        g >>= UInt64(zeros)
        u <<= UInt64(zeros)
        v <<= UInt64(zeros)
        eta -= Int64(zeros)
        i -= zeros
        if i == 0:
            break

        var m: UInt64
        var w: UInt64
        if eta < 0:
            eta = -eta
            var tmp = f
            f = g
            g = UInt64(0) - tmp
            tmp = u
            u = q
            q = UInt64(0) - tmp
            tmp = v
            v = r
            r = UInt64(0) - tmp
            var limit = i if Int(eta) + 1 > i else Int(eta) + 1
            m = (UInt64(0xFFFFFFFFFFFFFFFF) >> UInt64(64 - limit)) & 63
            w = (f * g * (f * f - 2)) & m
        else:
            var limit = i if Int(eta) + 1 > i else Int(eta) + 1
            m = (UInt64(0xFFFFFFFFFFFFFFFF) >> UInt64(64 - limit)) & 15
            var t = f + (((f + 1) & 4) << 1)
            w = ((UInt64(0) - t) * g) & m

        g += f * w
        q += u * w
        r += v * w

    return (eta, Trans2x2(Int64(u), Int64(v), Int64(q), Int64(r)))


def _update_de_62(
    d_in: Signed62, e_in: Signed62, t: Trans2x2, mi: ModInfo
) -> Tuple[Signed62, Signed62]:
    """Apply the transition to (d, e), keeping both reduced modulo the modulus.
    """
    var d = d_in.copy()
    var e = e_in.copy()
    var u = t.u
    var v = t.v
    var q = t.q
    var r = t.r

    var sd = d.v[4] >> 63
    var se = e.v[4] >> 63
    var md = (u & sd) + (v & se)
    var me = (q & sd) + (r & se)

    var cd = Int128(u) * Int128(d.v[0]) + Int128(v) * Int128(e.v[0])
    var ce = Int128(q) * Int128(d.v[0]) + Int128(r) * Int128(e.v[0])

    md -= Int64((mi.modulus_inv62 * _lo64(cd) + UInt64(md)) & M62)
    me -= Int64((mi.modulus_inv62 * _lo64(ce) + UInt64(me)) & M62)

    cd += Int128(mi.modulus.v[0]) * Int128(md)
    ce += Int128(mi.modulus.v[0]) * Int128(me)
    # md/me were chosen so the bottom 62 bits cancel; drop them.
    cd >>= 62
    ce >>= 62

    var out_d = Signed62.zero()
    var out_e = Signed62.zero()

    for i in range(1, 5):
        cd += Int128(u) * Int128(d.v[i]) + Int128(v) * Int128(e.v[i])
        ce += Int128(q) * Int128(d.v[i]) + Int128(r) * Int128(e.v[i])
        cd += Int128(mi.modulus.v[i]) * Int128(md)
        ce += Int128(mi.modulus.v[i]) * Int128(me)
        out_d.v[i - 1] = Int64(_lo64(cd) & M62)
        out_e.v[i - 1] = Int64(_lo64(ce) & M62)
        cd >>= 62
        ce >>= 62

    out_d.v[4] = _i64(cd)
    out_e.v[4] = _i64(ce)
    return (out_d^, out_e^)


def _update_fg_62(
    f_in: Signed62, g_in: Signed62, t: Trans2x2, length: Int
) -> Tuple[Signed62, Signed62]:
    """Apply the transition to (f, g) over the first `length` limbs."""
    var f = f_in.copy()
    var g = g_in.copy()
    var u = t.u
    var v = t.v
    var q = t.q
    var r = t.r

    var cf = Int128(u) * Int128(f.v[0]) + Int128(v) * Int128(g.v[0])
    var cg = Int128(q) * Int128(f.v[0]) + Int128(r) * Int128(g.v[0])
    # The bottom 62 bits are zero by construction of the divsteps.
    cf >>= 62
    cg >>= 62

    var out_f = f.copy()
    var out_g = g.copy()
    for i in range(1, length):
        cf += Int128(u) * Int128(f.v[i]) + Int128(v) * Int128(g.v[i])
        cg += Int128(q) * Int128(f.v[i]) + Int128(r) * Int128(g.v[i])
        out_f.v[i - 1] = Int64(_lo64(cf) & M62)
        out_g.v[i - 1] = Int64(_lo64(cg) & M62)
        cf >>= 62
        cg >>= 62

    out_f.v[length - 1] = _i64(cf)
    out_g.v[length - 1] = _i64(cg)
    return (out_f^, out_g^)


def _normalize_62(r_in: Signed62, sign: Int64, mi: ModInfo) -> Signed62:
    """Bring the result into [0, modulus), negating first when `sign` is negative.
    """
    var m = Int64(M62)
    var r0 = r_in.v[0]
    var r1 = r_in.v[1]
    var r2 = r_in.v[2]
    var r3 = r_in.v[3]
    var r4 = r_in.v[4]

    var cond_add = r4 >> 63
    r0 += mi.modulus.v[0] & cond_add
    r1 += mi.modulus.v[1] & cond_add
    r2 += mi.modulus.v[2] & cond_add
    r3 += mi.modulus.v[3] & cond_add
    r4 += mi.modulus.v[4] & cond_add

    var cond_negate = sign >> 63
    r0 = (r0 ^ cond_negate) - cond_negate
    r1 = (r1 ^ cond_negate) - cond_negate
    r2 = (r2 ^ cond_negate) - cond_negate
    r3 = (r3 ^ cond_negate) - cond_negate
    r4 = (r4 ^ cond_negate) - cond_negate

    r1 += r0 >> 62
    r0 &= m
    r2 += r1 >> 62
    r1 &= m
    r3 += r2 >> 62
    r2 &= m
    r4 += r3 >> 62
    r3 &= m

    cond_add = r4 >> 63
    r0 += mi.modulus.v[0] & cond_add
    r1 += mi.modulus.v[1] & cond_add
    r2 += mi.modulus.v[2] & cond_add
    r3 += mi.modulus.v[3] & cond_add
    r4 += mi.modulus.v[4] & cond_add

    r1 += r0 >> 62
    r0 &= m
    r2 += r1 >> 62
    r1 &= m
    r3 += r2 >> 62
    r2 &= m
    r4 += r3 >> 62
    r3 &= m

    return Signed62.of(r0, r1, r2, r3, r4)


def modinv(x: Signed62, mi: ModInfo) -> Signed62:
    """Constant-time modular inverse. The inverse of zero is zero."""
    var d = Signed62.zero()
    var e = Signed62.of(1, 0, 0, 0, 0)
    var f = mi.modulus.copy()
    var g = x.copy()
    var zeta = Int64(-1)

    for _ in range(10):
        var step = _divsteps_59(zeta, UInt64(f.v[0]), UInt64(g.v[0]))
        zeta = step[0]
        var de = _update_de_62(d, e, step[1], mi)
        d = de[0].copy()
        e = de[1].copy()
        var fg = _update_fg_62(f, g, step[1], 5)
        f = fg[0].copy()
        g = fg[1].copy()

    return _normalize_62(d, f.v[4], mi)


@always_inline
def modinv_var(x: Signed62, mi: ModInfo) -> Signed62:
    """Variable-time modular inverse — faster, but the running time depends on
    the input, so use it only on public values."""
    var d = Signed62.zero()
    var e = Signed62.of(1, 0, 0, 0, 0)
    var f = mi.modulus.copy()
    var g = x.copy()
    var eta = Int64(-1)
    var length = 5

    while True:
        var step = _divsteps_62_var(eta, UInt64(f.v[0]), UInt64(g.v[0]))
        eta = step[0]
        var de = _update_de_62(d, e, step[1], mi)
        d = de[0].copy()
        e = de[1].copy()
        var fg = _update_fg_62(f, g, step[1], length)
        f = fg[0].copy()
        g = fg[1].copy()

        if g.v[0] == 0:
            var cond = Int64(0)
            for j in range(1, length):
                cond |= g.v[j]
            if cond == 0:
                break

        var f_top = f.v[length - 1]
        var g_top = g.v[length - 1]
        var shrink = Int64(length - 2) >> 63
        shrink |= f_top ^ (f_top >> 63)
        shrink |= g_top ^ (g_top >> 63)
        if shrink == 0:
            f.v[length - 2] |= Int64(UInt64(f_top) << 62)
            g.v[length - 2] |= Int64(UInt64(g_top) << 62)
            length -= 1

    return _normalize_62(d, f.v[length - 1], mi)
