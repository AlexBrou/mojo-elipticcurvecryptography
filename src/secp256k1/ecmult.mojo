"""Scalar multiplication.

Three entry points:

* `EcmultGenContext.mult` — constant-time k*G using a precomputed comb table.
* `ecmult_const` — constant-time q*A for an arbitrary point A.
* `ecmult` — variable-time na*A + ng*G, for signature verification.

The variable-time path uses wNAF together with the GLV endomorphism, splitting
each 256-bit scalar into two ~128-bit halves.
"""

from .field import Fe
from .group import BETA, Ge, Gej, set_all_gej_var
from .scalar import Scalar

# --------------------------------------------------------------------- k*G

comptime GEN_WINDOW = 4
comptime GEN_ENTRIES = 1 << GEN_WINDOW  # 16
comptime GEN_BLOCKS = 256 // GEN_WINDOW  # 64


# Window for the variable-time table of odd multiples of G. The scalar is split
# by the endomorphism first, so each half is ~128 bits and needs 128/(W+1)
# additions; W=8 gives 128 table entries per half (about 20 KB total).
comptime G_WNAF_WINDOW = 8
comptime G_TABLE_SIZE = 1 << (G_WNAF_WINDOW - 2)


struct EcmultGenContext(Movable):
    """Precomputed multiples of G.

    Two tables are built:

    * `table` — `table[b * 16 + j] == j * 16^b * G`, scanned in constant time
      by `mult` for secret scalars (key generation, signing).
    * `g_odd` / `lam_g_odd` — odd multiples of G and of lambda*G, for the
      variable-time wNAF used when verifying, where the scalar is public.
    """

    var table: List[Ge]
    var g_odd: List[Ge]
    var lam_g_odd: List[Ge]

    def __init__(out self):
        var jac = List[Gej](capacity=GEN_BLOCKS * GEN_ENTRIES)
        var base = Gej.from_ge(Ge.generator())
        for _ in range(GEN_BLOCKS):
            # entries for this block: 0*base .. 15*base
            var acc = Gej.infinity_point()
            for _j in range(GEN_ENTRIES):
                jac.append(acc)
                acc = acc.add_var(base)
            # advance base by 2^GEN_WINDOW
            for _ in range(GEN_WINDOW):
                base = base.double()
        # one batch inversion for the whole table
        self.table = set_all_gej_var(jac)

        var g = Gej.from_ge(Ge.generator())
        self.g_odd = _odd_multiples(g, G_TABLE_SIZE)
        self.lam_g_odd = _odd_multiples(
            Gej.from_ge(Ge.generator().mul_lambda()), G_TABLE_SIZE
        )

    def mult(self, k: Scalar) -> Gej:
        """Constant-time k*G."""
        var acc = Gej.infinity_point()
        for b in range(GEN_BLOCKS):
            var digit = Int(k.get_bits(b * GEN_WINDOW, GEN_WINDOW))
            var sel = Ge.infinity_point()
            # constant-time table scan
            for j in range(GEN_ENTRIES):
                var e = self.table[b * GEN_ENTRIES + j]
                var hit = j == digit
                sel.x.cmov(e.x, hit)
                sel.y.cmov(e.y, hit)
            # digit 0 selects the infinity entry, which add_ge cannot consume;
            # add unconditionally and keep the old accumulator instead.
            var added = acc.add_ge(sel)
            acc = _gej_cmov(acc, added, digit != 0)
        return acc


def _gej_cmov(a: Gej, b: Gej, flag: Bool) -> Gej:
    var r = a
    r.x.cmov(b.x, flag)
    r.y.cmov(b.y, flag)
    r.z.cmov(b.z, flag)
    r.infinity = b.infinity if flag else a.infinity
    return r


# ------------------------------------------------------------ constant-time q*A

comptime CONST_WINDOW = 5
comptime CONST_MAX_DIGIT = 1 << (CONST_WINDOW - 1)  # 16
# digits of the signed recoding live in [-15, 16], so the table holds 1*A..16*A
comptime CONST_TABLE_SIZE = CONST_MAX_DIGIT


def _odd_multiples(a: Gej, count: Int) -> List[Ge]:
    """Affine odd multiples A, 3A, 5A, ... (2*count-1)A."""
    var jac = List[Gej](capacity=count)
    var d = a.double()
    var cur = a
    for _ in range(count):
        jac.append(cur)
        cur = cur.add_var(d)
    return set_all_gej_var(jac)


comptime WNAF_WINDOW_A = 5
comptime WNAF_TABLE_A = 1 << (WNAF_WINDOW_A - 1)  # 16 odd multiples


def _odd_multiples_fixed(a: Gej) -> InlineArray[Ge, WNAF_TABLE_A]:
    """The same table as `_odd_multiples`, on the stack.

    `ecmult` builds two of these per call, so keeping them out of the heap is
    worth the specialisation. The batch inversion is inlined for the same
    reason: one field inversion for the whole table, no temporaries.
    """
    var jac = InlineArray[Gej, WNAF_TABLE_A](fill=a)
    var d = a.double()
    var cur = a
    for i in range(WNAF_TABLE_A):
        jac[i] = cur
        cur = cur.add_var(d)

    # Montgomery's trick: prefix[i] is the product of z_0..z_{i-1}.
    var prefix = InlineArray[Fe, WNAF_TABLE_A](fill=Fe.from_int(1))
    var acc = Fe.from_int(1)
    for i in range(WNAF_TABLE_A):
        prefix[i] = acc
        acc = acc * jac[i].z

    var inv = acc.inv_var()
    var out = InlineArray[Ge, WNAF_TABLE_A](fill=Ge.infinity_point())
    for i in range(WNAF_TABLE_A - 1, -1, -1):
        var zinv = prefix[i] * inv
        inv = inv * jac[i].z
        var zi2 = zinv.sqr()
        out[i] = Ge(jac[i].x * zi2, jac[i].y * zi2 * zinv, False)
    return out^


def _all_multiples_fixed(a: Gej) -> InlineArray[Ge, CONST_TABLE_SIZE]:
    """Affine multiples A, 2A, ... 16*A, on the stack with one inversion."""
    var jac = InlineArray[Gej, CONST_TABLE_SIZE](fill=a)
    var cur = a
    for i in range(CONST_TABLE_SIZE):
        jac[i] = cur
        cur = cur.add_var(a)

    var prefix = InlineArray[Fe, CONST_TABLE_SIZE](fill=Fe.from_int(1))
    var acc = Fe.from_int(1)
    for i in range(CONST_TABLE_SIZE):
        prefix[i] = acc
        acc = acc * jac[i].z

    var inv = acc.inv()
    var out = InlineArray[Ge, CONST_TABLE_SIZE](fill=Ge.infinity_point())
    for i in range(CONST_TABLE_SIZE - 1, -1, -1):
        var zinv = prefix[i] * inv
        inv = inv * jac[i].z
        var zi2 = zinv.sqr()
        out[i] = Ge(jac[i].x * zi2, jac[i].y * zi2 * zinv, False)
    return out^


# 27 windows of 5 bits cover 135 bits: enough for a GLV half plus its carry.
comptime CONST_SPLIT_DIGITS = 27


def ecmult_const(a: Ge, q: Scalar) -> Gej:
    """Constant-time q*A.

    The scalar is split by the GLV endomorphism into two ~128-bit halves, so
    this runs 130 doublings rather than 265. Both halves read the same table:
    lambda*(x, y) == (beta*x, y), so the endomorphism costs one extra field
    multiplication per lookup instead of a second table.

    Digits land in [-15, 16] and a zero digit is discarded with a conditional
    move, so the control flow does not depend on the scalar.
    """
    if a.infinity or q.is_zero():
        return Gej.infinity_point()

    var table = _all_multiples_fixed(Gej.from_ge(a))

    var split = q.split_lambda()
    var neg1 = split[0].is_high()
    var neg2 = split[1].is_high()
    var s1 = split[0].cond_negate(neg1)
    var s2 = split[1].cond_negate(neg2)

    var d1 = InlineArray[Int, CONST_SPLIT_DIGITS](fill=0)
    var d2 = InlineArray[Int, CONST_SPLIT_DIGITS](fill=0)
    _recode_const(s1, d1)
    _recode_const(s2, d2)

    var acc = Gej.infinity_point()
    for i in range(CONST_SPLIT_DIGITS - 1, -1, -1):
        if i != CONST_SPLIT_DIGITS - 1:
            for _ in range(CONST_WINDOW):
                acc = acc.double()
        acc = _accumulate(acc, table, d1[i], False, neg1)
        acc = _accumulate(acc, table, d2[i], True, neg2)
    return acc


def _recode_const(s: Scalar, mut digits: InlineArray[Int, CONST_SPLIT_DIGITS]):
    """Signed 5-bit recoding of a GLV half; digits land in [-15, 16]."""
    var carry = 0
    for i in range(CONST_SPLIT_DIGITS):
        var d = Int(s.get_bits(i * CONST_WINDOW, CONST_WINDOW)) + carry
        if d > CONST_MAX_DIGIT:
            d -= 1 << CONST_WINDOW
            carry = 1
        else:
            carry = 0
        digits[i] = d


@always_inline
def _accumulate(
    acc: Gej,
    table: InlineArray[Ge, CONST_TABLE_SIZE],
    d: Int,
    twist: Bool,
    flip: Bool,
) -> Gej:
    """Add (+/-)|d|*A, optionally through the endomorphism, in constant time."""
    # abs(d) without a branch: mask is all-ones when d is negative
    var mask = d >> 63
    var mag = (d ^ mask) - mask
    var neg = mask != 0

    var sel = Ge.infinity_point()
    for j in range(CONST_TABLE_SIZE):
        var hit = (j + 1) == mag
        sel.x.cmov(table[j].x, hit)
        sel.y.cmov(table[j].y, hit)

    if twist:
        sel.x = sel.x * BETA
    var selneg = sel.neg()
    sel.x.cmov(selneg.x, neg != flip)
    sel.y.cmov(selneg.y, neg != flip)

    var added = acc.add_ge(sel)
    return _gej_cmov(acc, added, mag != 0)


# ------------------------------------------------- variable-time na*A + ng*G

comptime WNAF_BITS = 129


def _wnaf_into(
    a: Scalar, size: Int, w: Int, mut wnaf: InlineArray[Int32, WNAF_BITS]
) -> Int:
    """Width-w NAF of `a` over `size` bits, written into `wnaf`.

    Returns the number of digits actually used. Writing into a fixed stack
    array avoids the four heap allocations a per-call list would cost.
    """
    for i in range(size):
        wnaf[i] = 0

    var s = a
    var sign = 1
    if s.get_bits(255, 1) != 0:
        s = s.negated()
        sign = -1

    var last_set = -1
    var bit = 0
    var carry = 0
    while bit < size:
        if Int(s.get_bits(bit, 1)) == carry:
            bit += 1
            continue
        var now = w
        if now > size - bit:
            now = size - bit
        var word = Int(s.get_bits(bit, now)) + carry
        carry = (word >> (w - 1)) & 1
        word -= carry << w
        wnaf[bit] = Int32(sign * word)
        last_set = bit
        bit += now
    return last_set + 1


def ecmult(ctx: EcmultGenContext, a: Gej, na: Scalar, ng: Scalar) -> Gej:
    """Variable-time na*A + ng*G.

    Both scalars are split by the GLV endomorphism into ~128-bit halves, so all
    four wNAFs share one run of 129 doublings. Nothing on this path allocates.
    """
    var have_a = not (a.infinity or na.is_zero())
    var have_g = not ng.is_zero()
    if not have_a and not have_g:
        return Gej.infinity_point()

    var wa1 = InlineArray[Int32, WNAF_BITS](fill=0)
    var wa2 = InlineArray[Int32, WNAF_BITS](fill=0)
    var wg1 = InlineArray[Int32, WNAF_BITS](fill=0)
    var wg2 = InlineArray[Int32, WNAF_BITS](fill=0)
    var la1 = 0
    var la2 = 0
    var lg1 = 0
    var lg2 = 0

    var ta1 = InlineArray[Ge, WNAF_TABLE_A](fill=Ge.infinity_point())
    var ta2 = InlineArray[Ge, WNAF_TABLE_A](fill=Ge.infinity_point())

    if have_a:
        var split = na.split_lambda()
        var neg1 = split[0].is_high()
        var neg2 = split[1].is_high()
        la1 = _wnaf_into(
            split[0].cond_negate(neg1), WNAF_BITS, WNAF_WINDOW_A, wa1
        )
        la2 = _wnaf_into(
            split[1].cond_negate(neg2), WNAF_BITS, WNAF_WINDOW_A, wa2
        )
        var a1 = a.neg() if neg1 else a
        var a2j = Gej.from_ge(a.to_ge_var().mul_lambda())
        var a2 = a2j.neg() if neg2 else a2j
        ta1 = _odd_multiples_fixed(a1)
        ta2 = _odd_multiples_fixed(a2)

    var gneg1 = False
    var gneg2 = False
    if have_g:
        var split = ng.split_lambda()
        gneg1 = split[0].is_high()
        gneg2 = split[1].is_high()
        lg1 = _wnaf_into(
            split[0].cond_negate(gneg1), WNAF_BITS, G_WNAF_WINDOW, wg1
        )
        lg2 = _wnaf_into(
            split[1].cond_negate(gneg2), WNAF_BITS, G_WNAF_WINDOW, wg2
        )

    var size = la1
    if la2 > size:
        size = la2
    if lg1 > size:
        size = lg1
    if lg2 > size:
        size = lg2

    var r = Gej.infinity_point()
    for i in range(size - 1, -1, -1):
        r = r.double()
        if have_a:
            var d1 = Int(wa1[i])
            if d1 != 0:
                r = _add_signed_fixed(r, ta1, d1)
            var d2 = Int(wa2[i])
            if d2 != 0:
                r = _add_signed_fixed(r, ta2, d2)
        if have_g:
            var d1 = Int(wg1[i])
            if d1 != 0:
                r = _add_signed(r, ctx.g_odd, -d1 if gneg1 else d1)
            var d2 = Int(wg2[i])
            if d2 != 0:
                r = _add_signed(r, ctx.lam_g_odd, -d2 if gneg2 else d2)
    return r


def ecmult_var(a: Gej, na: Scalar) -> Gej:
    """Variable-time na*A using wNAF with the GLV endomorphism."""
    if a.infinity or na.is_zero():
        return Gej.infinity_point()

    var split = na.split_lambda()
    var neg1 = split[0].is_high()
    var neg2 = split[1].is_high()

    var a1 = a.neg() if neg1 else a
    var a2j = Gej.from_ge(a.to_ge_var().mul_lambda())
    var a2 = a2j.neg() if neg2 else a2j

    var w1 = InlineArray[Int32, WNAF_BITS](fill=0)
    var w2 = InlineArray[Int32, WNAF_BITS](fill=0)
    var l1 = _wnaf_into(
        split[0].cond_negate(neg1), WNAF_BITS, WNAF_WINDOW_A, w1
    )
    var l2 = _wnaf_into(
        split[1].cond_negate(neg2), WNAF_BITS, WNAF_WINDOW_A, w2
    )

    var t1 = _odd_multiples_fixed(a1)
    var t2 = _odd_multiples_fixed(a2)

    var size = l1
    if l2 > size:
        size = l2

    var r = Gej.infinity_point()
    for i in range(size - 1, -1, -1):
        r = r.double()
        var d1 = Int(w1[i])
        if d1 != 0:
            r = _add_signed_fixed(r, t1, d1)
        var d2 = Int(w2[i])
        if d2 != 0:
            r = _add_signed_fixed(r, t2, d2)
    return r


def _add_signed_fixed(
    r: Gej, table: InlineArray[Ge, WNAF_TABLE_A], d: Int
) -> Gej:
    if d > 0:
        return r.add_ge_var(table[(d - 1) // 2])
    return r.add_ge_var(table[(-d - 1) // 2].neg())


def _add_signed(r: Gej, table: List[Ge], d: Int) -> Gej:
    if d > 0:
        return r.add_ge_var(table[(d - 1) // 2])
    return r.add_ge_var(table[(-d - 1) // 2].neg())
