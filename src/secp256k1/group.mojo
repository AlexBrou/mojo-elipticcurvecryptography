"""Group operations on the secp256k1 curve y^2 = x^3 + 7.

`Ge` is an affine point, `Gej` a Jacobian point (x/z^2, y/z^3). The formulas
are ports of libsecp256k1's `group_impl.h`; the magnitude comments in that file
carry over and explain the `negated(m)` arguments.
"""

from .field import Fe

comptime CURVE_B: UInt64 = 7

# beta: the cube root of unity used by the endomorphism lambda*(x,y) = (beta*x, y)
comptime BETA = Fe.from_limbs(
    0x96C28719501EE,
    0x7512F58995C13,
    0xC3434E99CF049,
    0x7106E64479EA,
    0x7AE96A2B657C,
)

# The generator point G.
comptime GX = Fe.from_limbs(
    0x2815B16F81798,
    0xDB2DCE28D959F,
    0xE870B07029BFC,
    0xBBAC55A06295C,
    0x79BE667EF9DC,
)
comptime GY = Fe.from_limbs(
    0x7D08FFB10D4B8,
    0x48A68554199C4,
    0xE1108A8FD17B4,
    0xC4655DA4FBFC0,
    0x483ADA7726A3,
)

comptime TAG_EVEN: UInt8 = 0x02
comptime TAG_ODD: UInt8 = 0x03
comptime TAG_UNCOMPRESSED: UInt8 = 0x04
comptime TAG_HYBRID_EVEN: UInt8 = 0x06
comptime TAG_HYBRID_ODD: UInt8 = 0x07


@fieldwise_init
struct Ge(ImplicitlyCopyable):
    """An affine point, or the point at infinity when `infinity` is set."""

    var x: Fe
    var y: Fe
    var infinity: Bool

    @staticmethod
    def infinity_point() -> Ge:
        return Ge(Fe.zero(), Fe.zero(), True)

    @staticmethod
    def generator() -> Ge:
        return Ge(GX, GY, False)

    @staticmethod
    def from_xy(x: Fe, y: Fe) -> Ge:
        return Ge(x, y, False)

    def neg(self) -> Ge:
        var y = self.y
        y.normalize_weak()
        return Ge(self.x, y.negated(1), self.infinity)

    def clear(mut self):
        """Wipe the coordinates; see `scrub.mojo`."""
        self.x.clear()
        self.y.clear()
        self.infinity = True

    @staticmethod
    def set_ge_zinv(a: Ge, zi: Fe) -> Ge:
        """`a` reinterpreted in the frame where its z-inverse is `zi`.

        Used to bring a table of points onto one shared z without inverting.
        """
        var zi2 = zi.sqr()
        return Ge(a.x * zi2, a.y * zi2 * zi, a.infinity)

    def mul_lambda(self) -> Ge:
        return Ge(self.x * BETA, self.y, self.infinity)

    def is_valid_var(self) -> Bool:
        """Check the point satisfies the curve equation."""
        if self.infinity:
            return False
        var y2 = self.y.sqr()
        var x3 = self.x.sqr() * self.x
        x3.add_int(CURVE_B)
        return y2.equal(x3)

    def eq_var(self, other: Ge) -> Bool:
        if self.infinity != other.infinity:
            return False
        if self.infinity:
            return True
        return self.x.equal(other.x) and self.y.equal(other.y)

    # -------------------------------------------------------- (de)serializing

    @staticmethod
    def set_xo_var(x: Fe, odd: Bool) -> Tuple[Ge, Bool]:
        """Recover a point from its x coordinate and the parity of y."""
        var x2 = x.sqr()
        var x3 = x * x2
        x3.add_int(CURVE_B)
        var res = x3.sqrt()
        var y = res[0]
        y.normalize()
        if y.is_odd_norm() != odd:
            y = y.negated(1)
        return (Ge(x, y, False), res[1])

    @staticmethod
    def parse(pub: Span[UInt8, _]) -> Tuple[Ge, Bool]:
        """Parse a 33-byte compressed or 65-byte uncompressed/hybrid pubkey."""
        var n = len(pub)
        if n == 33 and (pub[0] == TAG_EVEN or pub[0] == TAG_ODD):
            var px = Fe.from_bytes_limit(pub[1:33])
            if not px[1]:
                return (Ge.infinity_point(), False)
            return Ge.set_xo_var(px[0], pub[0] == TAG_ODD)
        if n == 65 and (
            pub[0] == TAG_UNCOMPRESSED
            or pub[0] == TAG_HYBRID_EVEN
            or pub[0] == TAG_HYBRID_ODD
        ):
            var px = Fe.from_bytes_limit(pub[1:33])
            var py = Fe.from_bytes_limit(pub[33:65])
            if not px[1] or not py[1]:
                return (Ge.infinity_point(), False)
            var y = py[0]
            y.normalize()
            if (pub[0] == TAG_HYBRID_EVEN or pub[0] == TAG_HYBRID_ODD) and (
                y.is_odd_norm() != (pub[0] == TAG_HYBRID_ODD)
            ):
                return (Ge.infinity_point(), False)
            var p = Ge(px[0], py[0], False)
            return (p, p.is_valid_var())
        return (Ge.infinity_point(), False)

    def serialize33(self) -> List[UInt8]:
        var x = self.x
        var y = self.y
        x.normalize()
        y.normalize()
        var out = List[UInt8](capacity=33)
        out.append(TAG_ODD if y.is_odd_norm() else TAG_EVEN)
        out.extend(x.to_bytes())
        return out^

    def serialize65(self) -> List[UInt8]:
        var x = self.x
        var y = self.y
        x.normalize()
        y.normalize()
        var out = List[UInt8](capacity=65)
        out.append(TAG_UNCOMPRESSED)
        out.extend(x.to_bytes())
        out.extend(y.to_bytes())
        return out^


@fieldwise_init
struct Gej(ImplicitlyCopyable):
    """A Jacobian point: the affine point is (x/z^2, y/z^3)."""

    var x: Fe
    var y: Fe
    var z: Fe
    var infinity: Bool

    @staticmethod
    def infinity_point() -> Gej:
        return Gej(Fe.zero(), Fe.zero(), Fe.zero(), True)

    @staticmethod
    def from_ge(a: Ge) -> Gej:
        return Gej(a.x, a.y, Fe.from_int(1), a.infinity)

    def is_infinity(self) -> Bool:
        return self.infinity

    @always_inline
    def neg(self) -> Gej:
        var y = self.y
        y.normalize_weak()
        return Gej(self.x, y.negated(1), self.z, self.infinity)

    def clear(mut self):
        """Wipe the coordinates; see `scrub.mojo`."""
        self.x.clear()
        self.y.clear()
        self.z.clear()
        self.infinity = True

    def to_ge_var(self) -> Ge:
        """Convert to affine, inverting z (variable time in the inversion)."""
        if self.infinity:
            return Ge.infinity_point()
        var zi = self.z.inv_var()
        var zi2 = zi.sqr()
        var zi3 = zi2 * zi
        return Ge(self.x * zi2, self.y * zi3, False)

    def eq_ge_var(self, b: Ge) -> Bool:
        if self.infinity != b.infinity:
            return False
        if self.infinity:
            return True
        # b.x * z^2 == x  and  b.y * z^3 == y
        var z2 = self.z.sqr()
        var z3 = z2 * self.z
        return (b.x * z2).equal(self.x) and (b.y * z3).equal(self.y)

    def rescale(self, s: Fe) -> Gej:
        """Return the same point with z multiplied by s."""
        var s2 = s.sqr()
        var s3 = s2 * s
        return Gej(self.x * s2, self.y * s3, self.z * s, self.infinity)

    # ------------------------------------------------------------- arithmetic

    @always_inline
    def double(self) -> Gej:
        """Point doubling: 3 mul, 4 sqr. Correct for infinity too."""
        var z = self.z * self.y
        var s = self.y.sqr()
        var l = self.x.sqr()
        l.mul_int(3)
        l.half()
        var t = s.negated(1) * self.x
        var x = l.sqr()
        x.add_assign(t)
        x.add_assign(t)
        s = s.sqr()
        t.add_assign(x)
        var y = t * l
        y.add_assign(s)
        y = y.negated(2)
        return Gej(x, y, z, self.infinity)

    def add_ge(self, b: Ge) -> Gej:
        """Add an affine point without variable-time branches."""
        var zz = self.z.sqr()
        var u1 = self.x
        var u2 = b.x * zz
        var s1 = self.y
        var s2 = b.y * zz * self.z
        var t = u1
        t.add_assign(u2)
        var m = s1
        m.add_assign(s2)
        var rr = t.sqr()
        var m_alt = u2.negated(1)
        var tt = u1 * m_alt
        rr.add_assign(tt)

        var degenerate = m.normalizes_to_zero()

        var rr_alt = s1
        rr_alt.mul_int(2)
        m_alt.add_assign(u1)

        rr_alt.cmov(rr, not degenerate)
        m_alt.cmov(m, not degenerate)

        var n = m_alt.sqr()
        var q = t.negated(5) * n
        n = n.sqr()
        n.cmov(m, degenerate)
        t = rr_alt.sqr()
        var z = self.z * m_alt
        t.add_assign(q)
        var x = t
        t.mul_int(2)
        t.add_assign(q)
        t = t * rr_alt
        t.add_assign(n)
        var y = t.negated(6)
        y.half()

        x.cmov(b.x, self.infinity)
        y.cmov(b.y, self.infinity)
        z.cmov(Fe.from_int(1), self.infinity)

        return Gej(x, y, z, z.normalizes_to_zero())

    @always_inline
    def double_zr(self) -> Tuple[Gej, Fe]:
        """`double`, also returning the ratio between the new z and the old.

        The doubling formula sets z_new = z_old * y, so the ratio is y — which
        a caller walking a table onto a shared z needs alongside the ratios
        from the additions.
        """
        var ratio = self.y
        ratio.normalize_weak()
        return (self.double(), ratio)

    @always_inline
    def add_ge_var_zr(self, b: Ge) -> Tuple[Gej, Fe]:
        """`add_ge_var`, also returning the ratio between the new z and the old.

        z_new == z_old * h, and `h` is what the caller needs to walk a whole
        table onto a single shared z afterwards. Only valid on the normal
        path: the caller must know the points are neither equal nor opposite,
        which holds for successive odd multiples of a point of large order.
        """
        var z12 = self.z.sqr()
        var u1 = self.x
        var u2 = b.x * z12
        var s1 = self.y
        var s2 = b.y * z12 * self.z
        var h = u1.negated(4)
        h.add_assign(u2)
        var i = s2.negated(1)
        i.add_assign(s1)

        var z = self.z * h
        var h2 = h.sqr().negated(1)
        var h3 = h2 * h
        var t = u1 * h2

        var x = i.sqr()
        x.add_assign(h3)
        x.add_assign(t)
        x.add_assign(t)

        t.add_assign(x)
        var y = t * i
        h3 = h3 * s1
        y.add_assign(h3)

        return (Gej(x, y, z, False), h)

    @always_inline
    def add_var(self, b: Gej) -> Gej:
        """Add two Jacobian points, branching on the special cases."""
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
        var h = u1.negated(1)
        h.add_assign(u2)
        var i = s2.negated(1)
        i.add_assign(s1)

        if h.normalizes_to_zero_var():
            if i.normalizes_to_zero_var():
                return self.double()
            return Gej.infinity_point()

        var t = h * b.z
        var z = self.z * t

        var h2 = h.sqr().negated(1)
        var h3 = h2 * h
        t = u1 * h2

        var x = i.sqr()
        x.add_assign(h3)
        x.add_assign(t)
        x.add_assign(t)

        t.add_assign(x)
        var y = t * i
        h3 = h3 * s1
        y.add_assign(h3)

        return Gej(x, y, z, False)

    @always_inline
    def add_ge_var(self, b: Ge) -> Gej:
        """Mixed addition: add an affine point, branching on special cases.

        Cheaper than promoting `b` to Jacobian and calling `add_var`, because
        b.z == 1 removes four field multiplications.
        """
        if self.infinity:
            return Gej.from_ge(b)
        if b.infinity:
            return self

        var z12 = self.z.sqr()
        var u1 = self.x
        var u2 = b.x * z12
        var s1 = self.y
        var s2 = b.y * z12 * self.z
        var h = u1.negated(4)
        h.add_assign(u2)
        var i = s2.negated(1)
        i.add_assign(s1)

        if h.normalizes_to_zero_var():
            if i.normalizes_to_zero_var():
                return self.double()
            return Gej.infinity_point()

        var z = self.z * h
        var h2 = h.sqr().negated(1)
        var h3 = h2 * h
        var t = u1 * h2

        var x = i.sqr()
        x.add_assign(h3)
        x.add_assign(t)
        x.add_assign(t)

        t.add_assign(x)
        var y = t * i
        h3 = h3 * s1
        y.add_assign(h3)

        return Gej(x, y, z, False)

    def add_zinv_var(self, b: Ge, bzinv: Fe) -> Gej:
        """Add `b`, given as an affine point whose true z-inverse is `bzinv`."""
        if self.infinity:
            var bzinv2 = bzinv.sqr()
            var bzinv3 = bzinv2 * bzinv
            return Gej(b.x * bzinv2, b.y * bzinv3, Fe.from_int(1), b.infinity)
        if b.infinity:
            return self

        var az = self.z * bzinv
        var z12 = az.sqr()
        var u1 = self.x
        var u2 = b.x * z12
        var s1 = self.y
        var s2 = b.y * z12 * az
        var h = u1.negated(4)
        h.add_assign(u2)
        var i = s2.negated(1)
        i.add_assign(s1)

        if h.normalizes_to_zero_var():
            if i.normalizes_to_zero_var():
                return self.double()
            return Gej.infinity_point()

        var z = self.z * h
        var h2 = h.sqr().negated(1)
        var h3 = h2 * h
        var t = u1 * h2

        var x = i.sqr()
        x.add_assign(h3)
        x.add_assign(t)
        x.add_assign(t)

        t.add_assign(x)
        var y = t * i
        h3 = h3 * s1
        y.add_assign(h3)

        return Gej(x, y, z, False)


def set_all_gej_var(points: List[Gej]) -> List[Ge]:
    """Batch-convert Jacobian points to affine with a single field inversion.

    Uses Montgomery's trick: one inversion plus 3 multiplications per point,
    instead of one inversion per point.
    """
    var n = len(points)
    var out = List[Ge](capacity=n)
    var prefix = List[Fe](capacity=n)
    var acc = Fe.from_int(1)
    var any = False
    for i in range(n):
        prefix.append(acc)
        if not points[i].infinity:
            acc = acc * points[i].z
            any = True
    if not any:
        for _ in range(n):
            out.append(Ge.infinity_point())
        return out^

    var inv = acc.inv_var()
    # Walk backwards, peeling one z off the running inverse at each step.
    var zinv = List[Fe](capacity=n)
    for _ in range(n):
        zinv.append(Fe.zero())
    for i in range(n - 1, -1, -1):
        if points[i].infinity:
            continue
        zinv[i] = prefix[i] * inv
        inv = inv * points[i].z

    for i in range(n):
        if points[i].infinity:
            out.append(Ge.infinity_point())
        else:
            var zi2 = zinv[i].sqr()
            var zi3 = zi2 * zinv[i]
            out.append(Ge(points[i].x * zi2, points[i].y * zi3, False))
    return out^
