"""Group operation tests, checked against vectors produced by libsecp256k1."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from secp256k1.field import Fe
from secp256k1.group import Ge, Gej, set_all_gej_var
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def parse_point(h: String) raises -> Ge:
    """Parse the "04||x||y" / "INF" encoding used by the vector generator."""
    if h == "INF":
        return Ge.infinity_point()
    var b = hex_to_bytes(h)
    if len(b) != 65:
        raise Error("point must be 65 bytes")
    var res = Ge.parse(b)
    if not res[1]:
        raise Error("vector point failed to parse: " + h)
    return res[0]


def point_hex(a: Ge) raises -> String:
    if a.infinity:
        return "INF"
    return bytes_to_hex(a.serialize65())


def gej_hex(a: Gej) raises -> String:
    return point_hex(a.to_ge_var())


def rows(op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load("group.txt"):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def test_generator() raises:
    for r in rows("GENERATOR"):
        assert_equal(point_hex(Ge.generator()), r.arg(0))
    assert_true(Ge.generator().is_valid_var())


def test_parse_roundtrip() raises:
    for r in rows("SER33"):
        var p = parse_point(r.arg(0))
        assert_equal(bytes_to_hex(p.serialize33()), r.arg(1))
        # and parsing the compressed form recovers the same point
        var back = Ge.parse(p.serialize33())
        assert_true(back[1])
        assert_true(back[0].eq_var(p))


def test_double() raises:
    for r in rows("DOUBLE"):
        var a = parse_point(r.arg(0))
        assert_equal(gej_hex(Gej.from_ge(a).double()), r.arg(1))


def test_double_infinity() raises:
    for r in rows("DOUBLEJ"):
        assert_equal(gej_hex(Gej.infinity_point().double()), r.arg(1))


def test_add_ge() raises:
    for r in rows("ADDGE"):
        var a = parse_point(r.arg(0))
        var b = parse_point(r.arg(1))
        assert_equal(gej_hex(Gej.from_ge(a).add_ge(b)), r.arg(2))


def test_add_ge_var() raises:
    for r in rows("ADDGE"):
        var a = parse_point(r.arg(0))
        var b = parse_point(r.arg(1))
        assert_equal(gej_hex(Gej.from_ge(a).add_ge_var(b)), r.arg(2))


def test_add_jacobian() raises:
    for r in rows("ADDJ"):
        var a = parse_point(r.arg(0))
        var b = parse_point(r.arg(1))
        assert_equal(gej_hex(Gej.from_ge(a).add_var(Gej.from_ge(b))), r.arg(2))


def test_neg() raises:
    for r in rows("NEG"):
        assert_equal(point_hex(parse_point(r.arg(0)).neg()), r.arg(1))


def test_mul_lambda() raises:
    for r in rows("MULLAMBDA"):
        assert_equal(point_hex(parse_point(r.arg(0)).mul_lambda()), r.arg(1))


def test_add_zinv_var() raises:
    # add_zinv_var(a, b, 1/bz) must match adding b directly.
    for r in rows("ADDGE"):
        var a = parse_point(r.arg(0))
        var b = parse_point(r.arg(1))
        if b.infinity:
            continue
        # Represent b with a non-trivial z so the zinv path is exercised.
        var s = Fe.from_int(7)
        var bj = Gej.from_ge(b).rescale(s)
        var expected = Gej.from_ge(a).add_ge_var(b)
        var got = Gej.from_ge(a).add_zinv_var(Ge(bj.x, bj.y, False), s.inv())
        assert_equal(gej_hex(got), gej_hex(expected))


def test_rescale_is_identity() raises:
    for r in rows("SER33"):
        var p = parse_point(r.arg(0))
        var j = Gej.from_ge(p).rescale(Fe.from_int(12345))
        assert_equal(gej_hex(j), point_hex(p))
        assert_true(j.eq_ge_var(p))


def test_set_all_gej_var() raises:
    var pts = List[Gej]()
    var expected = List[String]()
    var n = 0
    for r in rows("SER33"):
        var p = parse_point(r.arg(0))
        var j = Gej.from_ge(p).rescale(Fe.from_int(UInt64(3 + n)))
        pts.append(j)
        expected.append(point_hex(p))
        n += 1
        if n >= 20:
            break
    # sprinkle in an infinity to check it is handled
    pts.append(Gej.infinity_point())
    expected.append("INF")

    var affine = set_all_gej_var(pts)
    assert_equal(len(affine), len(expected))
    for i in range(len(affine)):
        assert_equal(point_hex(affine[i]), expected[i])


def test_curve_membership() raises:
    for r in rows("SER33"):
        assert_true(parse_point(r.arg(0)).is_valid_var())
    # a point off the curve must be rejected
    var bad = Ge(Fe.from_int(1), Fe.from_int(1), False)
    assert_false(bad.is_valid_var())


def test_parse_rejects_bad_input() raises:
    var bad_prefix = List[UInt8]()
    bad_prefix.append(0x05)
    for _ in range(32):
        bad_prefix.append(0)
    assert_false(Ge.parse(bad_prefix)[1])

    # x = 5 has no y (5^3 + 7 is not a quadratic residue mod p), so parsing
    # a compressed key with that x must fail.
    var not_on_curve = List[UInt8]()
    not_on_curve.append(0x02)
    for _ in range(31):
        not_on_curve.append(0)
    not_on_curve.append(5)
    assert_false(Ge.parse(not_on_curve)[1])

    # x = 1 does have a y, so it must parse and land on the curve.
    var on_curve = List[UInt8]()
    on_curve.append(0x02)
    for _ in range(31):
        on_curve.append(0)
    on_curve.append(1)
    var ok = Ge.parse(on_curve)
    assert_true(ok[1])
    assert_true(ok[0].is_valid_var())

    # x >= p must be rejected outright.
    var too_big = List[UInt8]()
    too_big.append(0x02)
    for _ in range(32):
        too_big.append(0xFF)
    assert_false(Ge.parse(too_big)[1])

    # wrong lengths
    assert_false(Ge.parse(List[UInt8]())[1])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
