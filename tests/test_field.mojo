"""Field arithmetic tests, checked against vectors produced by libsecp256k1."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from secp256k1.field import Fe
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def parse_fe(h: String) raises -> Fe:
    var b = hex_to_bytes(h)
    if len(b) != 32:
        raise Error("field element must be 32 bytes")
    return Fe.from_bytes_mod(b)


def fe_hex(a: Fe) raises -> String:
    var t = a
    t.normalize()
    return bytes_to_hex(t.to_bytes())


def rows(op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load("field.txt"):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def test_roundtrip_bytes() raises:
    for r in rows("MUL"):
        var a = parse_fe(r.arg(0))
        assert_equal(fe_hex(a), r.arg(0))


def test_add() raises:
    for r in rows("ADD"):
        var a = parse_fe(r.arg(0))
        var b = parse_fe(r.arg(1))
        assert_equal(fe_hex(a + b), r.arg(2))


def test_mul() raises:
    for r in rows("MUL"):
        var a = parse_fe(r.arg(0))
        var b = parse_fe(r.arg(1))
        assert_equal(fe_hex(a * b), r.arg(2))


def test_sqr() raises:
    for r in rows("SQR"):
        var a = parse_fe(r.arg(0))
        assert_equal(fe_hex(a.sqr()), r.arg(1))


def test_negate() raises:
    for r in rows("NEG"):
        var a = parse_fe(r.arg(0))
        assert_equal(fe_hex(a.negated(1)), r.arg(1))


def test_half() raises:
    for r in rows("HALF"):
        var a = parse_fe(r.arg(0))
        var h = a
        h.half()
        assert_equal(fe_hex(h), r.arg(1))


def test_mul_int() raises:
    for r in rows("MULINT7"):
        var a = parse_fe(r.arg(0))
        var t = a
        t.mul_int(7)
        assert_equal(fe_hex(t), r.arg(1))


def test_inv() raises:
    for r in rows("INV"):
        var a = parse_fe(r.arg(0))
        assert_equal(fe_hex(a.inv()), r.arg(1))


def test_inv_var() raises:
    for r in rows("INV"):
        var a = parse_fe(r.arg(0))
        assert_equal(fe_hex(a.inv_var()), r.arg(1))


def test_inv_agrees_with_exponentiation() raises:
    # safegcd (inv) and the a^(p-2) chain (inv_pow) are independent
    # implementations; they must agree on every vector.
    for r in rows("INV"):
        var a = parse_fe(r.arg(0))
        assert_equal(fe_hex(a.inv()), fe_hex(a.inv_pow()))


def test_inv_is_an_inverse() raises:
    # a * a^-1 == 1 for every nonzero vector element.
    for r in rows("MUL"):
        var a = parse_fe(r.arg(0))
        if a.normalized().is_zero_norm():
            continue
        var one = a * a.inv()
        assert_equal(fe_hex(one), String("0") * 63 + "1")


def test_sqrt() raises:
    for r in rows("SQRT"):
        var a = parse_fe(r.arg(0))
        var res = a.sqrt()
        if r.arg(1) == "NONE":
            assert_false(res[1], "expected non-square: " + r.arg(0))
        else:
            assert_true(res[1], "expected square: " + r.arg(0))
            assert_equal(fe_hex(res[0]), r.arg(1))


def test_is_odd() raises:
    for r in rows("ISODD"):
        var a = parse_fe(r.arg(0)).normalized()
        assert_equal(Int(a.is_odd_norm()), Int(r.arg(1)))


def test_zero_and_equal() raises:
    var z = Fe.zero()
    assert_true(z.normalizes_to_zero())
    assert_true(z.normalized().is_zero_norm())
    var one = Fe.from_int(1)
    assert_false(one.normalizes_to_zero())
    assert_true(one.equal(one))
    assert_false(one.equal(z))


def test_normalize_at_p() raises:
    # p itself must normalize to zero, and p+1 to one.
    var p = Fe.from_limbs(
        0xFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFF,
        0x0FFFFFFFFFFFF,
    )
    assert_true(p.normalizes_to_zero())
    assert_true(p.normalized().is_zero_norm())
    var p1 = p
    p1.add_int(1)
    assert_equal(fe_hex(p1), String("0") * 63 + "1")


def test_cmov() raises:
    var a = Fe.from_int(5)
    var b = Fe.from_int(9)
    var r = a
    r.cmov(b, False)
    assert_equal(fe_hex(r), fe_hex(a))
    r.cmov(b, True)
    assert_equal(fe_hex(r), fe_hex(b))


def test_clear() raises:
    var a = parse_fe(rows("MUL")[0].arg(0))
    assert_false(a.normalized().is_zero_norm())
    a.clear()
    assert_true(a.normalized().is_zero_norm())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
