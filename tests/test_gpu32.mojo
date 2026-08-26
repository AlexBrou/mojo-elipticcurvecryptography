"""The 32-bit (GPU-compatible) arithmetic, checked against the same
libsecp256k1 vectors as the 64-bit CPU implementation.

These run on the CPU: the point is to validate the algorithms independently of
GPU execution, so a kernel failure can never be confused with a maths bug.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from secp256k1.gpu32 import (
    FeGpu,
    GeGpu,
    GejGpu,
    ScalarBits,
    mul_point,
    mul_point_split,
)
from secp256k1.scalar import Scalar
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def to_arr32(b: List[UInt8]) raises -> InlineArray[UInt8, 32]:
    if len(b) != 32:
        raise Error("expected 32 bytes")
    var a = InlineArray[UInt8, 32](fill=0)
    for i in range(32):
        a[i] = b[i]
    return a^


def parse_fe(h: String) raises -> FeGpu:
    return FeGpu.from_bytes(to_arr32(hex_to_bytes(h)))


def fe_hex(a: FeGpu) -> String:
    var b = a.to_bytes()
    var out = String()
    var digits = "0123456789abcdef"
    for i in range(32):
        var v = Int(b[i])
        out += digits[byte=v >> 4]
        out += digits[byte=v & 0xF]
    return out^


def parse_scalar(h: String) raises -> ScalarBits:
    var b = hex_to_bytes(h)
    var d = InlineArray[UInt32, 8](fill=0)
    for i in range(8):
        var base = 28 - 4 * i
        d[i] = (
            (UInt32(b[base]) << 24)
            | (UInt32(b[base + 1]) << 16)
            | (UInt32(b[base + 2]) << 8)
            | UInt32(b[base + 3])
        )
    return ScalarBits(d^)


def parse_point(h: String) raises -> GeGpu:
    if h == "INF":
        return GeGpu.infinity_point()
    var b = hex_to_bytes(h)
    if len(b) != 65 or b[0] != 0x04:
        raise Error("expected an uncompressed point")
    var x = InlineArray[UInt8, 32](fill=0)
    var y = InlineArray[UInt8, 32](fill=0)
    for i in range(32):
        x[i] = b[1 + i]
        y[i] = b[33 + i]
    return GeGpu(FeGpu.from_bytes(x), FeGpu.from_bytes(y), False)


def point_hex(a: GeGpu) -> String:
    if a.infinity:
        return "INF"
    return "04" + fe_hex(a.x) + fe_hex(a.y)


def gej_hex(a: GejGpu) -> String:
    return point_hex(a.to_ge())


def rows(file: String, op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load(file):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def test_fe_roundtrip() raises:
    for r in rows("field.txt", "MUL"):
        assert_equal(fe_hex(parse_fe(r.arg(0))), r.arg(0))


def test_fe_add() raises:
    for r in rows("field.txt", "ADD"):
        assert_equal(fe_hex(parse_fe(r.arg(0)) + parse_fe(r.arg(1))), r.arg(2))


def test_fe_mul() raises:
    for r in rows("field.txt", "MUL"):
        assert_equal(fe_hex(parse_fe(r.arg(0)) * parse_fe(r.arg(1))), r.arg(2))


def test_fe_sqr() raises:
    for r in rows("field.txt", "SQR"):
        assert_equal(fe_hex(parse_fe(r.arg(0)).sqr()), r.arg(1))


def test_fe_neg() raises:
    for r in rows("field.txt", "NEG"):
        assert_equal(fe_hex(parse_fe(r.arg(0)).neg()), r.arg(1))


def test_fe_half() raises:
    for r in rows("field.txt", "HALF"):
        assert_equal(fe_hex(parse_fe(r.arg(0)).half()), r.arg(1))


def test_fe_mul_int() raises:
    for r in rows("field.txt", "MULINT7"):
        assert_equal(fe_hex(parse_fe(r.arg(0)).mul_int(7)), r.arg(1))


def test_fe_inv() raises:
    for r in rows("field.txt", "INV"):
        assert_equal(fe_hex(parse_fe(r.arg(0)).inv()), r.arg(1))


def test_fe_sqrt() raises:
    for r in rows("field.txt", "SQRT"):
        var res = parse_fe(r.arg(0)).sqrt()
        if r.arg(1) == "NONE":
            assert_false(res[1])
        else:
            assert_true(res[1])
            assert_equal(fe_hex(res[0]), r.arg(1))


def test_fe_sub_is_add_neg() raises:
    for r in rows("field.txt", "ADD"):
        var a = parse_fe(r.arg(0))
        var b = parse_fe(r.arg(1))
        assert_equal(fe_hex(a - b), fe_hex(a + b.neg()))


def test_fe_is_odd() raises:
    for r in rows("field.txt", "ISODD"):
        assert_equal(Int(parse_fe(r.arg(0)).is_odd()), Int(r.arg(1)))


def test_fe_edge_cases() raises:
    var zero = FeGpu.zero()
    var one = FeGpu.one()
    assert_true(zero.is_zero())
    assert_true(zero.neg().is_zero())
    assert_true((one + one.neg()).is_zero())
    assert_true(FeGpu.modulus().is_zero() == False)
    # p reduces to zero on parse
    var p_bytes = hex_to_bytes(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    )
    assert_true(FeGpu.from_bytes(to_arr32(p_bytes)).is_zero())
    # p + 1 reduces to one
    var p1 = hex_to_bytes(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30"
    )
    assert_equal(fe_hex(FeGpu.from_bytes(to_arr32(p1))), String("0") * 63 + "1")


def test_group_double() raises:
    for r in rows("group.txt", "DOUBLE"):
        var a = parse_point(r.arg(0))
        assert_equal(gej_hex(GejGpu.from_ge(a).double()), r.arg(1))


def test_group_add_ge() raises:
    for r in rows("group.txt", "ADDGE"):
        var a = parse_point(r.arg(0))
        var b = parse_point(r.arg(1))
        assert_equal(gej_hex(GejGpu.from_ge(a).add_ge(b)), r.arg(2))


def test_group_add_jacobian() raises:
    for r in rows("group.txt", "ADDJ"):
        var a = parse_point(r.arg(0))
        var b = parse_point(r.arg(1))
        assert_equal(
            gej_hex(GejGpu.from_ge(a).add(GejGpu.from_ge(b))), r.arg(2)
        )


def test_group_neg() raises:
    for r in rows("group.txt", "NEG"):
        assert_equal(point_hex(parse_point(r.arg(0)).neg()), r.arg(1))


def test_curve_membership() raises:
    for r in rows("group.txt", "DOUBLE"):
        assert_true(parse_point(r.arg(0)).is_valid())


def test_mul_point() raises:
    for r in rows("ecmult.txt", "CONST"):
        var a = parse_point(r.arg(0))
        var k = parse_scalar(r.arg(1))
        assert_equal(gej_hex(mul_point(a, k)), r.arg(2))


def scalar_to_bits(s: Scalar) raises -> ScalarBits:
    var b = s.to_bytes()
    var d = InlineArray[UInt32, 8](fill=0)
    for i in range(8):
        var base = 28 - 4 * i
        d[i] = (
            (UInt32(b[base]) << 24)
            | (UInt32(b[base + 1]) << 16)
            | (UInt32(b[base + 2]) << 8)
            | UInt32(b[base + 3])
        )
    return ScalarBits(d^)


def test_mul_point_split() raises:
    # The GLV path the GPU kernels actually use: split the scalar the way the
    # host does, then check k1*P + k2*lambda*P against the C vectors.
    for r in rows("ecmult.txt", "CONST"):
        var a = parse_point(r.arg(0))
        var k = Scalar.from_bytes(hex_to_bytes(r.arg(1)))[0]
        var parts = k.split_lambda()
        var neg1 = parts[0].is_high()
        var neg2 = parts[1].is_high()
        var got = mul_point_split(
            a,
            scalar_to_bits(parts[0].cond_negate(neg1)),
            scalar_to_bits(parts[1].cond_negate(neg2)),
            neg1,
            neg2,
        )
        assert_equal(gej_hex(got), r.arg(2))


def test_mul_point_split_edge_cases() raises:
    var g = parse_point(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
    var zero = scalar_to_bits(Scalar.zero())
    assert_true(mul_point_split(g, zero, zero, False, False).infinity)
    assert_true(
        mul_point_split(
            GeGpu.infinity_point(), zero, zero, False, False
        ).infinity
    )
    # 1*G must come back as G
    var one = Scalar.one()
    var parts = one.split_lambda()
    var n1 = parts[0].is_high()
    var n2 = parts[1].is_high()
    var got = mul_point_split(
        g,
        scalar_to_bits(parts[0].cond_negate(n1)),
        scalar_to_bits(parts[1].cond_negate(n2)),
        n1,
        n2,
    )
    assert_equal(point_hex(got.to_ge()), point_hex(g))


def test_eq_x() raises:
    # eq_x must agree with an explicit affine conversion.
    for r in rows("group.txt", "DOUBLE"):
        var a = parse_point(r.arg(0))
        var j = GejGpu.from_ge(a).double()
        var affine = j.to_ge()
        assert_true(j.eq_x(affine.x))
        assert_false(j.eq_x(affine.x + FeGpu.one()))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
