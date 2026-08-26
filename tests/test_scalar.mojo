"""Scalar arithmetic tests, checked against vectors produced by libsecp256k1."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from secp256k1.scalar import Scalar
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def parse_sc(h: String) raises -> Scalar:
    var b = hex_to_bytes(h)
    if len(b) != 32:
        raise Error("scalar must be 32 bytes")
    var r = Scalar.from_bytes(b)
    return r[0]


def sc_hex(a: Scalar) raises -> String:
    return bytes_to_hex(a.to_bytes())


def rows(op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load("scalar.txt"):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def test_set_b32_overflow() raises:
    for r in rows("SETB32"):
        var b = hex_to_bytes(r.arg(0))
        var res = Scalar.from_bytes(b)
        assert_equal(sc_hex(res[0]), r.arg(1))
        assert_equal(Int(res[1]), Int(r.arg(2)))


def test_roundtrip() raises:
    for r in rows("MUL"):
        assert_equal(sc_hex(parse_sc(r.arg(0))), r.arg(0))


def test_add() raises:
    for r in rows("ADD"):
        var a = parse_sc(r.arg(0))
        var b = parse_sc(r.arg(1))
        var res = a.add_with_overflow(b)
        assert_equal(sc_hex(res[0]), r.arg(2))
        assert_equal(Int(res[1]), Int(r.arg(3)))


def test_mul() raises:
    for r in rows("MUL"):
        assert_equal(sc_hex(parse_sc(r.arg(0)) * parse_sc(r.arg(1))), r.arg(2))


def test_negate() raises:
    for r in rows("NEG"):
        assert_equal(sc_hex(parse_sc(r.arg(0)).negated()), r.arg(1))


def test_inverse() raises:
    for r in rows("INV"):
        assert_equal(sc_hex(parse_sc(r.arg(0)).inverse()), r.arg(1))


def test_inverse_var() raises:
    for r in rows("INV"):
        assert_equal(sc_hex(parse_sc(r.arg(0)).inverse_var()), r.arg(1))


def test_inverse_agrees_with_exponentiation() raises:
    # safegcd (inverse) vs the a^(n-2) window (inverse_pow): two independent
    # implementations that must agree.
    for r in rows("INV"):
        var a = parse_sc(r.arg(0))
        assert_equal(sc_hex(a.inverse()), sc_hex(a.inverse_pow()))


def test_inverse_is_an_inverse() raises:
    for r in rows("MUL"):
        var a = parse_sc(r.arg(0))
        if a.is_zero():
            continue
        assert_true((a * a.inverse()).is_one())


def test_half() raises:
    for r in rows("HALF"):
        assert_equal(sc_hex(parse_sc(r.arg(0)).half()), r.arg(1))


def test_is_high() raises:
    for r in rows("ISHIGH"):
        assert_equal(Int(parse_sc(r.arg(0)).is_high()), Int(r.arg(1)))


def test_is_even() raises:
    for r in rows("ISEVEN"):
        assert_equal(Int(parse_sc(r.arg(0)).is_even()), Int(r.arg(1)))


def test_split_lambda() raises:
    for r in rows("SPLITLAMBDA"):
        var res = parse_sc(r.arg(0)).split_lambda()
        assert_equal(sc_hex(res[0]), r.arg(1))
        assert_equal(sc_hex(res[1]), r.arg(2))


def test_split_128() raises:
    for r in rows("SPLIT128"):
        var res = parse_sc(r.arg(0)).split_128()
        assert_equal(sc_hex(res[0]), r.arg(1))
        assert_equal(sc_hex(res[1]), r.arg(2))


def test_basics() raises:
    var z = Scalar.zero()
    var o = Scalar.one()
    assert_true(z.is_zero())
    assert_true(o.is_one())
    assert_false(o.is_zero())
    assert_true(z.negated().is_zero())
    assert_true(z.inverse().is_zero())
    assert_true(z.inverse_var().is_zero())
    assert_true(z.inverse_pow().is_zero())
    assert_true((o.inverse()).is_one())
    assert_equal(sc_hex(o * o), sc_hex(o))
    # (n-1) + 1 == 0
    var nm1 = o.negated()
    assert_true((nm1 + o).is_zero())


def test_get_bits() raises:
    # get_bits must agree with the big-endian serialization, for every window
    # size and offset, including windows that straddle a limb boundary.
    for r in rows("MUL"):
        var a = parse_sc(r.arg(0))
        var b = a.to_bytes()
        for count in [1, 4, 8, 15, 32]:
            for offset in range(0, 256 - count + 1, 7):
                var expected = UInt32(0)
                for k in range(count):
                    var bit = offset + k
                    var byte = b[31 - (bit >> 3)]
                    var v = (byte >> UInt8(bit & 7)) & 1
                    expected |= UInt32(v) << UInt32(k)
                assert_equal(
                    Int(a.get_bits(offset, count)),
                    Int(expected),
                    "get_bits mismatch at offset " + String(offset),
                )


def test_cmov() raises:
    var a = Scalar.from_int(5)
    var b = Scalar.from_int(9)
    var r = a
    r.cmov(b, False)
    assert_true(r == a)
    r.cmov(b, True)
    assert_true(r == b)


def test_clear() raises:
    # Secrets are wiped with a volatile store so the optimizer cannot drop it;
    # tools/check_scrub.sh checks that at the assembly level, this checks the
    # value actually ends up zero.
    var a = parse_sc(rows("MUL")[0].arg(0))
    assert_false(a.is_zero())
    a.clear()
    assert_true(a.is_zero())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
