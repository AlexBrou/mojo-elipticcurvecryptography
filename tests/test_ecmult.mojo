"""Scalar multiplication tests, checked against vectors from libsecp256k1."""

from std.testing import assert_equal, assert_true, TestSuite

from secp256k1.ecmult import EcmultGenContext, ecmult, ecmult_const, ecmult_var
from secp256k1.field import Fe
from secp256k1.group import Ge, Gej
from secp256k1.scalar import Scalar
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def parse_point(h: String) raises -> Ge:
    if h == "INF":
        return Ge.infinity_point()
    var res = Ge.parse(hex_to_bytes(h))
    if not res[1]:
        raise Error("bad point vector: " + h)
    return res[0]


def point_hex(a: Ge) raises -> String:
    return "INF" if a.infinity else bytes_to_hex(a.serialize65())


def gej_hex(a: Gej) raises -> String:
    return point_hex(a.to_ge_var())


def parse_sc(h: String) raises -> Scalar:
    return Scalar.from_bytes(hex_to_bytes(h))[0]


def rows(op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load("ecmult.txt"):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def test_ecmult_gen() raises:
    var ctx = EcmultGenContext()
    for r in rows("GEN"):
        assert_equal(gej_hex(ctx.mult(parse_sc(r.arg(0)))), r.arg(1))


def test_ecmult_const() raises:
    for r in rows("CONST"):
        var a = parse_point(r.arg(0))
        var q = parse_sc(r.arg(1))
        assert_equal(gej_hex(ecmult_const(a, q)), r.arg(2))


def test_ecmult_const_matches_gen() raises:
    # q*G computed two independent ways must agree.
    var ctx = EcmultGenContext()
    var g = Ge.generator()
    var n = 0
    for r in rows("GEN"):
        var k = parse_sc(r.arg(0))
        if k.is_zero():
            continue
        assert_equal(gej_hex(ecmult_const(g, k)), gej_hex(ctx.mult(k)))
        n += 1
        if n >= 12:
            break


def test_ecmult() raises:
    var ctx = EcmultGenContext()
    for r in rows("ECMULT"):
        var a = parse_point(r.arg(0))
        var na = parse_sc(r.arg(1))
        var ng = parse_sc(r.arg(2))
        assert_equal(gej_hex(ecmult(ctx, Gej.from_ge(a), na, ng)), r.arg(3))


def test_ecmult_var_alone() raises:
    # na*A + 0*G must equal the pure variable-time path.
    var ctx = EcmultGenContext()
    for r in rows("CONST"):
        var a = parse_point(r.arg(0))
        var na = parse_sc(r.arg(1))
        assert_equal(
            gej_hex(ecmult(ctx, Gej.from_ge(a), na, Scalar.zero())), r.arg(2)
        )
        assert_equal(gej_hex(ecmult_var(Gej.from_ge(a), na)), r.arg(2))


def test_edge_scalars() raises:
    var ctx = EcmultGenContext()
    var g = Ge.generator()
    var one = Scalar.one()
    var nm1 = one.negated()

    # 1*G == G, (n-1)*G == -G, and the two must sum to infinity.
    assert_equal(gej_hex(ecmult_const(g, one)), point_hex(g))
    assert_equal(gej_hex(ecmult_const(g, nm1)), point_hex(g.neg()))
    assert_true(
        ecmult_const(g, one).add_var(ecmult_const(g, nm1)).is_infinity()
    )
    assert_true(ecmult_const(g, Scalar.zero()).is_infinity())
    assert_true(ecmult_const(Ge.infinity_point(), one).is_infinity())
    assert_true(ecmult_var(Gej.infinity_point(), one).is_infinity())
    assert_true(ctx.mult(Scalar.zero()).is_infinity())


def test_linearity() raises:
    # (a + b)*G == a*G + b*G, over the vector scalars.
    var ctx = EcmultGenContext()
    var prev = Scalar.one()
    var n = 0
    for r in rows("GEN"):
        var k = parse_sc(r.arg(0))
        var sum = k + prev
        var lhs = ctx.mult(sum)
        var rhs = ctx.mult(k).add_var(ctx.mult(prev))
        assert_equal(gej_hex(lhs), gej_hex(rhs))
        prev = k
        n += 1
        if n >= 10:
            break


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
