"""ECDSA and key tests, checked against vectors produced by libsecp256k1."""

from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)

from secp256k1.api import Secp256k1
from secp256k1.ecdsa import Signature
from secp256k1.group import Ge
from secp256k1.scalar import Scalar
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def rows(op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load("ecdsa.txt"):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def test_pubkey_create() raises:
    var ctx = Secp256k1()
    for r in rows("PUBKEY"):
        var sk = hex_to_bytes(r.arg(0))
        var res = ctx.pubkey_create(sk)
        assert_true(res[1])
        assert_equal(bytes_to_hex(res[0].serialize33()), r.arg(1))
        assert_equal(bytes_to_hex(res[0].serialize65()), r.arg(2))


def test_pubkey_parse_roundtrip() raises:
    var ctx = Secp256k1()
    for r in rows("PUBKEY"):
        var from33 = ctx.pubkey_parse(hex_to_bytes(r.arg(1)))
        var from65 = ctx.pubkey_parse(hex_to_bytes(r.arg(2)))
        assert_true(from33[1])
        assert_true(from65[1])
        assert_true(from33[0].eq_var(from65[0]))
        assert_equal(bytes_to_hex(from33[0].serialize65()), r.arg(2))


def test_sign_rfc6979() raises:
    var ctx = Secp256k1()
    for r in rows("SIGN"):
        var sk = hex_to_bytes(r.arg(0))
        var msg = hex_to_bytes(r.arg(1))
        var res = ctx.sign(msg, sk)
        assert_true(res[2], "signing failed")
        assert_equal(bytes_to_hex(res[0].serialize_compact()), r.arg(2))


def test_verify() raises:
    var ctx = Secp256k1()
    for r in rows("VERIFY"):
        var pk = ctx.pubkey_parse(hex_to_bytes(r.arg(0)))
        assert_true(pk[1])
        var msg = hex_to_bytes(r.arg(1))
        var sig = Signature.parse_compact(hex_to_bytes(r.arg(2)))
        var expected = r.arg(3) == "1"
        if not sig[1]:
            assert_false(expected, "vector expects a valid but unparseable sig")
            continue
        assert_equal(
            Int(ctx.verify(sig[0], msg, pk[0])),
            Int(expected),
            "verify mismatch for " + r.arg(2),
        )


def test_sign_then_verify() raises:
    var ctx = Secp256k1()
    for r in rows("SIGN"):
        var sk = hex_to_bytes(r.arg(0))
        var msg = hex_to_bytes(r.arg(1))
        var pk = ctx.pubkey_create(sk)
        var res = ctx.sign(msg, sk)
        assert_true(res[2])
        assert_true(ctx.verify(res[0], msg, pk[0]))
        assert_true(res[0].is_normalized())

        # a different message must not verify
        var other = msg.copy()
        other[0] ^= 0xFF
        assert_false(ctx.verify(res[0], other, pk[0]))


def test_der() raises:
    for r in rows("DER"):
        var sig = Signature.parse_compact(hex_to_bytes(r.arg(0)))
        assert_true(sig[1])
        assert_equal(bytes_to_hex(sig[0].serialize_der()), r.arg(1))


def test_recover() raises:
    var ctx = Secp256k1()
    for r in rows("RECOVER"):
        var msg = hex_to_bytes(r.arg(0))
        var sig = Signature.parse_compact(hex_to_bytes(r.arg(1)))
        assert_true(sig[1])
        var recid = Int(r.arg(2))
        var res = ctx.recover(sig[0], msg, recid)
        assert_true(res[1], "recovery failed")
        assert_equal(bytes_to_hex(res[0].serialize33()), r.arg(3))


def test_tweak_add_seckey() raises:
    var ctx = Secp256k1()
    for r in rows("TWEAKADD"):
        var res = ctx.seckey_tweak_add(
            hex_to_bytes(r.arg(0)), hex_to_bytes(r.arg(1))
        )
        assert_true(res[1])
        assert_equal(bytes_to_hex(res[0]), r.arg(2))


def test_tweak_mul_seckey() raises:
    var ctx = Secp256k1()
    for r in rows("TWEAKMUL"):
        var res = ctx.seckey_tweak_mul(
            hex_to_bytes(r.arg(0)), hex_to_bytes(r.arg(1))
        )
        assert_true(res[1])
        assert_equal(bytes_to_hex(res[0]), r.arg(2))


def test_tweak_add_pubkey() raises:
    var ctx = Secp256k1()
    for r in rows("PUBTWEAKADD"):
        var pk = ctx.pubkey_parse(hex_to_bytes(r.arg(0)))
        assert_true(pk[1])
        var res = ctx.pubkey_tweak_add(pk[0], hex_to_bytes(r.arg(1)))
        assert_true(res[1])
        assert_equal(bytes_to_hex(res[0].serialize33()), r.arg(2))


def test_tweak_consistency() raises:
    # pubkey(seckey_tweak_mul(sk, t)) == pubkey_tweak_mul(pubkey(sk), t)
    var ctx = Secp256k1()
    var n = 0
    for r in rows("TWEAKMUL"):
        var sk = hex_to_bytes(r.arg(0))
        var tw = hex_to_bytes(r.arg(1))
        var tweaked_sk = ctx.seckey_tweak_mul(sk, tw)
        var lhs = ctx.pubkey_create(tweaked_sk[0])
        var pk = ctx.pubkey_create(sk)
        var rhs = ctx.pubkey_tweak_mul(pk[0], tw)
        assert_true(rhs[1])
        assert_true(lhs[0].eq_var(rhs[0]))
        n += 1
        if n >= 10:
            break


def test_ecdh_symmetry() raises:
    # a * (b*G) == b * (a*G)
    var ctx = Secp256k1()
    var keys = List[List[UInt8]]()
    for r in rows("PUBKEY"):
        keys.append(hex_to_bytes(r.arg(0)))
        if len(keys) >= 8:
            break
    for i in range(len(keys) - 1):
        var a = keys[i].copy()
        var b = keys[i + 1].copy()
        var pa = ctx.pubkey_create(a)
        var pb = ctx.pubkey_create(b)
        var sa = ctx.ecdh_point(pb[0], a)
        var sb = ctx.ecdh_point(pa[0], b)
        assert_true(sa[1] and sb[1])
        assert_true(sa[0].eq_var(sb[0]))


def test_invalid_keys() raises:
    var ctx = Secp256k1()
    var zero = List[UInt8]()
    for _ in range(32):
        zero.append(0)
    assert_false(ctx.seckey_verify(zero))
    assert_false(ctx.pubkey_create(zero)[1])

    # n itself is out of range
    var order = hex_to_bytes(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    )
    assert_false(ctx.seckey_verify(order))
    assert_false(ctx.pubkey_create(order)[1])

    # n-1 is the largest valid key
    var nm1 = hex_to_bytes(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
    )
    assert_true(ctx.seckey_verify(nm1))
    assert_true(ctx.pubkey_create(nm1)[1])


def test_high_s_rejected() raises:
    # Flipping s to n-s keeps the signature mathematically valid but must be
    # rejected by verify(), which enforces low-s.
    var ctx = Secp256k1()
    var n = 0
    for r in rows("SIGN"):
        var sk = hex_to_bytes(r.arg(0))
        var msg = hex_to_bytes(r.arg(1))
        var pk = ctx.pubkey_create(sk)
        var res = ctx.sign(msg, sk)
        var flipped = Signature(res[0].r, res[0].s.negated())
        assert_false(flipped.is_normalized())
        assert_false(ctx.verify(flipped, msg, pk[0]))
        assert_true(ctx.verify(flipped.normalize(), msg, pk[0]))
        n += 1
        if n >= 8:
            break


def test_short_input_is_rejected() raises:
    """Every entry point taking caller-supplied bytes checks the length.

    `Scalar.from_bytes` reads 32 bytes unconditionally, so a shorter span used
    to abort on a bounds check with assertions enabled, and under
    `-D ASSERT=none` to read past the end of the buffer -- returning a key
    built from whatever happened to follow it.
    """
    var ctx = Secp256k1()
    var short = List[UInt8](capacity=16)
    for i in range(16):
        short.append(UInt8(i + 1))
    var full = List[UInt8](capacity=32)
    for i in range(32):
        full.append(UInt8(i + 1))
    var g = Ge.generator()

    assert_false(ctx.seckey_verify(short))

    with assert_raises(contains="32 bytes"):
        _ = ctx.pubkey_create(short)
    with assert_raises(contains="32 bytes"):
        _ = ctx.seckey_tweak_add(short, full)
    with assert_raises(contains="32 bytes"):
        _ = ctx.seckey_tweak_add(full, short)
    with assert_raises(contains="32 bytes"):
        _ = ctx.seckey_tweak_mul(short, full)
    with assert_raises(contains="32 bytes"):
        _ = ctx.seckey_tweak_mul(full, short)
    with assert_raises(contains="32 bytes"):
        _ = ctx.pubkey_tweak_add(g, short)
    with assert_raises(contains="32 bytes"):
        _ = ctx.pubkey_tweak_mul(g, short)
    with assert_raises(contains="32 bytes"):
        _ = ctx.ecdh_point(g, short)
    with assert_raises(contains="32 bytes"):
        _ = ctx.sign(short, full)
    with assert_raises(contains="32 bytes"):
        _ = ctx.sign(full, short)

    # An empty span is the same mistake, and must not be read as zero.
    var empty = List[UInt8]()
    with assert_raises(contains="32 bytes"):
        _ = ctx.ecdh_point(g, empty)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
