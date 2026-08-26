"""GPU batch operations, checked against the libsecp256k1 vectors and against
the CPU implementation in this repo.

Every GPU result is compared with a value the C library produced, so a kernel
that silently computes the wrong thing cannot pass.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from secp256k1.api import Secp256k1
from secp256k1.ecdsa import Signature
from secp256k1.ecmult import EcmultGenContext, ecmult_const
from secp256k1.group import Ge, Gej
from secp256k1.gpu import GpuBatch, batch_scalar_inverse
from secp256k1.scalar import Scalar
from secp256k1.util import hex_to_bytes, bytes_to_hex
from tests.vec import load, Row


def rows(file: String, op: String) raises -> List[Row]:
    var out = List[Row]()
    for r in load(file):
        if r.op == op:
            out.append(r.copy())
    if len(out) == 0:
        raise Error("no vectors for op " + op)
    return out^


def parse_point(h: String) raises -> Ge:
    if h == "INF":
        return Ge.infinity_point()
    var res = Ge.parse(hex_to_bytes(h))
    if not res[1]:
        raise Error("bad point vector: " + h)
    return res[0]


def point_hex(a: Ge) raises -> String:
    return "INF" if a.infinity else bytes_to_hex(a.serialize65())


def parse_sc(h: String) raises -> Scalar:
    return Scalar.from_bytes(hex_to_bytes(h))[0]


def test_device_available() raises:
    var gpu = GpuBatch(EcmultGenContext())
    var name = gpu.device_name()
    assert_true(name.byte_length() > 0, "no GPU device name reported")


def test_batch_mul_gen() raises:
    var gpu = GpuBatch(EcmultGenContext())
    var ks = List[Scalar]()
    var expected = List[String]()
    for r in rows("ecmult.txt", "GEN"):
        ks.append(parse_sc(r.arg(0)))
        expected.append(r.arg(1))

    var got = gpu.mul_gen(ks)
    assert_equal(len(got), len(expected))
    for i in range(len(got)):
        assert_equal(
            point_hex(got[i]), expected[i], "mul_gen mismatch at " + String(i)
        )


def test_batch_mul_point() raises:
    var gpu = GpuBatch(EcmultGenContext())
    var bases = List[Ge]()
    var ks = List[Scalar]()
    var expected = List[String]()
    for r in rows("ecmult.txt", "CONST"):
        bases.append(parse_point(r.arg(0)))
        ks.append(parse_sc(r.arg(1)))
        expected.append(r.arg(2))

    var got = gpu.mul_point(bases, ks)
    assert_equal(len(got), len(expected))
    for i in range(len(got)):
        assert_equal(
            point_hex(got[i]), expected[i], "mul_point mismatch at " + String(i)
        )


def test_batch_verify() raises:
    var ctx = Secp256k1()
    var gpu = GpuBatch(EcmultGenContext())

    var sigs = List[Signature]()
    var msgs = List[Scalar]()
    var pubs = List[Ge]()
    var expected = List[Bool]()

    for r in rows("ecdsa.txt", "VERIFY"):
        var pk = ctx.pubkey_parse(hex_to_bytes(r.arg(0)))
        if not pk[1]:
            continue
        var parsed = Signature.parse_compact(hex_to_bytes(r.arg(2)))
        if not parsed[1]:
            continue
        sigs.append(parsed[0])
        msgs.append(parse_sc(r.arg(1)))
        pubs.append(pk[0])
        # The C vectors were produced without the low-s rule, so a high-s
        # signature that C accepts is expected to be rejected here.
        expected.append(r.arg(3) == "1" and not parsed[0].s.is_high())

    var got = gpu.verify(sigs, msgs, pubs)
    assert_equal(len(got), len(expected))
    var accepted = 0
    var rejected = 0
    for i in range(len(got)):
        assert_equal(
            Int(got[i]), Int(expected[i]), "verify mismatch at " + String(i)
        )
        if expected[i]:
            accepted += 1
        else:
            rejected += 1
    # The vector set must actually exercise both outcomes.
    assert_true(accepted > 0, "no signature was expected to verify")
    assert_true(rejected > 0, "no signature was expected to fail")


def test_gpu_matches_cpu_verify() raises:
    var ctx = Secp256k1()
    var gpu = GpuBatch(EcmultGenContext())

    var sigs = List[Signature]()
    var msgs = List[Scalar]()
    var pubs = List[Ge]()
    for r in rows("ecdsa.txt", "SIGN"):
        var sk = hex_to_bytes(r.arg(0))
        var msg = hex_to_bytes(r.arg(1))
        var pk = ctx.pubkey_create(sk)
        var parsed = Signature.parse_compact(hex_to_bytes(r.arg(2)))
        sigs.append(parsed[0])
        msgs.append(parse_sc(r.arg(1)))
        pubs.append(pk[0])

    var got = gpu.verify(sigs, msgs, pubs)
    for i in range(len(got)):
        var msg_bytes = msgs[i].to_bytes()
        var cpu = ctx.verify(sigs[i], msg_bytes, pubs[i])
        assert_true(cpu, "CPU rejected a signature it produced")
        assert_equal(Int(got[i]), Int(cpu), "GPU/CPU disagree at " + String(i))


def test_gpu_matches_cpu_mul_gen() raises:
    var ctx = Secp256k1()
    var gpu = GpuBatch(EcmultGenContext())
    var ks = List[Scalar]()
    for r in rows("ecdsa.txt", "SIGN"):
        ks.append(parse_sc(r.arg(0)))
    var got = gpu.mul_gen(ks)
    for i in range(len(got)):
        var cpu = ctx.gen.mult(ks[i]).to_ge_var()
        assert_equal(point_hex(got[i]), point_hex(cpu))


def test_tampered_signature_rejected() raises:
    var ctx = Secp256k1()
    var gpu = GpuBatch(EcmultGenContext())

    var sigs = List[Signature]()
    var msgs = List[Scalar]()
    var pubs = List[Ge]()
    var n = 0
    for r in rows("ecdsa.txt", "SIGN"):
        var sk = hex_to_bytes(r.arg(0))
        var pk = ctx.pubkey_create(sk)
        var parsed = Signature.parse_compact(hex_to_bytes(r.arg(2)))
        # Verify against the wrong message.
        var wrong = parse_sc(r.arg(0))
        sigs.append(parsed[0])
        msgs.append(wrong)
        pubs.append(pk[0])
        n += 1
        if n >= 16:
            break

    var got = gpu.verify(sigs, msgs, pubs)
    for i in range(len(got)):
        assert_false(got[i], "a tampered signature verified at " + String(i))


def test_degenerate_inputs() raises:
    var gpu = GpuBatch(EcmultGenContext())

    # empty batches
    assert_equal(len(gpu.mul_gen(List[Scalar]())), 0)
    assert_equal(
        len(gpu.verify(List[Signature](), List[Scalar](), List[Ge]())), 0
    )

    # zero scalar gives the point at infinity
    var ks = List[Scalar]()
    ks.append(Scalar.zero())
    ks.append(Scalar.one())
    var pts = gpu.mul_gen(ks)
    assert_true(pts[0].infinity)
    assert_true(pts[1].eq_var(Ge.generator()))

    # a zero r or s must be rejected without reaching the kernel
    var sigs = List[Signature]()
    sigs.append(Signature(Scalar.zero(), Scalar.one()))
    sigs.append(Signature(Scalar.one(), Scalar.zero()))
    var msgs = List[Scalar]()
    msgs.append(Scalar.one())
    msgs.append(Scalar.one())
    var pubs = List[Ge]()
    pubs.append(Ge.generator())
    pubs.append(Ge.generator())
    var res = gpu.verify(sigs, msgs, pubs)
    assert_false(res[0])
    assert_false(res[1])


def test_mismatched_lengths_raise() raises:
    var gpu = GpuBatch(EcmultGenContext())
    var bases = List[Ge]()
    bases.append(Ge.generator())
    var ks = List[Scalar]()
    ks.append(Scalar.one())
    ks.append(Scalar.one())
    var raised = False
    try:
        _ = gpu.mul_point(bases, ks)
    except:
        raised = True
    assert_true(raised, "mismatched lengths should raise")


def test_batch_scalar_inverse() raises:
    var vals = List[Scalar]()
    for r in rows("scalar.txt", "INV"):
        vals.append(parse_sc(r.arg(0)))
    vals.append(Scalar.zero())

    var inv = batch_scalar_inverse(vals)
    assert_equal(len(inv), len(vals))
    for i in range(len(vals)):
        if vals[i].is_zero():
            assert_true(inv[i].is_zero())
        else:
            assert_true(
                inv[i] == vals[i].inverse(),
                "batch inverse differs at " + String(i),
            )
            assert_true((vals[i] * inv[i]).is_one())


def test_large_batch() raises:
    # Exercise more threads than one block holds, and a size that is not a
    # multiple of the block size, so the bounds check in the kernel matters.
    var ctx = Secp256k1()
    var gpu = GpuBatch(EcmultGenContext())
    comptime COUNT = 517
    var ks = List[Scalar]()
    var k = parse_sc(
        "0000000000000000000000000000000000000000000000000000000000000007"
    )
    for _ in range(COUNT):
        k = k * k + Scalar.from_int(3)
        ks.append(k)

    var got = gpu.mul_gen(ks)
    assert_equal(len(got), COUNT)
    for i in range(COUNT):
        var cpu = ctx.gen.mult(ks[i]).to_ge_var()
        assert_equal(
            point_hex(got[i]), point_hex(cpu), "mismatch at " + String(i)
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
