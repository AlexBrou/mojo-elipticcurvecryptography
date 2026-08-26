"""Benchmarks mirroring `bench` and `bench_internal` from libsecp256k1.

Timings are microseconds per operation, reported as min/avg/max over repeated
batches — the same shape the C benchmarks print, so the two can be compared
line by line.
"""

from std.time import perf_counter_ns

from secp256k1.api import Secp256k1
from secp256k1.ecmult import EcmultGenContext, ecmult, ecmult_const, ecmult_var
from secp256k1.field import Fe
from secp256k1.group import Ge, Gej
from secp256k1.scalar import Scalar

comptime ROUNDS = 10


struct Timer(Copyable, Movable):
    var best: Float64
    var worst: Float64
    var total: Float64
    var runs: Int

    def __init__(out self):
        self.best = 1.0e30
        self.worst = 0.0
        self.total = 0.0
        self.runs = 0

    def record(mut self, ns: Int, iters: Int):
        var us = Float64(ns) / (1000.0 * Float64(iters))
        if us < self.best:
            self.best = us
        if us > self.worst:
            self.worst = us
        self.total += us
        self.runs += 1

    def report(self, name: String):
        var avg = self.total / Float64(self.runs)
        print(_pad(name, 40) + _num(self.best) + _num(avg) + _num(self.worst))


def _pad(s: String, width: Int) -> String:
    var out = s
    while out.byte_length() < width:
        out += " "
    return out^


def _num(v: Float64) -> String:
    var s = String(v)
    if s.byte_length() > 9:
        var truncated = String(s[byte=0:9])
        s = truncated^
    return _pad(s, 14)


def header():
    print(
        _pad("Benchmark", 40)
        + _pad("Min(us)", 14)
        + _pad("Avg(us)", 14)
        + "Max(us)"
    )
    print()


def rnd32(seed: UInt64) -> List[UInt8]:
    """Deterministic pseudo-random 32 bytes (xorshift), for stable inputs."""
    var out = List[UInt8](capacity=32)
    var x = seed | 1
    for _ in range(4):
        x ^= x << 13
        x ^= x >> 7
        x ^= x << 17
        for j in range(8):
            out.append(UInt8((x >> UInt64(56 - 8 * j)) & 0xFF))
    return out^


def main() raises:
    header()

    # Every timed loop folds a byte of its result into `sink`, which is printed
    # at the end. Without that the optimizer deletes the loop bodies outright.
    var sink = 0

    var ctx = Secp256k1()

    var sk = rnd32(0x1234567)
    var msg = rnd32(0xABCDEF)
    var pk = ctx.pubkey_create(sk)[0]
    var sigres = ctx.sign(msg, sk)
    var sig = sigres[0]
    var recid = sigres[1]

    var a = Fe.from_bytes_mod(rnd32(0x9999))
    var b = Fe.from_bytes_mod(rnd32(0x8888))
    var sa = Scalar.from_bytes(rnd32(0x7777))[0]
    var sb = Scalar.from_bytes(rnd32(0x6666))[0]
    var pj = Gej.from_ge(pk)

    # ------------------------------------------------------------- high level
    var t_verify = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ctx.verify(sig, msg, pk))
        t_verify.record(perf_counter_ns() - t0, ITERS)
    t_verify.report("ecdsa_verify")

    var t_sign = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ctx.sign(msg, sk)[0].r.d0)
        t_sign.record(perf_counter_ns() - t0, ITERS)
    t_sign.report("ecdsa_sign")

    var t_keygen = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ctx.pubkey_create(sk)[0].x.normalized().n0)
        t_keygen.record(perf_counter_ns() - t0, ITERS)
    t_keygen.report("ec_keygen")

    var t_ecdh = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ctx.ecdh_point(pk, sk)[0].x.normalized().n0)
        t_ecdh.record(perf_counter_ns() - t0, ITERS)
    t_ecdh.report("ecdh")

    var t_recover = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ctx.recover(sig, msg, recid)[0].x.normalized().n0)
        t_recover.record(perf_counter_ns() - t0, ITERS)
    t_recover.report("ecdsa_recover")

    var t_ecmult = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 200
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ecmult(ctx.gen, pj, sa, sb).z.normalized().n0)
        t_ecmult.record(perf_counter_ns() - t0, ITERS)
    t_ecmult.report("ecmult (na*A + ng*G)")

    var t_ecmultvar = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 200
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ecmult_var(pj, sa).z.normalized().n0)
        t_ecmultvar.record(perf_counter_ns() - t0, ITERS)
    t_ecmultvar.report("ecmult_var (na*A)")

    var t_ecmultgen = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 200
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ctx.gen.mult(sa).z.normalized().n0)
        t_ecmultgen.record(perf_counter_ns() - t0, ITERS)
    t_ecmultgen.report("ecmult_gen (k*G, const time)")

    var t_ecmultconst = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 200
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += Int(ecmult_const(pk, sa).z.normalized().n0)
        t_ecmultconst.record(perf_counter_ns() - t0, ITERS)
    t_ecmultconst.report("ecmult_const (k*A, const time)")

    print()

    # --------------------------------------------------------------- internal
    var t_smul = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 200000
        var x = sa
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x * sb
        t_smul.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.d0)
    t_smul.report("scalar_mul")

    var t_sinv = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 20000
        var x = sa
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.inverse()
        t_sinv.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.d0)
    t_sinv.report("scalar_inverse")

    var t_sinvv = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 20000
        var x = sa
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.inverse_var()
        t_sinvv.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.d0)
    t_sinvv.report("scalar_inverse_var")

    var t_ssplit = Timer()
    var xsp = sa
    for _ in range(ROUNDS):
        comptime ITERS = 50000
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            xsp = xsp.split_lambda()[0] + sb
        t_ssplit.record(perf_counter_ns() - t0, ITERS)
        sink += Int(xsp.d0)
    t_ssplit.report("scalar_split")

    var t_fmul = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 500000
        var x = a
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x * b
        t_fmul.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.normalized().n0)
    t_fmul.report("field_mul")

    var t_fsqr = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 500000
        var x = a
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.sqr()
        t_fsqr.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.normalized().n0)
    t_fsqr.report("field_sqr")

    var t_finv = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 20000
        var x = a
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.inv()
        t_finv.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.normalized().n0)
    t_finv.report("field_inverse")

    var t_finvv = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 20000
        var x = a
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.inv_var()
        t_finvv.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.normalized().n0)
    t_finvv.report("field_inverse_var")

    var t_fsqrt = Timer()
    var xs = a
    for _ in range(ROUNDS):
        comptime ITERS = 300
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            # square first so a root always exists, then feed it back
            xs = xs.sqr().sqrt()[0]
        t_fsqrt.record(perf_counter_ns() - t0, ITERS)
        sink += Int(xs.normalized().n0)
    t_fsqrt.report("field_sqrt")

    var t_fnorm = Timer()
    var xn = a
    for _ in range(ROUNDS):
        comptime ITERS = 1000000
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            xn.normalize()
            xn = xn + b
        t_fnorm.record(perf_counter_ns() - t0, ITERS)
        sink += Int(xn.normalized().n0)
    t_fnorm.report("field_normalize")

    var t_gdbl = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 100000
        var x = pj
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.double()
        t_gdbl.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.z.normalized().n0)
    t_gdbl.report("group_double")

    var t_gaddvar = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50000
        var x = pj
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.add_var(pj)
        t_gaddvar.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.z.normalized().n0)
    t_gaddvar.report("group_add_var")

    # Two separate rows: `add_ge` is the constant-time mixed addition
    # (7M + 5S with conditional moves), `add_ge_var` the variable-time one
    # (8M + 3S). Reporting one against the other's C counterpart compares
    # different algorithms, which is what this benchmark used to do.
    var t_gaddge = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50000
        var x = pj
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.add_ge(pk)
        t_gaddge.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.z.normalized().n0)
    t_gaddge.report("group_add_affine")

    var t_gaddgevar = Timer()
    for _ in range(ROUNDS):
        comptime ITERS = 50000
        var x = pj
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            x = x.add_ge_var(pk)
        t_gaddgevar.record(perf_counter_ns() - t0, ITERS)
        sink += Int(x.z.normalized().n0)
    t_gaddgevar.report("group_add_affine_var")

    # Mirrors bench_group_to_affine_var in the C suite: feed the output
    # coordinates back into the input so the call cannot be hoisted, and so
    # the z being inverted actually varies. Inverting a z of 1 every time (what
    # a loop-invariant `Gej.from_ge(pk)` would give) is not representative --
    # safegcd converges immediately on it.
    var t_toaff = Timer()
    var jj = pj
    for _ in range(ROUNDS):
        comptime ITERS = 20000
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            var g = jj.to_ge_var()
            jj.x = jj.x + g.y
            jj.y = jj.y + b
            jj.z = g.x
        t_toaff.record(perf_counter_ns() - t0, ITERS)
        sink += Int(jj.x.normalized().n0)
    t_toaff.report("group_to_affine_var")

    # SHA-256 and HMAC are benchmarked in the mojo-sha256 repository, which
    # owns them now; measuring them again here would just track that project.

    var t_ctx = Timer()
    for _ in range(3):
        comptime ITERS = 3
        var t0 = perf_counter_ns()
        for _ in range(ITERS):
            sink += len(EcmultGenContext().table)
        t_ctx.record(perf_counter_ns() - t0, ITERS)
    t_ctx.report("context_create")

    print()
    print("(checksum", sink, "- ignore, it only keeps the loops alive)")
