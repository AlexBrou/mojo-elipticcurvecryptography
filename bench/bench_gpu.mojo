"""GPU batch throughput versus the single-threaded CPU path.

Reports operations per second, so the two can be compared directly. Each kernel
is warmed up first: the first launch pays for Metal shader compilation, which
is a one-time cost per process and would otherwise dominate.
"""

from std.time import perf_counter_ns

from secp256k1.api import Secp256k1
from secp256k1.ecdsa import Signature
from secp256k1.ecmult import EcmultGenContext
from secp256k1.group import Ge
from secp256k1.gpu import GpuBatch
from secp256k1.scalar import Scalar


def _pad(s: String, width: Int) -> String:
    var out = s
    while out.byte_length() < width:
        out += " "
    return out^


def _rate(count: Int, ns: Int) -> String:
    var per_sec = Float64(count) * 1.0e9 / Float64(ns)
    return _pad(String(Int(per_sec)), 14)


def _us(count: Int, ns: Int) -> String:
    var us = Float64(ns) / (1000.0 * Float64(count))
    var s = String(us)
    if s.byte_length() > 8:
        var t = String(s[byte=0:8])
        s = t^
    return _pad(s, 12)


def make_scalars(n: Int) -> List[Scalar]:
    var out = List[Scalar](capacity=n)
    var k = Scalar.from_int(7)
    for _ in range(n):
        k = k * k + Scalar.from_int(3)
        out.append(k)
    return out^


def main() raises:
    var ctx = Secp256k1()
    var gpu = GpuBatch(EcmultGenContext())
    print("GPU:", gpu.device_name())
    print()
    print(
        _pad("Workload", 34)
        + _pad("Batch", 8)
        + _pad("ops/sec", 14)
        + _pad("us/op", 12)
    )
    print()

    # ---- warm up both kernels (pays the Metal compile cost once)
    var warm = make_scalars(8)
    _ = gpu.mul_gen(warm)
    var wpts = List[Ge]()
    for _ in range(8):
        wpts.append(Ge.generator())
    _ = gpu.mul_point(wpts, warm)

    # ---- CPU baseline: k*G
    # Best of several rounds, matching how bench.mojo reports: a single
    # untimed-warm-up-free pass over a cold table reads about 2x slow.
    var cpu_ks = make_scalars(200)
    var acc = 0
    var cpu_ns = 0
    for round in range(6):
        var t0 = perf_counter_ns()
        for i in range(len(cpu_ks)):
            acc += Int(ctx.gen.mult(cpu_ks[i]).z.normalized().n0)
        var ns = perf_counter_ns() - t0
        if round == 0 or ns < cpu_ns:
            cpu_ns = ns
    print(
        _pad("k*G  (CPU, 1 thread)", 34)
        + _pad("-", 8)
        + _rate(len(cpu_ks), cpu_ns)
        + _us(len(cpu_ks), cpu_ns)
    )

    for size in [256, 4096, 32768]:
        var ks = make_scalars(size)
        var g0 = perf_counter_ns()
        var pts = gpu.mul_gen(ks)
        var g_ns = perf_counter_ns() - g0
        acc += len(pts)
        print(
            _pad("k*G  (GPU batch)", 34)
            + _pad(String(size), 8)
            + _rate(size, g_ns)
            + _us(size, g_ns)
        )
    print()

    # ---- CPU baseline: ECDSA verify
    var sk = List[UInt8]()
    for i in range(32):
        sk.append(UInt8(1 + i * 7))
    var msg = List[UInt8]()
    for i in range(32):
        msg.append(UInt8(200 - i * 3))
    var pk = ctx.pubkey_create(sk)[0]
    var signed = ctx.sign(msg, sk)
    var sig = signed[0]
    var msg_sc = Scalar.from_bytes(msg)[0]

    comptime CPU_VERIFY = 200
    for round in range(6):
        var t0 = perf_counter_ns()
        for _ in range(CPU_VERIFY):
            acc += Int(ctx.verify(sig, msg, pk))
        var ns = perf_counter_ns() - t0
        if round == 0 or ns < cpu_ns:
            cpu_ns = ns
    print(
        _pad("ecdsa_verify (CPU, 1 thread)", 34)
        + _pad("-", 8)
        + _rate(CPU_VERIFY, cpu_ns)
        + _us(CPU_VERIFY, cpu_ns)
    )

    for size in [256, 4096, 16384]:
        var sigs = List[Signature](capacity=size)
        var msgs = List[Scalar](capacity=size)
        var pubs = List[Ge](capacity=size)
        for _ in range(size):
            sigs.append(sig)
            msgs.append(msg_sc)
            pubs.append(pk)
        var g0 = perf_counter_ns()
        var res = gpu.verify(sigs, msgs, pubs)
        var g_ns = perf_counter_ns() - g0
        var okc = 0
        for i in range(len(res)):
            if res[i]:
                okc += 1
        if okc != size:
            raise Error("GPU verification disagreed with the CPU")
        acc += okc
        print(
            _pad("ecdsa_verify (GPU batch)", 34)
            + _pad(String(size), 8)
            + _rate(size, g_ns)
            + _us(size, g_ns)
        )

    print()
    print("(checksum", acc, ")")
