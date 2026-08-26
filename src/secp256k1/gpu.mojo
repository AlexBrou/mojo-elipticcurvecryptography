"""GPU batch operations.

Three kernels, each one thread per work item:

* `kernel_mul_gen`      — k*G, for bulk key derivation
* `kernel_mul_point`    — k*P, for bulk ECDH / point multiplication
* `kernel_verify`       — ECDSA verification

Kernels emit Jacobian points and never invert: the host finishes the batch with
a single field inversion (Montgomery's trick) for the whole set. Signature
verification avoids inversion entirely by comparing x*z^2 instead.

All of this is variable time and operates on public data. Secret-key work
belongs on the CPU path.
"""

from max.gpu.host import DeviceContext, DeviceBuffer
from std.gpu import global_idx

from .ecmult import EcmultGenContext
from .ecdsa import Signature
from .field import Fe
from .group import Ge, Gej, set_all_gej_var
from .gpu32 import (
    FeGpu,
    GeGpu,
    GejGpu,
    ScalarBits,
    mul_gen,
    mul_point,
    mul_point_split,
    GEN_BLOCKS,
    GEN_ENTRIES,
    GEN_ENTRY_WORDS,
    GEN_TABLE_WORDS,
)
from .scalar import Scalar

comptime SCALAR_WORDS = 8
comptime AFFINE_WORDS = 16
comptime JACOBIAN_WORDS = 24


# --------------------------------------------------------------- kernel I/O


@always_inline
def _load_scalar(p: Pointer[UInt32, MutAnyOrigin], i: Int) -> ScalarBits:
    var base = i * SCALAR_WORDS
    var d = InlineArray[UInt32, 8](fill=0)
    for j in range(8):
        d[j] = p[unsafe_offset=base + j]
    return ScalarBits(d^)


@always_inline
def _load_fe(p: Pointer[UInt32, MutAnyOrigin], base: Int) -> FeGpu:
    var d = InlineArray[UInt32, 8](fill=0)
    for j in range(8):
        d[j] = p[unsafe_offset=base + j]
    return FeGpu(d^)


@always_inline
def _load_affine(p: Pointer[UInt32, MutAnyOrigin], i: Int) -> GeGpu:
    var base = i * AFFINE_WORDS
    return GeGpu(_load_fe(p, base), _load_fe(p, base + 8), False)


@always_inline
def _store_fe(p: Pointer[UInt32, MutAnyOrigin], base: Int, v: FeGpu):
    for j in range(8):
        p[unsafe_offset=base + j] = v.n[j]


@always_inline
def _store_jacobian(p: Pointer[UInt32, MutAnyOrigin], i: Int, v: GejGpu):
    """Store x, y, z. A zero z marks the point at infinity."""
    var base = i * JACOBIAN_WORDS
    if v.infinity:
        for j in range(JACOBIAN_WORDS):
            p[unsafe_offset=base + j] = 0
        return
    _store_fe(p, base, v.x)
    _store_fe(p, base + 8, v.y)
    _store_fe(p, base + 16, v.z)


# ------------------------------------------------------------------ kernels


def kernel_mul_gen(
    table: Pointer[UInt32, MutAnyOrigin],
    scalars: Pointer[UInt32, MutAnyOrigin],
    points: Pointer[UInt32, MutAnyOrigin],
    n: Int64,
):
    var i = global_idx.x
    if Int64(i) >= n:
        return
    _store_jacobian(points, i, mul_gen(table, _load_scalar(scalars, i)))


def kernel_mul_point(
    bases: Pointer[UInt32, MutAnyOrigin],
    k1s: Pointer[UInt32, MutAnyOrigin],
    k2s: Pointer[UInt32, MutAnyOrigin],
    flags: Pointer[UInt32, MutAnyOrigin],
    points: Pointer[UInt32, MutAnyOrigin],
    n: Int64,
):
    var i = global_idx.x
    if Int64(i) >= n:
        return
    var f = flags[unsafe_offset=i]
    _store_jacobian(
        points,
        i,
        mul_point_split(
            _load_affine(bases, i),
            _load_scalar(k1s, i),
            _load_scalar(k2s, i),
            (f & 1) != 0,
            (f & 2) != 0,
        ),
    )


@always_inline
def _order_fe() -> FeGpu:
    var d: InlineArray[UInt32, 8] = [
        0xD0364141,
        0xBFD25E8C,
        0xAF48A03B,
        0xBAAEDCE6,
        0xFFFFFFFE,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    ]
    return FeGpu(d^)


@always_inline
def _p_minus_order_fe() -> FeGpu:
    var d: InlineArray[UInt32, 8] = [
        0x2FC9BAEE,
        0x402DA172,
        0x50B75FC4,
        0x45512319,
        1,
        0,
        0,
        0,
    ]
    return FeGpu(d^)


def kernel_verify(
    table: Pointer[UInt32, MutAnyOrigin],
    pubkeys: Pointer[UInt32, MutAnyOrigin],
    u1s: Pointer[UInt32, MutAnyOrigin],
    k1s: Pointer[UInt32, MutAnyOrigin],
    k2s: Pointer[UInt32, MutAnyOrigin],
    flags: Pointer[UInt32, MutAnyOrigin],
    sigrs: Pointer[UInt32, MutAnyOrigin],
    results: Pointer[UInt32, MutAnyOrigin],
    n: Int64,
):
    """Check that x(u2*P + u1*G) == r, working entirely in Jacobian form.

    The host has already reduced each signature to u1 = m/s and u2 = r/s, so
    the kernel needs no modular inversion.
    """
    var i = global_idx.x
    if Int64(i) >= n:
        return

    var pub = _load_affine(pubkeys, i)
    var u1 = _load_scalar(u1s, i)
    var f = flags[unsafe_offset=i]

    var pr = mul_point_split(
        pub,
        _load_scalar(k1s, i),
        _load_scalar(k2s, i),
        (f & 1) != 0,
        (f & 2) != 0,
    ).add(mul_gen(table, u1))
    if pr.infinity:
        results[unsafe_offset=i] = 0
        return

    var r = _load_fe(sigrs, i * SCALAR_WORDS)
    if pr.eq_x(r):
        results[unsafe_offset=i] = 1
        return

    # x could also be r + n, but only when that still fits below p.
    if r.cmp(_p_minus_order_fe()) >= 0:
        results[unsafe_offset=i] = 0
        return
    results[unsafe_offset=i] = 1 if pr.eq_x(r + _order_fe()) else 0


# ------------------------------------------------------------- host helpers


def _fe_to_words(a: Fe, mut out: List[UInt32]):
    """Append a field element as eight little-endian 32-bit limbs."""
    var t = a
    t.normalize()
    var b = t.to_bytes()
    for i in range(8):
        var base = 28 - 4 * i
        out.append(
            (UInt32(b[base]) << 24)
            | (UInt32(b[base + 1]) << 16)
            | (UInt32(b[base + 2]) << 8)
            | UInt32(b[base + 3])
        )


def _scalar_to_words(s: Scalar, mut out: List[UInt32]):
    var b = s.to_bytes()
    for i in range(8):
        var base = 28 - 4 * i
        out.append(
            (UInt32(b[base]) << 24)
            | (UInt32(b[base + 1]) << 16)
            | (UInt32(b[base + 2]) << 8)
            | UInt32(b[base + 3])
        )


def _split_scalar(
    k: Scalar,
    mut k1w: List[UInt32],
    mut k2w: List[UInt32],
    mut flags: List[UInt32],
):
    """GLV-split a scalar into two ~128-bit halves plus their sign bits.

    Doing this host-side keeps all scalar arithmetic on the CPU: the kernel
    only ever reads bits.
    """
    var parts = k.split_lambda()
    var neg1 = parts[0].is_high()
    var neg2 = parts[1].is_high()
    _scalar_to_words(parts[0].cond_negate(neg1), k1w)
    _scalar_to_words(parts[1].cond_negate(neg2), k2w)
    flags.append(UInt32(neg1) | (UInt32(neg2) << 1))


def _fe_from_words(w: List[UInt32], base: Int) raises -> Fe:
    var b = List[UInt8](capacity=32)
    for i in range(8):
        var v = w[base + 7 - i]
        b.append(UInt8(v >> 24))
        b.append(UInt8((v >> 16) & 0xFF))
        b.append(UInt8((v >> 8) & 0xFF))
        b.append(UInt8(v & 0xFF))
    return Fe.from_bytes_mod(b)


def serialize_gen_table(ctx: EcmultGenContext) -> List[UInt32]:
    """Flatten the comb table into the uint32 layout the kernels expect."""
    var out = List[UInt32](capacity=GEN_TABLE_WORDS)
    for i in range(GEN_BLOCKS * GEN_ENTRIES):
        var e = ctx.table[i]
        if e.infinity:
            for _ in range(GEN_ENTRY_WORDS):
                out.append(0)
        else:
            _fe_to_words(e.x, out)
            _fe_to_words(e.y, out)
    return out^


struct GpuBatch(Movable):
    """Holds the device context and the generator table uploaded to the GPU.

    Build one and reuse it: uploading the table is the expensive part.
    """

    var dev: DeviceContext
    var table: DeviceBuffer[DType.uint32]
    var block_size: Int

    def __init__(out self, gen: EcmultGenContext) raises:
        self.dev = DeviceContext()
        # 32 measured fastest on an Apple M2; the kernels are register-hungry,
        # so larger blocks lose occupancy. Above 256 Metal quietly declines to
        # run the kernel at all, which `_self_test` below catches.
        self.block_size = 32
        var words = serialize_gen_table(gen)
        var host = self.dev.enqueue_create_host_buffer[DType.uint32](
            GEN_TABLE_WORDS
        )
        self.dev.synchronize()
        for i in range(GEN_TABLE_WORDS):
            host[i] = words[i]
        self.table = self.dev.enqueue_create_buffer[DType.uint32](
            GEN_TABLE_WORDS
        )
        self.dev.enqueue_copy(dst_buf=self.table, src_buf=host)
        self.dev.synchronize()
        self._self_test()

    def device_name(mut self) raises -> String:
        return self.dev.name()

    def _self_test(mut self) raises:
        """Known-answer check that the kernels actually ran.

        A kernel whose launch configuration exceeds what the device can host is
        skipped *silently* by Metal, leaving the output buffer zeroed — which
        reads as "every signature is invalid". Checking 1*G == G at construction
        turns that into an error instead of a wrong answer.
        """
        var ks = List[Scalar]()
        ks.append(Scalar.one())
        var pts = self.mul_gen(ks)
        if len(pts) != 1 or not pts[0].eq_var(Ge.generator()):
            raise Error(
                "GPU self-test failed: the kernel did not produce 1*G. The"
                " launch configuration (block_size="
                + String(self.block_size)
                + ") is probably too large for this device."
            )

    def _upload(
        mut self, words: List[UInt32]
    ) raises -> DeviceBuffer[DType.uint32]:
        var n = len(words)
        var host = self.dev.enqueue_create_host_buffer[DType.uint32](n)
        self.dev.synchronize()
        for i in range(n):
            host[i] = words[i]
        var dev = self.dev.enqueue_create_buffer[DType.uint32](n)
        self.dev.enqueue_copy(dst_buf=dev, src_buf=host)
        return dev^

    def _download(
        mut self, buf: DeviceBuffer[DType.uint32], n: Int
    ) raises -> List[UInt32]:
        var host = self.dev.enqueue_create_host_buffer[DType.uint32](n)
        self.dev.enqueue_copy(dst_buf=host, src_buf=buf)
        self.dev.synchronize()
        var out = List[UInt32](capacity=n)
        for i in range(n):
            out.append(host[i])
        return out^

    def _grid(self, n: Int) -> Int:
        return (n + self.block_size - 1) // self.block_size

    def _to_affine(mut self, words: List[UInt32], n: Int) raises -> List[Ge]:
        """Convert the kernel's Jacobian output with one batched inversion."""
        var jac = List[Gej](capacity=n)
        for i in range(n):
            var base = i * JACOBIAN_WORDS
            var z = _fe_from_words(words, base + 16)
            if z.normalized().is_zero_norm():
                jac.append(Gej.infinity_point())
            else:
                jac.append(
                    Gej(
                        _fe_from_words(words, base),
                        _fe_from_words(words, base + 8),
                        z,
                        False,
                    )
                )
        return set_all_gej_var(jac)

    # ------------------------------------------------------------ operations

    def mul_gen(mut self, scalars: List[Scalar]) raises -> List[Ge]:
        """k*G for every scalar in the batch."""
        var n = len(scalars)
        if n == 0:
            return List[Ge]()
        var words = List[UInt32](capacity=n * SCALAR_WORDS)
        for i in range(n):
            _scalar_to_words(scalars[i], words)
        var d_scalars = self._upload(words)
        var d_points = self.dev.enqueue_create_buffer[DType.uint32](
            n * JACOBIAN_WORDS
        )
        self.dev.enqueue_function[kernel_mul_gen](
            self.table.unsafe_ptr(),
            d_scalars.unsafe_ptr(),
            d_points.unsafe_ptr(),
            Int64(n),
            grid_dim=self._grid(n),
            block_dim=self.block_size,
        )
        var out = self._download(d_points, n * JACOBIAN_WORDS)
        return self._to_affine(out, n)

    def mul_point(
        mut self, bases: List[Ge], scalars: List[Scalar]
    ) raises -> List[Ge]:
        """k*P for every (point, scalar) pair in the batch."""
        var n = len(scalars)
        if n != len(bases):
            raise Error("bases and scalars must have the same length")
        if n == 0:
            return List[Ge]()

        var bwords = List[UInt32](capacity=n * AFFINE_WORDS)
        for i in range(n):
            if bases[i].infinity:
                raise Error("cannot multiply the point at infinity")
            _fe_to_words(bases[i].x, bwords)
            _fe_to_words(bases[i].y, bwords)
        var k1w = List[UInt32](capacity=n * SCALAR_WORDS)
        var k2w = List[UInt32](capacity=n * SCALAR_WORDS)
        var flags = List[UInt32](capacity=n)
        for i in range(n):
            _split_scalar(scalars[i], k1w, k2w, flags)

        var d_bases = self._upload(bwords)
        var d_k1 = self._upload(k1w)
        var d_k2 = self._upload(k2w)
        var d_flags = self._upload(flags)
        var d_points = self.dev.enqueue_create_buffer[DType.uint32](
            n * JACOBIAN_WORDS
        )
        self.dev.enqueue_function[kernel_mul_point](
            d_bases.unsafe_ptr(),
            d_k1.unsafe_ptr(),
            d_k2.unsafe_ptr(),
            d_flags.unsafe_ptr(),
            d_points.unsafe_ptr(),
            Int64(n),
            grid_dim=self._grid(n),
            block_dim=self.block_size,
        )
        var out = self._download(d_points, n * JACOBIAN_WORDS)
        return self._to_affine(out, n)

    def verify(
        mut self,
        sigs: List[Signature],
        msgs: List[Scalar],
        pubkeys: List[Ge],
    ) raises -> List[Bool]:
        """Verify a batch of signatures.

        The per-signature inversion 1/s is done here, for the whole batch at
        once, so the kernel only has to do the two scalar multiplications.
        Signatures with high s are rejected, matching the CPU `verify`.
        """
        var n = len(sigs)
        if n != len(msgs) or n != len(pubkeys):
            raise Error("sigs, msgs and pubkeys must have the same length")
        if n == 0:
            return List[Bool]()

        # Reject the malformed ones up front; they never reach the GPU.
        var valid = List[Bool](capacity=n)
        var to_invert = List[Scalar](capacity=n)
        for i in range(n):
            var ok = (
                not sigs[i].r.is_zero()
                and not sigs[i].s.is_zero()
                and not sigs[i].s.is_high()
                and not pubkeys[i].infinity
            )
            valid.append(ok)
            to_invert.append(sigs[i].s if ok else Scalar.one())

        var sinv = batch_scalar_inverse(to_invert)

        var pwords = List[UInt32](capacity=n * AFFINE_WORDS)
        var u1words = List[UInt32](capacity=n * SCALAR_WORDS)
        var k1w = List[UInt32](capacity=n * SCALAR_WORDS)
        var k2w = List[UInt32](capacity=n * SCALAR_WORDS)
        var flags = List[UInt32](capacity=n)
        var rwords = List[UInt32](capacity=n * SCALAR_WORDS)
        var g = Ge.generator()
        for i in range(n):
            var pk = pubkeys[i] if valid[i] else g
            _fe_to_words(pk.x, pwords)
            _fe_to_words(pk.y, pwords)
            _scalar_to_words(sinv[i] * msgs[i], u1words)
            _split_scalar(sinv[i] * sigs[i].r, k1w, k2w, flags)
            _scalar_to_words(sigs[i].r, rwords)

        var d_pub = self._upload(pwords)
        var d_u1 = self._upload(u1words)
        var d_k1 = self._upload(k1w)
        var d_k2 = self._upload(k2w)
        var d_flags = self._upload(flags)
        var d_r = self._upload(rwords)
        var d_res = self.dev.enqueue_create_buffer[DType.uint32](n)

        self.dev.enqueue_function[kernel_verify](
            self.table.unsafe_ptr(),
            d_pub.unsafe_ptr(),
            d_u1.unsafe_ptr(),
            d_k1.unsafe_ptr(),
            d_k2.unsafe_ptr(),
            d_flags.unsafe_ptr(),
            d_r.unsafe_ptr(),
            d_res.unsafe_ptr(),
            Int64(n),
            grid_dim=self._grid(n),
            block_dim=self.block_size,
        )

        var res = self._download(d_res, n)
        var out = List[Bool](capacity=n)
        for i in range(n):
            out.append(valid[i] and res[i] == 1)
        return out^


def batch_scalar_inverse(values: List[Scalar]) -> List[Scalar]:
    """Invert a whole list with a single inversion (Montgomery's trick).

    Costs one inversion plus three multiplications per element instead of one
    inversion each. Zeros invert to zero and are skipped.
    """
    var n = len(values)
    var prefix = List[Scalar](capacity=n)
    var acc = Scalar.one()
    var any = False
    for i in range(n):
        prefix.append(acc)
        if not values[i].is_zero():
            acc = acc * values[i]
            any = True

    var out = List[Scalar](capacity=n)
    for _ in range(n):
        out.append(Scalar.zero())
    if not any:
        return out^

    var inv = acc.inverse_var()
    for i in range(n - 1, -1, -1):
        if values[i].is_zero():
            continue
        out[i] = prefix[i] * inv
        inv = inv * values[i]
    return out^
