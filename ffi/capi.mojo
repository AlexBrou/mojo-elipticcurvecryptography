"""A C ABI for the library, so it can be used the way libsecp256k1 is.

Building this with `mojo build --emit shared-lib` produces an ordinary
`.dylib`/`.so` exporting plain C symbols, which anything that can call C —
C, C++, Rust, Go, Python via ctypes, Node via ffi — can link against. See
`include/secp256k1_mojo.h` for the declarations and `examples/` for callers.

Conventions follow libsecp256k1: every function returns 1 on success and 0 on
failure, buffers are caller-allocated, and a context is created once and reused
(it holds the precomputed generator table).
"""

from std.memory import Layout

from secp256k1.api import Secp256k1
from secp256k1.ecdsa import Signature
from secp256k1.group import Ge


comptime Handle = Pointer[NoneType, MutUntrackedOrigin]
comptime Bytes = Pointer[UInt8, MutUntrackedOrigin]


@always_inline
def _read(p: Bytes, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(p[unsafe_offset=i])
    return out^


@always_inline
def _write(p: Bytes, data: List[UInt8]):
    for i in range(len(data)):
        p[unsafe_offset=i] = data[i]


@always_inline
def _ctx(h: Handle) -> Pointer[Secp256k1, MutUntrackedOrigin]:
    return h.unsafe_bitcast[Secp256k1]()


# ----------------------------------------------------------------- context


@export
def secp256k1_mojo_context_create() abi("C") -> Handle:
    """Build a context. Costs about a thousand point operations, so create one
    and reuse it. Returns NULL-equivalent only if allocation fails."""
    # unsafe_leak() hands the raw pointer over: ownership crosses the ABI
    # boundary to the caller, who must return it to
    # secp256k1_mojo_context_destroy.
    var p = alloc[Secp256k1](Layout[Secp256k1](count=1)).unsafe_leak()
    p.unsafe_write(Secp256k1())
    return p.unsafe_bitcast[NoneType]()


@export
def secp256k1_mojo_context_destroy(h: Handle) abi("C"):
    var p = _ctx(h)
    p.unsafe_deinit_pointee()
    p.unsafe_free()


# -------------------------------------------------------------------- keys


@export
def secp256k1_mojo_ec_seckey_verify(
    h: Handle, seckey32: Bytes
) abi("C") -> Int32:
    try:
        return 1 if _ctx(h)[].seckey_verify(_read(seckey32, 32)) else 0
    except:
        return 0


@export
def secp256k1_mojo_ec_pubkey_create(
    h: Handle, out33: Bytes, seckey32: Bytes
) abi("C") -> Int32:
    """Write the 33-byte compressed public key for `seckey32`."""
    try:
        var r = _ctx(h)[].pubkey_create(_read(seckey32, 32))
        if not r[1]:
            return 0
        _write(out33, r[0].serialize33())
        return 1
    except:
        return 0


@export
def secp256k1_mojo_ec_pubkey_create_uncompressed(
    h: Handle, out65: Bytes, seckey32: Bytes
) abi("C") -> Int32:
    try:
        var r = _ctx(h)[].pubkey_create(_read(seckey32, 32))
        if not r[1]:
            return 0
        _write(out65, r[0].serialize65())
        return 1
    except:
        return 0


@export
def secp256k1_mojo_ec_pubkey_parse(
    h: Handle, out65: Bytes, pubkey: Bytes, pubkeylen: Int32
) abi("C") -> Int32:
    """Parse a 33- or 65-byte public key and re-emit it uncompressed."""
    var n = Int(pubkeylen)
    if n != 33 and n != 65:
        return 0
    var r = Ge.parse(_read(pubkey, n))
    if not r[1]:
        return 0
    _write(out65, r[0].serialize65())
    return 1


# ------------------------------------------------------------------- ecdsa


@export
def secp256k1_mojo_ecdsa_sign(
    h: Handle, out_sig64: Bytes, msg32: Bytes, seckey32: Bytes
) abi("C") -> Int32:
    """Deterministic (RFC 6979) signature, written as 64 bytes of r||s."""
    try:
        var r = _ctx(h)[].sign(_read(msg32, 32), _read(seckey32, 32))
        if not r[2]:
            return 0
        _write(out_sig64, r[0].serialize_compact())
        return 1
    except:
        return 0


@export
def secp256k1_mojo_ecdsa_sign_recoverable(
    h: Handle,
    out_sig64: Bytes,
    out_recid: Pointer[Int32, MutUntrackedOrigin],
    msg32: Bytes,
    seckey32: Bytes,
) abi("C") -> Int32:
    try:
        var r = _ctx(h)[].sign(_read(msg32, 32), _read(seckey32, 32))
        if not r[2]:
            return 0
        _write(out_sig64, r[0].serialize_compact())
        out_recid[] = Int32(r[1])
        return 1
    except:
        return 0


@export
def secp256k1_mojo_ecdsa_verify(
    h: Handle, sig64: Bytes, msg32: Bytes, pubkey: Bytes, pubkeylen: Int32
) abi("C") -> Int32:
    """Verify r||s against a 33- or 65-byte public key.

    Signatures with high s are rejected, matching libsecp256k1.
    """
    var n = Int(pubkeylen)
    if n != 33 and n != 65:
        return 0
    try:
        var pk = Ge.parse(_read(pubkey, n))
        if not pk[1]:
            return 0
        var sig = Signature.parse_compact(_read(sig64, 64))
        if not sig[1]:
            return 0
        return 1 if _ctx(h)[].verify(sig[0], _read(msg32, 32), pk[0]) else 0
    except:
        return 0


@export
def secp256k1_mojo_ecdsa_recover(
    h: Handle, out33: Bytes, sig64: Bytes, recid: Int32, msg32: Bytes
) abi("C") -> Int32:
    try:
        var sig = Signature.parse_compact(_read(sig64, 64))
        if not sig[1]:
            return 0
        var r = _ctx(h)[].recover(sig[0], _read(msg32, 32), Int(recid))
        if not r[1]:
            return 0
        _write(out33, r[0].serialize33())
        return 1
    except:
        return 0


@export
def secp256k1_mojo_ecdsa_signature_to_der(
    h: Handle,
    out_der: Bytes,
    out_len: Pointer[Int32, MutUntrackedOrigin],
    sig64: Bytes,
) abi("C") -> Int32:
    """DER-encode r||s. `out_der` must have room for 72 bytes."""
    try:
        var sig = Signature.parse_compact(_read(sig64, 64))
        if not sig[1]:
            return 0
        var der = sig[0].serialize_der()
        _write(out_der, der)
        out_len[] = Int32(len(der))
        return 1
    except:
        return 0


# -------------------------------------------------------------------- ecdh


@export
def secp256k1_mojo_ecdh(
    h: Handle, out33: Bytes, pubkey: Bytes, pubkeylen: Int32, seckey32: Bytes
) abi("C") -> Int32:
    """The shared point seckey*pubkey, compressed. Hash it before use as a key.
    """
    var n = Int(pubkeylen)
    if n != 33 and n != 65:
        return 0
    try:
        var pk = Ge.parse(_read(pubkey, n))
        if not pk[1]:
            return 0
        var r = _ctx(h)[].ecdh_point(pk[0], _read(seckey32, 32))
        if not r[1]:
            return 0
        _write(out33, r[0].serialize33())
        return 1
    except:
        return 0


# ------------------------------------------------------------------ tweaks


@export
def secp256k1_mojo_ec_seckey_tweak_add(
    h: Handle, seckey32: Bytes, tweak32: Bytes
) abi("C") -> Int32:
    """Tweak in place: seckey = (seckey + tweak) mod n."""
    try:
        var r = _ctx(h)[].seckey_tweak_add(
            _read(seckey32, 32), _read(tweak32, 32)
        )
        if not r[1]:
            return 0
        _write(seckey32, r[0])
        return 1
    except:
        return 0


@export
def secp256k1_mojo_ec_seckey_tweak_mul(
    h: Handle, seckey32: Bytes, tweak32: Bytes
) abi("C") -> Int32:
    try:
        var r = _ctx(h)[].seckey_tweak_mul(
            _read(seckey32, 32), _read(tweak32, 32)
        )
        if not r[1]:
            return 0
        _write(seckey32, r[0])
        return 1
    except:
        return 0
