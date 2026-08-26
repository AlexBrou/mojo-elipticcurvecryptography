"""A native CPython extension module.

Unlike `ffi/capi.mojo`, which exposes a C ABI for any language to call, this
builds a real Python module: `import secp256k1_mojo` gives you a class with
methods, exceptions instead of return codes, and `bytes` in and out. No
`ctypes`, no `argtypes` declarations, nothing for the caller to get wrong.

Build it:

    mojo build --emit shared-lib -I src -I vendor/mojo-sha256/src \\
        -o secp256k1_mojo.so ffi/secp256k1_mojo.mojo

The file name, the module name, and the `PyInit_` suffix must all match, and
the `.so` has to be on `sys.path`.
"""

from std.os import abort
from std.python import Python, PythonObject
from std.python.bindings import PythonModuleBuilder

from secp256k1.api import Secp256k1
from secp256k1.ecdsa import Signature
from secp256k1.group import Ge
from secp256k1.scalar import Scalar


# ------------------------------------------------------------ conversions


def _to_bytes(obj: PythonObject) raises -> List[UInt8]:
    """A Python bytes-like object as a Mojo list."""
    var n = len(obj)
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(Int(py=obj[i])))
    return out^


def _from_bytes(data: List[UInt8]) raises -> PythonObject:
    """A Mojo byte list as a Python `bytes`."""
    var builtins = Python.import_module("builtins")
    var lst = Python.list()
    for i in range(len(data)):
        lst.append(PythonObject(Int(data[i])))
    return builtins.bytes(lst)


def _expect(obj: PythonObject, n: Int, what: String) raises -> List[UInt8]:
    var b = _to_bytes(obj)
    if len(b) != n:
        raise Error(what + " must be exactly " + String(n) + " bytes")
    return b^


# ----------------------------------------------------------------- module


struct Context(Defaultable, Movable, Writable):
    """`secp256k1_mojo.Context` — build one and reuse it.

    Construction precomputes the generator table, which costs about a thousand
    point operations, so it is not something to do per call.
    """

    var ctx: Secp256k1

    def __init__(out self):
        self.ctx = Secp256k1()

    # `add_type` requires Writable. Both methods are given explicitly because
    # the derived versions need every field to be Writable, and `Secp256k1`
    # (which holds a table of curve points) is not.
    def write_to(self, mut writer: Some[Writer]):
        writer.write("secp256k1_mojo.Context()")

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("secp256k1_mojo.Context()")

    @staticmethod
    def py_init(args: PythonObject, kwargs: PythonObject) raises -> Context:
        return Context()

    @staticmethod
    def public_key(
        self_ptr: Pointer[Self, MutAnyOrigin],
        seckey: PythonObject,
        compressed: PythonObject,
    ) raises -> PythonObject:
        var sk = _expect(seckey, 32, "secret key")
        var r = self_ptr[].ctx.pubkey_create(sk)
        if not r[1]:
            raise Error("invalid secret key")
        if Int(py=compressed) != 0:
            return _from_bytes(r[0].serialize33())
        return _from_bytes(r[0].serialize65())

    @staticmethod
    def sign(
        self_ptr: Pointer[Self, MutAnyOrigin],
        msg32: PythonObject,
        seckey: PythonObject,
    ) raises -> PythonObject:
        var m = _expect(msg32, 32, "message hash")
        var sk = _expect(seckey, 32, "secret key")
        var r = self_ptr[].ctx.sign(m, sk)
        if not r[2]:
            raise Error("signing failed: invalid secret key")
        return _from_bytes(r[0].serialize_compact())

    @staticmethod
    def sign_recoverable(
        self_ptr: Pointer[Self, MutAnyOrigin],
        msg32: PythonObject,
        seckey: PythonObject,
    ) raises -> PythonObject:
        """Returns `(signature, recovery_id)`."""
        var m = _expect(msg32, 32, "message hash")
        var sk = _expect(seckey, 32, "secret key")
        var r = self_ptr[].ctx.sign(m, sk)
        if not r[2]:
            raise Error("signing failed: invalid secret key")
        var tup = Python.list()
        tup.append(_from_bytes(r[0].serialize_compact()))
        tup.append(PythonObject(r[1]))
        return Python.import_module("builtins").tuple(tup)

    @staticmethod
    def verify(
        self_ptr: Pointer[Self, MutAnyOrigin],
        sig: PythonObject,
        msg32: PythonObject,
        pubkey: PythonObject,
    ) raises -> PythonObject:
        var s = _expect(sig, 64, "signature")
        var m = _expect(msg32, 32, "message hash")
        var pk = _to_bytes(pubkey)
        if len(pk) != 33 and len(pk) != 65:
            raise Error("public key must be 33 or 65 bytes")

        var parsed_pk = Ge.parse(pk)
        if not parsed_pk[1]:
            return PythonObject(False)
        var parsed_sig = Signature.parse_compact(s)
        if not parsed_sig[1]:
            return PythonObject(False)
        return PythonObject(
            self_ptr[].ctx.verify(parsed_sig[0], m, parsed_pk[0])
        )

    @staticmethod
    def recover(
        self_ptr: Pointer[Self, MutAnyOrigin],
        sig: PythonObject,
        recovery_id: PythonObject,
        msg32: PythonObject,
    ) raises -> PythonObject:
        var s = _expect(sig, 64, "signature")
        var m = _expect(msg32, 32, "message hash")
        var rid = Int(py=recovery_id)
        if rid < 0 or rid > 3:
            raise Error("recovery id must be 0..3")
        var parsed = Signature.parse_compact(s)
        if not parsed[1]:
            raise Error("malformed signature")
        var r = self_ptr[].ctx.recover(parsed[0], m, rid)
        if not r[1]:
            raise Error("recovery failed")
        return _from_bytes(r[0].serialize33())

    @staticmethod
    def shared_secret(
        self_ptr: Pointer[Self, MutAnyOrigin],
        pubkey: PythonObject,
        seckey: PythonObject,
    ) raises -> PythonObject:
        """The raw ECDH point, compressed. Hash it before using it as a key."""
        var pk = _to_bytes(pubkey)
        if len(pk) != 33 and len(pk) != 65:
            raise Error("public key must be 33 or 65 bytes")
        var sk = _expect(seckey, 32, "secret key")
        var parsed = Ge.parse(pk)
        if not parsed[1]:
            raise Error("malformed public key")
        var r = self_ptr[].ctx.ecdh_point(parsed[0], sk)
        if not r[1]:
            raise Error("ecdh failed")
        return _from_bytes(r[0].serialize33())

    @staticmethod
    def seckey_tweak_add(
        self_ptr: Pointer[Self, MutAnyOrigin],
        seckey: PythonObject,
        tweak: PythonObject,
    ) raises -> PythonObject:
        var sk = _expect(seckey, 32, "secret key")
        var tw = _expect(tweak, 32, "tweak")
        var r = self_ptr[].ctx.seckey_tweak_add(sk, tw)
        if not r[1]:
            raise Error("tweak produced an invalid key")
        return _from_bytes(r[0])

    @staticmethod
    def seckey_verify(
        self_ptr: Pointer[Self, MutAnyOrigin], seckey: PythonObject
    ) raises -> PythonObject:
        var sk = _to_bytes(seckey)
        if len(sk) != 32:
            return PythonObject(False)
        return PythonObject(self_ptr[].ctx.seckey_verify(sk))


@export
def PyInit_secp256k1_mojo() abi("C") -> PythonObject:
    try:
        var m = PythonModuleBuilder("secp256k1_mojo")
        _ = (
            m.add_type[Context]("Context")
            .def_py_init[Context.py_init]()
            .def_method[Context.public_key]("public_key")
            .def_method[Context.sign]("sign")
            .def_method[Context.sign_recoverable]("sign_recoverable")
            .def_method[Context.verify]("verify")
            .def_method[Context.recover]("recover")
            .def_method[Context.shared_secret]("shared_secret")
            .def_method[Context.seckey_tweak_add]("seckey_tweak_add")
            .def_method[Context.seckey_verify]("seckey_verify")
        )
        return m.finalize()
    except e:
        abort(String("failed to create secp256k1_mojo module: ", e))
