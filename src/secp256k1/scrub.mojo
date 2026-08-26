"""Explicitly wipe secrets from memory.

A plain `x = 0` on a value that is never read again is a dead store, and the
optimizer is free to delete it — which is exactly what happens to naive
attempts at scrubbing. These helpers write through a volatile store, which the
compiler must emit.

This mirrors `secp256k1_memclear_explicit` in libsecp256k1. It is defence in
depth: it does not protect a secret while it is in use, only shortens how long
a copy lingers in memory (or in a core dump, or in a page that later gets
swapped) after the caller is done with it.
"""


@always_inline
def scrub_u64(mut x: UInt64):
    Pointer(to=x).unsafe_store[volatile=True](0, UInt64(0))


@always_inline
def scrub_u32(mut x: UInt32):
    Pointer(to=x).unsafe_store[volatile=True](0, UInt32(0))


@always_inline
def scrub_u8(mut x: UInt8):
    Pointer(to=x).unsafe_store[volatile=True](0, UInt8(0))
