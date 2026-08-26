// Calls the Mojo secp256k1 shared library from Node through koffi.
//
// Nothing here is Mojo-aware: the library exports plain C symbols, so this is
// the same FFI you would write against libsecp256k1 itself.
//
// Build the library first:
//   pixi run mojo build --emit shared-lib -I src -o libsecp256k1_mojo.dylib ffi/capi.mojo
// then either set LIBSECP256K1_MOJO, or leave it at the repository root.

import koffi from 'koffi';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

function libraryPath() {
  if (process.env.LIBSECP256K1_MOJO) return process.env.LIBSECP256K1_MOJO;
  const names = ['libsecp256k1_mojo.dylib', 'libsecp256k1_mojo.so'];
  const dirs = [here, join(here, '..'), join(here, '..', '..'), process.cwd()];
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  throw new Error(
    'could not find libsecp256k1_mojo; set LIBSECP256K1_MOJO to its path ' +
      '(build it with: pixi run mojo build --emit shared-lib -I src ' +
      '-o libsecp256k1_mojo.dylib ffi/capi.mojo)',
  );
}

const lib = koffi.load(libraryPath());

// koffi needs the C signatures spelled out. `_Out_` marks buffers the library
// writes into, so koffi copies the result back to the JS side.
const ctxCreate = lib.func('void *secp256k1_mojo_context_create()');
const ctxDestroy = lib.func('void secp256k1_mojo_context_destroy(void *ctx)');
const pubkeyCreate = lib.func(
  'int secp256k1_mojo_ec_pubkey_create(void *ctx, _Out_ uint8_t *out33, uint8_t *seckey32)',
);
const sign = lib.func(
  'int secp256k1_mojo_ecdsa_sign(void *ctx, _Out_ uint8_t *sig64, uint8_t *msg32, uint8_t *seckey32)',
);
const signRecoverable = lib.func(
  'int secp256k1_mojo_ecdsa_sign_recoverable(void *ctx, _Out_ uint8_t *sig64, _Out_ int *recid, uint8_t *msg32, uint8_t *seckey32)',
);
const verify = lib.func(
  'int secp256k1_mojo_ecdsa_verify(void *ctx, uint8_t *sig64, uint8_t *msg32, uint8_t *pubkey, int pubkeylen)',
);
const recover = lib.func(
  'int secp256k1_mojo_ecdsa_recover(void *ctx, _Out_ uint8_t *out33, uint8_t *sig64, int recid, uint8_t *msg32)',
);
const ecdh = lib.func(
  'int secp256k1_mojo_ecdh(void *ctx, _Out_ uint8_t *out33, uint8_t *pubkey, int pubkeylen, uint8_t *seckey32)',
);

/** A small idiomatic wrapper over the C ABI. */
export class Secp256k1 {
  #ctx;

  constructor() {
    this.#ctx = ctxCreate();
  }

  close() {
    if (this.#ctx) {
      ctxDestroy(this.#ctx);
      this.#ctx = null;
    }
  }

  publicKey(seckey) {
    const out = Buffer.alloc(33);
    if (!pubkeyCreate(this.#ctx, out, seckey)) throw new Error('invalid secret key');
    return out;
  }

  sign(msg32, seckey) {
    const out = Buffer.alloc(64);
    if (!sign(this.#ctx, out, msg32, seckey)) throw new Error('signing failed');
    return out;
  }

  signRecoverable(msg32, seckey) {
    const out = Buffer.alloc(64);
    const recid = [0];
    if (!signRecoverable(this.#ctx, out, recid, msg32, seckey)) {
      throw new Error('signing failed');
    }
    return { signature: out, recoveryId: recid[0] };
  }

  verify(sig64, msg32, pubkey) {
    return verify(this.#ctx, sig64, msg32, pubkey, pubkey.length) === 1;
  }

  recover(sig64, recoveryId, msg32) {
    const out = Buffer.alloc(33);
    if (!recover(this.#ctx, out, sig64, recoveryId, msg32)) {
      throw new Error('recovery failed');
    }
    return out;
  }

  sharedSecret(pubkey, seckey) {
    const out = Buffer.alloc(33);
    if (!ecdh(this.#ctx, out, pubkey, pubkey.length, seckey)) {
      throw new Error('ecdh failed');
    }
    return out;
  }
}

const seckey = Buffer.from(Array.from({ length: 32 }, (_, i) => (1 + i * 7) & 0xff));
const msg = Buffer.from(Array.from({ length: 32 }, (_, i) => (200 - i * 3) & 0xff));

const ctx = new Secp256k1();
try {
  const pub = ctx.publicKey(seckey);
  const sig = ctx.sign(msg, seckey);

  console.log('pubkey   ', pub.toString('hex'));
  console.log('signature', sig.toString('hex'));
  console.log('verify   ', ctx.verify(sig, msg, pub));

  const tampered = Buffer.from(msg);
  tampered[0] ^= 0xff;
  console.log('tampered ', ctx.verify(sig, tampered, pub));

  const { signature, recoveryId } = ctx.signRecoverable(msg, seckey);
  const recovered = ctx.recover(signature, recoveryId, msg);
  console.log('recovered', recovered.toString('hex'));

  console.log('ecdh     ', ctx.sharedSecret(pub, seckey).toString('hex'));

  if (!ctx.verify(sig, msg, pub)) throw new Error('valid signature rejected');
  if (ctx.verify(sig, tampered, pub)) throw new Error('tampered signature accepted');
  if (!recovered.equals(pub)) throw new Error('recovered the wrong key');
  console.log('\nall checks passed');
} finally {
  ctx.close();
}
