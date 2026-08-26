/* C API for the Mojo secp256k1 implementation.
 *
 * Build the library with:
 *   mojo build --emit shared-lib -I src -o libsecp256k1_mojo.dylib ffi/capi.mojo
 *
 * Conventions follow libsecp256k1: every function returns 1 on success and 0
 * on failure, all buffers are caller-allocated, and the context is created
 * once and reused (it holds the precomputed generator table).
 *
 * The context is NOT thread-safe for concurrent mutation, but it is only read
 * after construction, so sharing one across threads for signing and verifying
 * is fine.
 */
#ifndef SECP256K1_MOJO_H
#define SECP256K1_MOJO_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void *secp256k1_mojo_ctx;

secp256k1_mojo_ctx secp256k1_mojo_context_create(void);
void secp256k1_mojo_context_destroy(secp256k1_mojo_ctx ctx);

/* keys */
int secp256k1_mojo_ec_seckey_verify(secp256k1_mojo_ctx ctx,
                                    const unsigned char *seckey32);
int secp256k1_mojo_ec_pubkey_create(secp256k1_mojo_ctx ctx,
                                    unsigned char *out33,
                                    const unsigned char *seckey32);
int secp256k1_mojo_ec_pubkey_create_uncompressed(secp256k1_mojo_ctx ctx,
                                                 unsigned char *out65,
                                                 const unsigned char *seckey32);
int secp256k1_mojo_ec_pubkey_parse(secp256k1_mojo_ctx ctx,
                                   unsigned char *out65,
                                   const unsigned char *pubkey,
                                   int pubkeylen);

/* ecdsa */
int secp256k1_mojo_ecdsa_sign(secp256k1_mojo_ctx ctx, unsigned char *out_sig64,
                              const unsigned char *msg32,
                              const unsigned char *seckey32);
int secp256k1_mojo_ecdsa_sign_recoverable(secp256k1_mojo_ctx ctx,
                                          unsigned char *out_sig64,
                                          int *out_recid,
                                          const unsigned char *msg32,
                                          const unsigned char *seckey32);
int secp256k1_mojo_ecdsa_verify(secp256k1_mojo_ctx ctx,
                                const unsigned char *sig64,
                                const unsigned char *msg32,
                                const unsigned char *pubkey, int pubkeylen);
int secp256k1_mojo_ecdsa_recover(secp256k1_mojo_ctx ctx, unsigned char *out33,
                                 const unsigned char *sig64, int recid,
                                 const unsigned char *msg32);
/* out_der needs room for 72 bytes */
int secp256k1_mojo_ecdsa_signature_to_der(secp256k1_mojo_ctx ctx,
                                          unsigned char *out_der, int *out_len,
                                          const unsigned char *sig64);

/* ecdh: the raw shared point, compressed. Hash it before using it as a key. */
int secp256k1_mojo_ecdh(secp256k1_mojo_ctx ctx, unsigned char *out33,
                        const unsigned char *pubkey, int pubkeylen,
                        const unsigned char *seckey32);

/* tweaks, applied in place to seckey32 */
int secp256k1_mojo_ec_seckey_tweak_add(secp256k1_mojo_ctx ctx,
                                       unsigned char *seckey32,
                                       const unsigned char *tweak32);
int secp256k1_mojo_ec_seckey_tweak_mul(secp256k1_mojo_ctx ctx,
                                       unsigned char *seckey32,
                                       const unsigned char *tweak32);

#ifdef __cplusplus
}
#endif
#endif /* SECP256K1_MOJO_H */
