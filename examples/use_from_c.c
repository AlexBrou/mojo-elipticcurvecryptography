/* Uses the Mojo library from C, and cross-checks every result against
 * libsecp256k1 so the example doubles as an interop test.
 *
 * Build with examples/build_and_run.sh.
 */
#include <stdio.h>
#include <string.h>

#include "secp256k1_mojo.h"
#include "secp256k1.h"

static void hex(const char *label, const unsigned char *b, size_t n) {
    printf("%-22s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int fail = 0;
static void check(int cond, const char *what) {
    printf("  %-46s %s\n", what, cond ? "ok" : "FAILED");
    if (!cond) fail = 1;
}

int main(void) {
    unsigned char seckey[32], msg[32];
    for (int i = 0; i < 32; i++) {
        seckey[i] = (unsigned char)(1 + i * 7);
        msg[i] = (unsigned char)(200 - i * 3);
    }

    secp256k1_mojo_ctx mctx = secp256k1_mojo_context_create();
    secp256k1_context *cctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* --- public key ------------------------------------------------- */
    unsigned char mpub[33], cpub_buf[33];
    check(secp256k1_mojo_ec_pubkey_create(mctx, mpub, seckey) == 1,
          "mojo: derive public key");

    secp256k1_pubkey cpub;
    size_t len = 33;
    secp256k1_ec_pubkey_create(cctx, &cpub, seckey);
    secp256k1_ec_pubkey_serialize(cctx, cpub_buf, &len, &cpub,
                                  SECP256K1_EC_COMPRESSED);
    hex("pubkey (mojo):", mpub, 33);
    check(memcmp(mpub, cpub_buf, 33) == 0, "matches libsecp256k1");

    /* --- sign -------------------------------------------------------- */
    unsigned char msig[64], csig_buf[64];
    check(secp256k1_mojo_ecdsa_sign(mctx, msig, msg, seckey) == 1,
          "mojo: sign");

    secp256k1_ecdsa_signature csig;
    secp256k1_ecdsa_sign(cctx, &csig, msg, seckey, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_compact(cctx, csig_buf, &csig);
    hex("signature (mojo):", msig, 64);
    check(memcmp(msig, csig_buf, 64) == 0,
          "byte-identical to libsecp256k1 (RFC 6979)");

    /* --- verify, both directions ------------------------------------- */
    check(secp256k1_mojo_ecdsa_verify(mctx, msig, msg, mpub, 33) == 1,
          "mojo verifies its own signature");
    check(secp256k1_ecdsa_verify(cctx, &csig, msg, &cpub) == 1,
          "libsecp256k1 verifies the mojo signature");

    secp256k1_ecdsa_signature parsed;
    secp256k1_ecdsa_signature_parse_compact(cctx, &parsed, msig);
    check(secp256k1_ecdsa_verify(cctx, &parsed, msg, &cpub) == 1,
          "C accepts the bytes mojo produced");

    unsigned char bad[64];
    memcpy(bad, msig, 64);
    bad[10] ^= 0x40;
    check(secp256k1_mojo_ecdsa_verify(mctx, bad, msg, mpub, 33) == 0,
          "mojo rejects a tampered signature");

    /* --- recovery ---------------------------------------------------- */
    unsigned char rsig[64], recovered[33];
    int recid = 0;
    check(secp256k1_mojo_ecdsa_sign_recoverable(mctx, rsig, &recid, msg,
                                                seckey) == 1,
          "mojo: recoverable sign");
    check(secp256k1_mojo_ecdsa_recover(mctx, recovered, rsig, recid, msg) == 1,
          "mojo: recover");
    check(memcmp(recovered, mpub, 33) == 0, "recovered key is the signer");

    /* --- ecdh -------------------------------------------------------- */
    unsigned char shared[33];
    check(secp256k1_mojo_ecdh(mctx, shared, mpub, 33, seckey) == 1,
          "mojo: ecdh");
    hex("ecdh point (mojo):", shared, 33);

    /* --- der --------------------------------------------------------- */
    unsigned char der[72], cder[72];
    int derlen = 0;
    size_t cderlen = 72;
    check(secp256k1_mojo_ecdsa_signature_to_der(mctx, der, &derlen, msig) == 1,
          "mojo: DER encode");
    secp256k1_ecdsa_signature_serialize_der(cctx, cder, &cderlen, &csig);
    check((size_t)derlen == cderlen && memcmp(der, cder, cderlen) == 0,
          "DER matches libsecp256k1");

    secp256k1_mojo_context_destroy(mctx);
    secp256k1_context_destroy(cctx);

    printf("\n%s\n", fail ? "SOME CHECKS FAILED" : "all checks passed");
    return fail;
}
