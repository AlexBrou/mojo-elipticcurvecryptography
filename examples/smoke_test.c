/* A known-answer check that depends only on libsecp256k1_mojo.
 *
 * The runtime image ships no interpreter and no reference library, so this is
 * what proves the shared library in that image actually works. The expected
 * values were produced by libsecp256k1 and are verified against it by
 * examples/use_from_c.c.
 */
#include <stdio.h>
#include <string.h>

#include "secp256k1_mojo.h"

static const char *EXPECTED_PUBKEY =
    "03b37e346e416155b2b0fa289e09ca1f70a2c6fed7da70a9080520219f161050c1";
static const char *EXPECTED_SIG =
    "6b4ddacee09071e5c278ec2ee20e27fff504a8f59fcc456f81436d9744375e98"
    "4ed74ba6b24ec6e9c624e441a0cfca074f991fda6094786fb67c109c863d5322";

static void to_hex(const unsigned char *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

int main(void) {
    unsigned char seckey[32], msg[32], pub[33], sig[64];
    char hex[131];
    int fail = 0;

    for (int i = 0; i < 32; i++) {
        seckey[i] = (unsigned char)(1 + i * 7);
        msg[i] = (unsigned char)(200 - i * 3);
    }

    secp256k1_mojo_ctx ctx = secp256k1_mojo_context_create();
    if (!ctx) {
        printf("context creation failed\n");
        return 1;
    }

    if (!secp256k1_mojo_ec_pubkey_create(ctx, pub, seckey)) {
        printf("pubkey creation failed\n");
        fail = 1;
    } else {
        to_hex(pub, 33, hex);
        printf("pubkey    %s\n", hex);
        if (strcmp(hex, EXPECTED_PUBKEY) != 0) {
            printf("  MISMATCH, expected %s\n", EXPECTED_PUBKEY);
            fail = 1;
        }
    }

    if (!secp256k1_mojo_ecdsa_sign(ctx, sig, msg, seckey)) {
        printf("signing failed\n");
        fail = 1;
    } else {
        to_hex(sig, 64, hex);
        printf("signature %s\n", hex);
        if (strcmp(hex, EXPECTED_SIG) != 0) {
            printf("  MISMATCH, expected %s\n", EXPECTED_SIG);
            fail = 1;
        }
    }

    if (secp256k1_mojo_ecdsa_verify(ctx, sig, msg, pub, 33) != 1) {
        printf("verification of a valid signature failed\n");
        fail = 1;
    }

    sig[10] ^= 0x40;
    if (secp256k1_mojo_ecdsa_verify(ctx, sig, msg, pub, 33) != 0) {
        printf("a tampered signature was accepted\n");
        fail = 1;
    }

    secp256k1_mojo_context_destroy(ctx);
    printf("\n%s\n", fail ? "SMOKE TEST FAILED" : "smoke test passed");
    return fail;
}
