/* Generates test vectors for the Mojo secp256k1 port, ground-truthed against
 * the reference C implementation's internals. Deterministic (xorshift seed). */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "secp256k1.c"
#include "../include/secp256k1.h"
#include "modinv64_impl.h"
#include "int128_impl.h"

static uint64_t rng_s[2] = {0x123456789abcdef0ULL, 0xfedcba9876543210ULL};
static uint64_t rnd64(void) {
    uint64_t x = rng_s[0], y = rng_s[1];
    rng_s[0] = y;
    x ^= x << 23;
    x ^= x >> 17;
    x ^= y ^ (y >> 26);
    rng_s[1] = x;
    return x + y;
}
static void rnd32(unsigned char *b) {
    int i;
    for (i = 0; i < 4; i++) {
        uint64_t v = rnd64();
        int j;
        for (j = 0; j < 8; j++) b[i*8+j] = (v >> (56 - 8*j)) & 0xff;
    }
}

static FILE *out;
static void ph(const unsigned char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) fprintf(out, "%02x", b[i]);
}
static void pfe(const secp256k1_fe *a) {
    unsigned char b[32];
    secp256k1_fe t = *a;
    secp256k1_fe_normalize_var(&t);
    secp256k1_fe_get_b32(b, &t);
    ph(b, 32);
}
static void psc(const secp256k1_scalar *a) {
    unsigned char b[32];
    secp256k1_scalar_get_b32(b, a);
    ph(b, 32);
}
/* serialize a group element as 65-byte uncompressed, or "00"*1 for infinity */
static void pge(const secp256k1_ge *a) {
    if (a->infinity) { fprintf(out, "INF"); return; }
    fprintf(out, "04"); pfe(&a->x); pfe(&a->y);
}
static void pgej(const secp256k1_gej *a) {
    secp256k1_ge g;
    secp256k1_gej t = *a;
    if (secp256k1_gej_is_infinity(&t)) { fprintf(out, "INF"); return; }
    secp256k1_ge_set_gej_var(&g, &t);
    pge(&g);
}

/* random field element (uniform-ish over [0,p)) */
static void rnd_fe(secp256k1_fe *r) {
    unsigned char b[32];
    do { rnd32(b); } while (!secp256k1_fe_set_b32_limit(r, b));
}
static void rnd_scalar(secp256k1_scalar *r) {
    unsigned char b[32];
    int over;
    do { rnd32(b); secp256k1_scalar_set_b32(r, b, &over); }
    while (over || secp256k1_scalar_is_zero(r));
}
static void rnd_ge(secp256k1_ge *r, const secp256k1_context *ctx) {
    secp256k1_scalar s;
    secp256k1_gej j;
    rnd_scalar(&s);
    secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &j, &s);
    secp256k1_ge_set_gej_var(r, &j);
}

#define N 64

int main(void) {
    int i;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* ---------------- field ---------------- */
    out = fopen("tests/vectors/field.txt", "w");
    fprintf(out, "# op args... expected\n");
    /* fixed edge cases */
    {
        secp256k1_fe zero, one, pm1, pm2;
        unsigned char b[32];
        secp256k1_fe_set_int_unchecked(&zero, 0);
        secp256k1_fe_set_int_unchecked(&one, 1);
        memset(b, 0xff, 32);
        b[31] = 0xFC; b[28] = 0xFE; /* p-3 ... just use limit parse */
        /* p-1 */
        {
            static const unsigned char pm1b[32] = {
                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0x2e};
            secp256k1_fe_set_b32_limit(&pm1, pm1b);
        }
        secp256k1_fe_negate_unchecked(&pm2, &one, 1); /* -1 = p-1 */
        (void)pm2;
        {
            secp256k1_fe r;
            r = pm1; secp256k1_fe_add(&r, &one);
            fprintf(out, "ADD "); pfe(&pm1); fprintf(out, " "); pfe(&one);
            fprintf(out, " "); pfe(&r); fprintf(out, "\n");
            r = pm1; secp256k1_fe_mul(&r, &pm1, &pm1);
            fprintf(out, "MUL "); pfe(&pm1); fprintf(out, " "); pfe(&pm1);
            fprintf(out, " "); pfe(&r); fprintf(out, "\n");
            secp256k1_fe_inv(&r, &one);
            fprintf(out, "INV "); pfe(&one); fprintf(out, " "); pfe(&r); fprintf(out, "\n");
            secp256k1_fe_inv(&r, &zero);
            fprintf(out, "INV "); pfe(&zero); fprintf(out, " "); pfe(&r); fprintf(out, "\n");
        }
    }
    for (i = 0; i < N; i++) {
        secp256k1_fe a, b, r, s;
        rnd_fe(&a); rnd_fe(&b);

        r = a; secp256k1_fe_add(&r, &b);
        fprintf(out, "ADD "); pfe(&a); fprintf(out, " "); pfe(&b); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        secp256k1_fe_mul(&r, &a, &b);
        fprintf(out, "MUL "); pfe(&a); fprintf(out, " "); pfe(&b); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        secp256k1_fe_sqr(&r, &a);
        fprintf(out, "SQR "); pfe(&a); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        secp256k1_fe_negate_unchecked(&r, &a, 1); secp256k1_fe_normalize_var(&r);
        fprintf(out, "NEG "); pfe(&a); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        secp256k1_fe_inv(&r, &a);
        fprintf(out, "INV "); pfe(&a); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        r = a; secp256k1_fe_half(&r); secp256k1_fe_normalize_var(&r);
        fprintf(out, "HALF "); pfe(&a); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        r = a; secp256k1_fe_mul_int_unchecked(&r, 7); secp256k1_fe_normalize_var(&r);
        fprintf(out, "MULINT7 "); pfe(&a); fprintf(out, " "); pfe(&r); fprintf(out, "\n");

        fprintf(out, "ISODD "); pfe(&a); fprintf(out, " %d\n", secp256k1_fe_is_odd(&a));

        /* sqrt of a square always exists */
        secp256k1_fe_sqr(&s, &a);
        if (secp256k1_fe_sqrt(&r, &s)) {
            secp256k1_fe_normalize_var(&r);
            fprintf(out, "SQRT "); pfe(&s); fprintf(out, " "); pfe(&r); fprintf(out, "\n");
        }
        /* a itself may or may not be a square */
        if (secp256k1_fe_sqrt(&r, &a)) {
            secp256k1_fe_normalize_var(&r);
            fprintf(out, "SQRT "); pfe(&a); fprintf(out, " "); pfe(&r); fprintf(out, "\n");
        } else {
            fprintf(out, "SQRT "); pfe(&a); fprintf(out, " NONE\n");
        }
    }
    fclose(out);

    /* ---------------- scalar ---------------- */
    out = fopen("tests/vectors/scalar.txt", "w");
    fprintf(out, "# op args... expected\n");
    {
        /* overflow behaviour: n itself, n-1, n+1 */
        static const unsigned char nb[32] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
            0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
        unsigned char t[32];
        secp256k1_scalar s;
        int over;
        memcpy(t, nb, 32);
        secp256k1_scalar_set_b32(&s, t, &over);
        fprintf(out, "SETB32 "); ph(t, 32); fprintf(out, " "); psc(&s); fprintf(out, " %d\n", over);
        t[31] = 0x40;
        secp256k1_scalar_set_b32(&s, t, &over);
        fprintf(out, "SETB32 "); ph(t, 32); fprintf(out, " "); psc(&s); fprintf(out, " %d\n", over);
        t[31] = 0x42;
        secp256k1_scalar_set_b32(&s, t, &over);
        fprintf(out, "SETB32 "); ph(t, 32); fprintf(out, " "); psc(&s); fprintf(out, " %d\n", over);
    }
    for (i = 0; i < N; i++) {
        secp256k1_scalar a, b, r;
        int over;
        rnd_scalar(&a); rnd_scalar(&b);

        over = secp256k1_scalar_add(&r, &a, &b);
        fprintf(out, "ADD "); psc(&a); fprintf(out, " "); psc(&b); fprintf(out, " "); psc(&r); fprintf(out, " %d\n", over);

        secp256k1_scalar_mul(&r, &a, &b);
        fprintf(out, "MUL "); psc(&a); fprintf(out, " "); psc(&b); fprintf(out, " "); psc(&r); fprintf(out, "\n");

        secp256k1_scalar_negate(&r, &a);
        fprintf(out, "NEG "); psc(&a); fprintf(out, " "); psc(&r); fprintf(out, "\n");

        secp256k1_scalar_inverse(&r, &a);
        fprintf(out, "INV "); psc(&a); fprintf(out, " "); psc(&r); fprintf(out, "\n");

        secp256k1_scalar_half(&r, &a);
        fprintf(out, "HALF "); psc(&a); fprintf(out, " "); psc(&r); fprintf(out, "\n");

        fprintf(out, "ISHIGH "); psc(&a); fprintf(out, " %d\n", secp256k1_scalar_is_high(&a));
        fprintf(out, "ISEVEN "); psc(&a); fprintf(out, " %d\n", secp256k1_scalar_is_even(&a));

        {
            secp256k1_scalar r1, r2;
            secp256k1_scalar_split_lambda(&r1, &r2, &a);
            fprintf(out, "SPLITLAMBDA "); psc(&a); fprintf(out, " "); psc(&r1);
            fprintf(out, " "); psc(&r2); fprintf(out, "\n");
        }
        {
            secp256k1_scalar r1, r2;
            secp256k1_scalar_split_128(&r1, &r2, &a);
            fprintf(out, "SPLIT128 "); psc(&a); fprintf(out, " "); psc(&r1);
            fprintf(out, " "); psc(&r2); fprintf(out, "\n");
        }
    }
    fclose(out);

    /* ---------------- group ---------------- */
    out = fopen("tests/vectors/group.txt", "w");
    fprintf(out, "# op args... expected (points as 04||x||y or INF)\n");
    {
        secp256k1_gej gj;
        secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);
        fprintf(out, "GENERATOR "); pge(&secp256k1_ge_const_g); fprintf(out, "\n");
        secp256k1_gej_double(&gj, &gj);
        fprintf(out, "DOUBLE "); pge(&secp256k1_ge_const_g); fprintf(out, " "); pgej(&gj); fprintf(out, "\n");
        /* infinity cases */
        {
            secp256k1_gej inf, r;
            secp256k1_ge gneg;
            secp256k1_gej_set_infinity(&inf);
            secp256k1_gej_double(&r, &inf);
            fprintf(out, "DOUBLEJ INF "); pgej(&r); fprintf(out, "\n");
            secp256k1_gej_set_ge(&r, &secp256k1_ge_const_g);
            secp256k1_ge_neg(&gneg, &secp256k1_ge_const_g);
            secp256k1_gej_add_ge(&r, &r, &gneg);
            fprintf(out, "ADDGE "); pge(&secp256k1_ge_const_g); fprintf(out, " "); pge(&gneg);
            fprintf(out, " "); pgej(&r); fprintf(out, "\n");
            secp256k1_gej_set_ge(&r, &secp256k1_ge_const_g);
            secp256k1_gej_add_ge(&r, &r, &secp256k1_ge_const_g);
            fprintf(out, "ADDGE "); pge(&secp256k1_ge_const_g); fprintf(out, " "); pge(&secp256k1_ge_const_g);
            fprintf(out, " "); pgej(&r); fprintf(out, "\n");
        }
    }
    for (i = 0; i < N; i++) {
        secp256k1_ge a, b;
        secp256k1_gej ja, r;
        rnd_ge(&a, ctx); rnd_ge(&b, ctx);
        secp256k1_gej_set_ge(&ja, &a);

        secp256k1_gej_double(&r, &ja);
        fprintf(out, "DOUBLE "); pge(&a); fprintf(out, " "); pgej(&r); fprintf(out, "\n");

        secp256k1_gej_add_ge(&r, &ja, &b);
        fprintf(out, "ADDGE "); pge(&a); fprintf(out, " "); pge(&b); fprintf(out, " "); pgej(&r); fprintf(out, "\n");

        {
            secp256k1_gej jb;
            secp256k1_gej_set_ge(&jb, &b);
            secp256k1_gej_add_var(&r, &ja, &jb, NULL);
            fprintf(out, "ADDJ "); pge(&a); fprintf(out, " "); pge(&b); fprintf(out, " "); pgej(&r); fprintf(out, "\n");
        }
        {
            secp256k1_ge n;
            secp256k1_ge_neg(&n, &a);
            fprintf(out, "NEG "); pge(&a); fprintf(out, " "); pge(&n); fprintf(out, "\n");
        }
        {
            secp256k1_ge l;
            secp256k1_ge_mul_lambda(&l, &a);
            fprintf(out, "MULLAMBDA "); pge(&a); fprintf(out, " "); pge(&l); fprintf(out, "\n");
        }
        /* serialization round trips */
        {
            unsigned char c33[33];
            secp256k1_ge tmp = a;
            secp256k1_ge_serialize33(&tmp, c33);
            fprintf(out, "SER33 "); pge(&a); fprintf(out, " "); ph(c33, 33); fprintf(out, "\n");
        }
    }
    fclose(out);

    /* ---------------- ecmult ---------------- */
    out = fopen("tests/vectors/ecmult.txt", "w");
    fprintf(out, "# op args... expected\n");
    {
        secp256k1_scalar one, k;
        secp256k1_gej r;
        secp256k1_scalar_set_int(&one, 1);
        secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &r, &one);
        fprintf(out, "GEN "); psc(&one); fprintf(out, " "); pgej(&r); fprintf(out, "\n");
        secp256k1_scalar_set_int(&k, 0);
        secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &r, &k);
        fprintf(out, "GEN "); psc(&k); fprintf(out, " "); pgej(&r); fprintf(out, "\n");
        secp256k1_scalar_set_int(&k, 2);
        secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &r, &k);
        fprintf(out, "GEN "); psc(&k); fprintf(out, " "); pgej(&r); fprintf(out, "\n");
        /* n-1 */
        secp256k1_scalar_set_int(&k, 1);
        secp256k1_scalar_negate(&k, &k);
        secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &r, &k);
        fprintf(out, "GEN "); psc(&k); fprintf(out, " "); pgej(&r); fprintf(out, "\n");
    }
    for (i = 0; i < N; i++) {
        secp256k1_scalar k, na, ng;
        secp256k1_ge a;
        secp256k1_gej ja, r;

        rnd_scalar(&k);
        secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &r, &k);
        fprintf(out, "GEN "); psc(&k); fprintf(out, " "); pgej(&r); fprintf(out, "\n");

        rnd_ge(&a, ctx); rnd_scalar(&na); rnd_scalar(&ng);
        secp256k1_gej_set_ge(&ja, &a);
        secp256k1_ecmult(&r, &ja, &na, &ng);
        fprintf(out, "ECMULT "); pge(&a); fprintf(out, " "); psc(&na); fprintf(out, " "); psc(&ng);
        fprintf(out, " "); pgej(&r); fprintf(out, "\n");

        secp256k1_ecmult_const(&r, &a, &na);
        fprintf(out, "CONST "); pge(&a); fprintf(out, " "); psc(&na); fprintf(out, " "); pgej(&r); fprintf(out, "\n");
    }
    fclose(out);

    /* ---------------- ecdsa / pubkey ---------------- */
    out = fopen("tests/vectors/ecdsa.txt", "w");
    fprintf(out, "# op args... expected\n");
    for (i = 0; i < N; i++) {
        unsigned char sk[32], msg[32], sig64[64], pub33[33], pub65[65];
        secp256k1_pubkey pk;
        secp256k1_ecdsa_signature sig;
        size_t len;
        int recid;
        secp256k1_ecdsa_recoverable_signature rsig;

        do { rnd32(sk); } while (!secp256k1_ec_seckey_verify(ctx, sk));
        rnd32(msg);

        if (!secp256k1_ec_pubkey_create(ctx, &pk, sk)) continue;
        len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pub33, &len, &pk, SECP256K1_EC_COMPRESSED);
        len = 65;
        secp256k1_ec_pubkey_serialize(ctx, pub65, &len, &pk, SECP256K1_EC_UNCOMPRESSED);
        fprintf(out, "PUBKEY "); ph(sk, 32); fprintf(out, " "); ph(pub33, 33);
        fprintf(out, " "); ph(pub65, 65); fprintf(out, "\n");

        /* RFC6979 deterministic signature */
        if (!secp256k1_ecdsa_sign(ctx, &sig, msg, sk, NULL, NULL)) continue;
        secp256k1_ecdsa_signature_serialize_compact(ctx, sig64, &sig);
        fprintf(out, "SIGN "); ph(sk, 32); fprintf(out, " "); ph(msg, 32);
        fprintf(out, " "); ph(sig64, 64); fprintf(out, "\n");

        fprintf(out, "VERIFY "); ph(pub33, 33); fprintf(out, " "); ph(msg, 32);
        fprintf(out, " "); ph(sig64, 64); fprintf(out, " 1\n");

        /* corrupt one byte -> must fail */
        {
            unsigned char bad[64];
            memcpy(bad, sig64, 64);
            bad[13] ^= 0x01;
            /* only emit if it stays a valid scalar pair and actually fails */
            secp256k1_ecdsa_signature s2;
            if (secp256k1_ecdsa_signature_parse_compact(ctx, &s2, bad)) {
                int ok = secp256k1_ecdsa_verify(ctx, &s2, msg, &pk);
                fprintf(out, "VERIFY "); ph(pub33, 33); fprintf(out, " "); ph(msg, 32);
                fprintf(out, " "); ph(bad, 64); fprintf(out, " %d\n", ok);
            }
        }

        /* DER round trip */
        len = 72;
        {
            unsigned char der[72];
            if (secp256k1_ecdsa_signature_serialize_der(ctx, der, &len, &sig)) {
                fprintf(out, "DER "); ph(sig64, 64); fprintf(out, " "); ph(der, len); fprintf(out, "\n");
            }
        }

        /* recoverable */
        if (secp256k1_ecdsa_sign_recoverable(ctx, &rsig, msg, sk, NULL, NULL)) {
            unsigned char r64[64];
            secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, r64, &recid, &rsig);
            fprintf(out, "RECOVER "); ph(msg, 32); fprintf(out, " "); ph(r64, 64);
            fprintf(out, " %d ", recid); ph(pub33, 33); fprintf(out, "\n");
        }

        /* tweaks */
        {
            unsigned char tw[32], sk2[32];
            secp256k1_pubkey pk2;
            rnd32(tw);
            memcpy(sk2, sk, 32);
            if (secp256k1_ec_seckey_tweak_add(ctx, sk2, tw)) {
                fprintf(out, "TWEAKADD "); ph(sk, 32); fprintf(out, " "); ph(tw, 32);
                fprintf(out, " "); ph(sk2, 32); fprintf(out, "\n");
            }
            memcpy(sk2, sk, 32);
            if (secp256k1_ec_seckey_tweak_mul(ctx, sk2, tw)) {
                fprintf(out, "TWEAKMUL "); ph(sk, 32); fprintf(out, " "); ph(tw, 32);
                fprintf(out, " "); ph(sk2, 32); fprintf(out, "\n");
            }
            pk2 = pk;
            if (secp256k1_ec_pubkey_tweak_add(ctx, &pk2, tw)) {
                unsigned char p2[33];
                len = 33;
                secp256k1_ec_pubkey_serialize(ctx, p2, &len, &pk2, SECP256K1_EC_COMPRESSED);
                fprintf(out, "PUBTWEAKADD "); ph(pub33, 33); fprintf(out, " "); ph(tw, 32);
                fprintf(out, " "); ph(p2, 33); fprintf(out, "\n");
            }
        }

        /* ECDH-ish: shared point = sk * pubkey(other) via ecmult_const already covered */
    }
    fclose(out);

    /* ---------------- sha256 / hmac / rfc6979 ---------------- */
    out = fopen("tests/vectors/hash.txt", "w");
    fprintf(out, "# op input expected\n");
    {
        /* known SHA-256 vectors */
        const char *msgs[] = {"", "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "The quick brown fox jumps over the lazy dog"};
        int m;
        for (m = 0; m < 4; m++) {
            secp256k1_sha256 h;
            unsigned char o[32];
            secp256k1_sha256_initialize(&h);
            secp256k1_sha256_write(&ctx->hash_ctx, &h, (const unsigned char*)msgs[m], strlen(msgs[m]));
            secp256k1_sha256_finalize(&ctx->hash_ctx, &h, o);
            fprintf(out, "SHA256 "); ph((const unsigned char*)msgs[m], strlen(msgs[m]));
            fprintf(out, " "); ph(o, 32); fprintf(out, "\n");
        }
        /* long message: 1000 'a' */
        {
            unsigned char buf[1000];
            secp256k1_sha256 h;
            unsigned char o[32];
            memset(buf, 'a', 1000);
            secp256k1_sha256_initialize(&h);
            secp256k1_sha256_write(&ctx->hash_ctx, &h, buf, 1000);
            secp256k1_sha256_finalize(&ctx->hash_ctx, &h, o);
            fprintf(out, "SHA256 "); ph(buf, 1000); fprintf(out, " "); ph(o, 32); fprintf(out, "\n");
        }
    }
    for (i = 0; i < 16; i++) {
        unsigned char key[32], data[64], o[32];
        secp256k1_hmac_sha256 hm;
        rnd32(key); rnd32(data); rnd32(data+32);
        secp256k1_hmac_sha256_initialize(&ctx->hash_ctx, &hm, key, 32);
        secp256k1_hmac_sha256_write(&ctx->hash_ctx, &hm, data, 64);
        secp256k1_hmac_sha256_finalize(&ctx->hash_ctx, &hm, o);
        fprintf(out, "HMAC "); ph(key, 32); fprintf(out, " "); ph(data, 64);
        fprintf(out, " "); ph(o, 32); fprintf(out, "\n");

        {
            secp256k1_rfc6979_hmac_sha256 rng;
            unsigned char seed[64], out1[32], out2[32];
            memcpy(seed, key, 32); memcpy(seed+32, data, 32);
            secp256k1_rfc6979_hmac_sha256_initialize(&ctx->hash_ctx, &rng, seed, 64);
            secp256k1_rfc6979_hmac_sha256_generate(&ctx->hash_ctx, &rng, out1, 32);
            secp256k1_rfc6979_hmac_sha256_generate(&ctx->hash_ctx, &rng, out2, 32);
            fprintf(out, "RFC6979 "); ph(seed, 64); fprintf(out, " "); ph(out1, 32);
            fprintf(out, " "); ph(out2, 32); fprintf(out, "\n");
        }
    }
    fclose(out);

    secp256k1_context_destroy(ctx);
    fprintf(stderr, "vectors written\n");
    return 0;
}
