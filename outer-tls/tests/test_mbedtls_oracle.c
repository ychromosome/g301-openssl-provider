/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Independent test oracle: NIST SP 800-38D AES-256-GCM through Mbed TLS.
 * The provider under test is OpenSSL-backed; Mbed TLS supplies the expected
 * ciphertext and tag.  The deterministic generator is test data, not a RNG.
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/gcm.h>
#include <mbedtls/version.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define WORKING_NAME "G301-AES-256-GCM-V1"
#define PROPERTY_QUERY "provider=g301,fips=no"
#define CASES ((size_t)4096)
#define MAX_AAD ((size_t)255)
#define MAX_MESSAGE ((size_t)1024)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const unsigned char manifest[32] = {
    0x47, 0x33, 0x30, 0x31, 0x2d, 0x54, 0x4c, 0x53,
    0x31, 0x33, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x01,
    0x04, 0x01, 0x01, 0x2d, 0x01, 0x00, 0x63, 0x01,
    0x01, 0x74, 0x01, 0x00, 0xaf, 0x02, 0x03, 0xb3
};

static const size_t aad_sizes[] = {
    0, 1, 5, 15, 16, 17, 31, 32, 33, 37, MAX_AAD
};

static const size_t message_sizes[] = {
    0, 1, 15, 16, 17, 31, 32, 33, 255, MAX_MESSAGE
};

typedef struct deterministic_bytes_st {
    uint64_t state;
} DETERMINISTIC_BYTES;

static unsigned char next_byte(DETERMINISTIC_BYTES *generator)
{
    generator->state = generator->state
            * UINT64_C(6364136223846793005)
        + UINT64_C(1442695040888963407);
    return (unsigned char)(generator->state >> 56);
}

static void fill_bytes(DETERMINISTIC_BYTES *generator, unsigned char *out,
    size_t length)
{
    size_t i;

    for (i = 0; i < length; i++)
        out[i] = next_byte(generator);
}

static int get_tag(EVP_CIPHER_CTX *ctx, unsigned char tag[16])
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, 16),
        OSSL_PARAM_END
    };

    return EVP_CIPHER_CTX_get_params(ctx, params) > 0
        && params[0].return_size == 16;
}

static int set_tag(EVP_CIPHER_CTX *ctx, const unsigned char tag[16])
{
    unsigned char copy[16];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, copy,
            sizeof(copy)),
        OSSL_PARAM_END
    };

    memcpy(copy, tag, sizeof(copy));
    return EVP_CIPHER_CTX_set_params(ctx, params) > 0;
}

static int provider_encrypt(EVP_CIPHER *cipher, const unsigned char key[32],
    const unsigned char nonce[12], const unsigned char *aad, size_t aad_len,
    const unsigned char *plaintext, size_t plaintext_len,
    unsigned char *ciphertext, unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0;
    int total = 0;
    int ok = 0;

    if (aad_len > (size_t)INT_MAX || plaintext_len > (size_t)INT_MAX)
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_EncryptInit_ex2(ctx, cipher, key, nonce, NULL) <= 0)
        goto end;
    if (aad_len != 0
        && (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) <= 0
            || outl != (int)aad_len))
        goto end;
    if (plaintext_len != 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext,
                (int)plaintext_len)
            <= 0)
            goto end;
        total = outl;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &outl) <= 0)
        goto end;
    total += outl;
    if ((size_t)total != plaintext_len || !get_tag(ctx, tag))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int provider_decrypt(EVP_CIPHER *cipher, const unsigned char key[32],
    const unsigned char nonce[12], const unsigned char *aad, size_t aad_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char tag[16], unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0;
    int total = 0;
    int ok = 0;

    if (aad_len > (size_t)INT_MAX || ciphertext_len > (size_t)INT_MAX)
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_DecryptInit_ex2(ctx, cipher, key, nonce, NULL) <= 0
        || !set_tag(ctx, tag))
        goto end;
    if (aad_len != 0
        && (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) <= 0
            || outl != (int)aad_len))
        goto end;
    if (ciphertext_len != 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext,
                (int)ciphertext_len)
            <= 0)
            goto end;
        total = outl;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &outl) <= 0)
        goto end;
    total += outl;
    ok = (size_t)total == ciphertext_len;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int reference_encrypt(const unsigned char key[32],
    const unsigned char nonce[12], const unsigned char *aad, size_t aad_len,
    const unsigned char *plaintext, size_t plaintext_len,
    unsigned char *ciphertext, unsigned char tag[16], int include_manifest)
{
    mbedtls_gcm_context ctx;
    unsigned char combined_aad[sizeof(manifest) + MAX_AAD];
    const unsigned char *effective_aad = aad;
    size_t effective_aad_len = aad_len;
    int result;

    if (aad_len > MAX_AAD || plaintext_len > MAX_MESSAGE)
        return 0;
    if (include_manifest) {
        memcpy(combined_aad, manifest, sizeof(manifest));
        if (aad_len != 0)
            memcpy(combined_aad + sizeof(manifest), aad, aad_len);
        effective_aad = combined_aad;
        effective_aad_len = sizeof(manifest) + aad_len;
    }
    mbedtls_gcm_init(&ctx);
    result = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (result == 0) {
        result = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_len, nonce, 12, effective_aad, effective_aad_len,
            plaintext, ciphertext, 16, tag);
    }
    mbedtls_gcm_free(&ctx);
    return result == 0;
}

static int reference_decrypt(const unsigned char key[32],
    const unsigned char nonce[12], const unsigned char *aad, size_t aad_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char tag[16], unsigned char *plaintext,
    int include_manifest)
{
    mbedtls_gcm_context ctx;
    unsigned char combined_aad[sizeof(manifest) + MAX_AAD];
    const unsigned char *effective_aad = aad;
    size_t effective_aad_len = aad_len;
    int result;

    if (aad_len > MAX_AAD || ciphertext_len > MAX_MESSAGE)
        return 0;
    if (include_manifest) {
        memcpy(combined_aad, manifest, sizeof(manifest));
        if (aad_len != 0)
            memcpy(combined_aad + sizeof(manifest), aad, aad_len);
        effective_aad = combined_aad;
        effective_aad_len = sizeof(manifest) + aad_len;
    }
    mbedtls_gcm_init(&ctx);
    result = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (result == 0) {
        result = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len, nonce, 12,
            effective_aad, effective_aad_len, tag, 16, ciphertext, plaintext);
    }
    mbedtls_gcm_free(&ctx);
    return result == 0;
}

int main(int argc, char **argv)
{
    DETERMINISTIC_BYTES generator = {
        UINT64_C(0x00301947af0203b3)
    };
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char aad[MAX_AAD];
    unsigned char plaintext[MAX_MESSAGE];
    unsigned char provider_ciphertext[MAX_MESSAGE];
    unsigned char reference_ciphertext[MAX_MESSAGE];
    unsigned char provider_plaintext[MAX_MESSAGE];
    unsigned char reference_plaintext[MAX_MESSAGE];
    unsigned char provider_tag[16];
    unsigned char reference_tag[16];
    unsigned char ordinary_tag[16];
    unsigned char tampered_tag[16];
    size_t i;
    int result = EXIT_FAILURE;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
        || OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) <= 0)
        goto end;
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    g301_provider = OSSL_PROVIDER_load(libctx, "g301");
    if (default_provider == NULL || g301_provider == NULL)
        goto end;
    cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME, PROPERTY_QUERY);
    if (cipher == NULL)
        goto end;

    for (i = 0; i < CASES; i++) {
        size_t aad_len = aad_sizes[i % ARRAY_SIZE(aad_sizes)];
        size_t plaintext_len = message_sizes[(i * 7U)
            % ARRAY_SIZE(message_sizes)];

        fill_bytes(&generator, key, sizeof(key));
        fill_bytes(&generator, nonce, sizeof(nonce));
        fill_bytes(&generator, aad, aad_len);
        fill_bytes(&generator, plaintext, plaintext_len);
        memset(provider_ciphertext, 0xa5, sizeof(provider_ciphertext));
        memset(reference_ciphertext, 0x5a, sizeof(reference_ciphertext));
        if (!provider_encrypt(cipher, key, nonce, aad, aad_len, plaintext,
                plaintext_len, provider_ciphertext, provider_tag)
            || !reference_encrypt(key, nonce, aad, aad_len, plaintext,
                plaintext_len, reference_ciphertext, reference_tag, 1)
            || memcmp(provider_ciphertext, reference_ciphertext,
                   plaintext_len)
                != 0
            || memcmp(provider_tag, reference_tag, sizeof(provider_tag)) != 0
            || !provider_decrypt(cipher, key, nonce, aad, aad_len,
                reference_ciphertext, plaintext_len, reference_tag,
                provider_plaintext)
            || !reference_decrypt(key, nonce, aad, aad_len,
                provider_ciphertext, plaintext_len, provider_tag,
                reference_plaintext, 1)
            || memcmp(provider_plaintext, plaintext, plaintext_len) != 0
            || memcmp(reference_plaintext, plaintext, plaintext_len) != 0) {
            fprintf(stderr, "oracle mismatch at deterministic case %zu\n", i);
            ERR_print_errors_fp(stderr);
            goto end;
        }

        /*
         * NIST SP 800-38D: changing authenticated data or the tag must make
         * authentication fail.  These expectations are not learned from the
         * provider under test.
         */
        memcpy(tampered_tag, reference_tag, sizeof(tampered_tag));
        tampered_tag[i % sizeof(tampered_tag)] ^= 0x01U;
        if (provider_decrypt(cipher, key, nonce, aad, aad_len,
                reference_ciphertext, plaintext_len, tampered_tag,
                provider_plaintext)) {
            fprintf(stderr, "tampered tag accepted at case %zu\n", i);
            goto end;
        }

        /*
         * The sole G301 profile distinction is the fixed manifest prefix.
         * A plain AES-GCM peer authenticating only caller AAD must not
         * interoperate accidentally with a G301 peer.
         */
        if (!reference_encrypt(key, nonce, aad, aad_len, plaintext,
                plaintext_len, reference_ciphertext, ordinary_tag, 0)
            || provider_decrypt(cipher, key, nonce, aad, aad_len,
                reference_ciphertext, plaintext_len, ordinary_tag,
                provider_plaintext)
            || reference_decrypt(key, nonce, aad, aad_len,
                provider_ciphertext, plaintext_len, provider_tag,
                reference_plaintext, 0)) {
            fprintf(stderr,
                "one-sided manifest mismatch accepted at case %zu\n", i);
            goto end;
        }
    }
    printf("g301 Mbed TLS differential oracle: %zu/%zu PASS (%s)\n",
        CASES, CASES, MBEDTLS_VERSION_STRING_FULL);
    result = EXIT_SUCCESS;
end:
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return result;
}
