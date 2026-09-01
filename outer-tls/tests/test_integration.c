/* SPDX-License-Identifier: Apache-2.0 */

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define WORKING_NAME "G301-AES-256-GCM-V1"
#define PROPERTY_QUERY "provider=g301,fips=no"
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            ERR_print_errors_fp(stderr);                                    \
            failures++;                                                     \
            goto end;                                                       \
        }                                                                   \
    } while (0)

static const unsigned char key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char iv[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
};

static const unsigned char manifest[32] = {
    0x47, 0x33, 0x30, 0x31, 0x2d, 0x54, 0x4c, 0x53,
    0x31, 0x33, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x01,
    0x04, 0x01, 0x01, 0x2d, 0x01, 0x00, 0x63, 0x01,
    0x01, 0x74, 0x01, 0x00, 0xaf, 0x02, 0x03, 0xb3
};

typedef struct kat_st {
    const unsigned char *aad;
    size_t aad_len;
    const unsigned char *plaintext;
    size_t plaintext_len;
    const unsigned char *ciphertext;
    const unsigned char *tag;
} KAT;

static const unsigned char aad1[] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
static const unsigned char plaintext1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x17
};
static const unsigned char ciphertext1[] = {
    0x47, 0x03, 0xd4, 0x18, 0xc1, 0xe0, 0xc4, 0x1c,
    0x85, 0x48, 0x9d, 0x80, 0xbd, 0xe4, 0x76, 0x7a
};
static const unsigned char tag1[] = {
    0xd1, 0x3e, 0x69, 0x0f, 0x20, 0xbc, 0x38, 0x92,
    0x3e, 0xa2, 0xb8, 0x54, 0xe2, 0x58, 0xe3, 0x2d
};

static const unsigned char aad2[] = { 0x17, 0x03, 0x03, 0x00, 0x11 };
static const unsigned char plaintext2[] = { 0x17 };
static const unsigned char ciphertext2[] = { 0x50 };
static const unsigned char tag2[] = {
    0x94, 0x1c, 0x16, 0x17, 0x61, 0x4c, 0xf0, 0x75,
    0xf5, 0x81, 0xd2, 0xcc, 0xd9, 0x0f, 0x08, 0x18
};

/* Frozen negative differential controls from docs/TEST_VECTORS.md. */
static const unsigned char zero_tag1[] = {
    0xb1, 0x75, 0xa5, 0xc4, 0xbb, 0xa7, 0xab, 0x87,
    0xf4, 0x81, 0xf8, 0x3c, 0x00, 0x85, 0xdc, 0x54
};
static const unsigned char two_tag1[] = {
    0xfb, 0xbb, 0x3b, 0x9e, 0x06, 0x4b, 0x29, 0x11,
    0x0f, 0x1b, 0xbb, 0x2c, 0x99, 0xf3, 0x87, 0x75
};
static const unsigned char zero_tag2[] = {
    0xf4, 0x57, 0xda, 0xdc, 0xfa, 0x57, 0x63, 0x60,
    0x3f, 0xa2, 0x92, 0xa4, 0x3b, 0xd2, 0x37, 0x61
};
static const unsigned char two_tag2[] = {
    0xbe, 0x99, 0x44, 0x86, 0x47, 0xbb, 0xe1, 0xf6,
    0xc4, 0x38, 0xd1, 0xb4, 0xa2, 0xa4, 0x6c, 0x40
};

static const unsigned char *const zero_tags[] = { zero_tag1, zero_tag2 };
static const unsigned char *const two_tags[] = { two_tag1, two_tag2 };

static const KAT kats[] = {
    { aad1, sizeof(aad1), plaintext1, sizeof(plaintext1),
        ciphertext1, tag1 },
    { aad2, sizeof(aad2), plaintext2, sizeof(plaintext2),
        ciphertext2, tag2 }
};

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
    unsigned char tag_copy[16];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
            tag_copy, 16),
        OSSL_PARAM_END
    };

    memcpy(tag_copy, tag, sizeof(tag_copy));
    return EVP_CIPHER_CTX_set_params(ctx, params) > 0;
}

static int encrypt_with_aad(EVP_CIPHER *cipher,
    const unsigned char *aad_prefix, size_t aad_prefix_len,
    const KAT *kat, unsigned char *ciphertext, unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = NULL;
    size_t ivlen = sizeof(iv);
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_END
    };
    int outl = 0;
    int total = 0;
    int ok = 0;

    if (kat->aad_len > (size_t)INT_MAX
        || kat->plaintext_len > (size_t)INT_MAX
        || aad_prefix_len > (size_t)INT_MAX)
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "encrypt fixture: context allocation failed\n");
        goto end;
    }
    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) <= 0) {
        fprintf(stderr, "encrypt fixture: init failed\n");
        goto end;
    }
    if (aad_prefix_len != 0
        && (EVP_EncryptUpdate(ctx, NULL, &outl, aad_prefix,
                (int)aad_prefix_len)
                <= 0
            || outl != (int)aad_prefix_len)) {
        fprintf(stderr, "encrypt fixture: prefix AAD failed\n");
        goto end;
    }
    if (EVP_EncryptUpdate(ctx, NULL, &outl, kat->aad,
            (int)kat->aad_len)
            <= 0
        || outl != (int)kat->aad_len) {
        fprintf(stderr, "encrypt fixture: caller AAD failed outl=%d\n", outl);
        goto end;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &outl, kat->plaintext,
            (int)kat->plaintext_len)
        <= 0) {
        fprintf(stderr, "encrypt fixture: payload failed\n");
        goto end;
    }
    total = outl;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &outl) <= 0) {
        fprintf(stderr, "encrypt fixture: final failed\n");
        goto end;
    }
    total += outl;
    if ((size_t)total != kat->plaintext_len || !get_tag(ctx, tag)) {
        fprintf(stderr, "encrypt fixture: tag failed total=%d\n", total);
        goto end;
    }
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int decrypt_wrapper(EVP_CIPHER *cipher, const KAT *kat,
    const unsigned char tag[16], unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char tag_copy[16];
    size_t ivlen = sizeof(iv);
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag_copy,
            sizeof(tag_copy)),
        OSSL_PARAM_END
    };
    int outl = 0;
    int total = 0;
    int ok = 0;

    memcpy(tag_copy, tag, sizeof(tag_copy));
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_DecryptInit_ex2(ctx, cipher, key, iv, params) <= 0
        || EVP_DecryptUpdate(ctx, NULL, &outl, kat->aad,
               (int)kat->aad_len)
            <= 0
        || outl != (int)kat->aad_len
        || EVP_DecryptUpdate(ctx, plaintext, &outl, kat->ciphertext,
               (int)kat->plaintext_len)
            <= 0)
        goto end;
    total = outl;
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &outl) <= 0)
        goto end;
    total += outl;
    ok = (size_t)total == kat->plaintext_len;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_fetch_and_params(OSSL_LIB_CTX *libctx, EVP_CIPHER *cipher)
{
    EVP_CIPHER *probe = NULL;
    const OSSL_PROVIDER *provider;
    OSSL_PARAM params[7];
    unsigned int mode = 0;
    size_t keylen = 0, ivlen = 0, blocksize = 0;
    int aead = 0, custom_iv = 0;
    int ok = 0;

    provider = EVP_CIPHER_get0_provider(cipher);
    CHECK(provider != NULL);
    CHECK(strcmp(OSSL_PROVIDER_get0_name(provider), "g301") == 0);

    probe = EVP_CIPHER_fetch(libctx, "AES-256-GCM", "provider=g301");
    CHECK(probe == NULL);
    probe = EVP_CIPHER_fetch(libctx,
        "G301-PUBLIC-NAME-NOT-FROZEN-AES-256-GCM",
        "provider=g301");
    CHECK(probe == NULL);
    probe = EVP_CIPHER_fetch(libctx, WORKING_NAME, "provider=g301,fips=yes");
    CHECK(probe == NULL);

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen);
    params[3] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE,
        &blocksize);
    params[4] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD, &aead);
    params[5] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CUSTOM_IV,
        &custom_iv);
    params[6] = OSSL_PARAM_construct_end();
    CHECK(EVP_CIPHER_get_params(cipher, params) > 0);
    CHECK(mode == EVP_CIPH_GCM_MODE);
    CHECK(keylen == 32 && ivlen == 12 && blocksize == 1);
    CHECK(aead == 1 && custom_iv == 1);
    ok = 1;
end:
    EVP_CIPHER_free(probe);
    return ok;
}

static int test_kats(EVP_CIPHER *wrapper, EVP_CIPHER *reference)
{
    size_t i;
    int ok = 0;

    for (i = 0; i < ARRAY_SIZE(kats); i++) {
        unsigned char wrapper_ct[sizeof(plaintext1)] = { 0 };
        unsigned char wrapper_tag[16] = { 0 };
        unsigned char reference_ct[sizeof(plaintext1)] = { 0 };
        unsigned char reference_tag[16] = { 0 };
        unsigned char recovered[sizeof(plaintext1)] = { 0 };
        unsigned char bad_tag[16];
        unsigned char zero_ct[sizeof(plaintext1)] = { 0 };
        unsigned char zero_tag[16] = { 0 };
        unsigned char two_ct[sizeof(plaintext1)] = { 0 };
        unsigned char two_tag[16] = { 0 };
        unsigned char double_manifest[sizeof(manifest) * 2];

        CHECK(encrypt_with_aad(wrapper, NULL, 0, &kats[i], wrapper_ct,
            wrapper_tag));
        CHECK(encrypt_with_aad(reference, manifest, sizeof(manifest), &kats[i],
            reference_ct, reference_tag));
        CHECK(memcmp(wrapper_ct, kats[i].ciphertext,
                  kats[i].plaintext_len)
            == 0);
        CHECK(memcmp(wrapper_tag, kats[i].tag, sizeof(wrapper_tag)) == 0);
        CHECK(memcmp(wrapper_ct, reference_ct, kats[i].plaintext_len) == 0);
        CHECK(memcmp(wrapper_tag, reference_tag, sizeof(wrapper_tag)) == 0);
        CHECK(encrypt_with_aad(reference, NULL, 0, &kats[i], zero_ct,
            zero_tag));
        memcpy(double_manifest, manifest, sizeof(manifest));
        memcpy(double_manifest + sizeof(manifest), manifest,
            sizeof(manifest));
        CHECK(encrypt_with_aad(reference, double_manifest,
            sizeof(double_manifest), &kats[i], two_ct, two_tag));
        /* AES-GCM payload bytes are AAD-independent for fixed K, N, and P. */
        CHECK(memcmp(wrapper_ct, zero_ct, kats[i].plaintext_len) == 0);
        CHECK(memcmp(wrapper_ct, two_ct, kats[i].plaintext_len) == 0);
        CHECK(memcmp(zero_tag, zero_tags[i], sizeof(wrapper_tag)) == 0);
        CHECK(memcmp(two_tag, two_tags[i], sizeof(wrapper_tag)) == 0);
        CHECK(!decrypt_wrapper(wrapper, &kats[i], zero_tag, recovered));
        CHECK(!decrypt_wrapper(wrapper, &kats[i], two_tag, recovered));
        CHECK(decrypt_wrapper(wrapper, &kats[i], wrapper_tag, recovered));
        CHECK(memcmp(recovered, kats[i].plaintext, kats[i].plaintext_len) == 0);

        memcpy(bad_tag, wrapper_tag, sizeof(bad_tag));
        bad_tag[0] ^= 1U;
        memset(recovered, 0xa5, sizeof(recovered));
        ERR_clear_error();
        CHECK(!decrypt_wrapper(wrapper, &kats[i], bad_tag, recovered));
        CHECK(ERR_peek_error() == 0);
    }
    ok = 1;
end:
    return ok;
}

static int completed_encrypt_ctx(EVP_CIPHER *cipher, EVP_CIPHER_CTX **out_ctx)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[sizeof(plaintext1)];
    int outl = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0
        || EVP_EncryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) <= 0
        || EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext1,
               (int)sizeof(plaintext1))
            <= 0
        || EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *out_ctx = ctx;
    return 1;
}

static int test_fixed_tag_getter(EVP_CIPHER *cipher)
{
    static const size_t query_sizes[] = { 0, 1, 15, 16, 17, SIZE_MAX };
    static const size_t bad_sizes[] = { 0, 1, 15, 17, SIZE_MAX };
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i;
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    {
        unsigned char sentinel[16];
        OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, sentinel,
                sizeof(sentinel)),
            OSSL_PARAM_END
        };
        memset(sentinel, 0xa5, sizeof(sentinel));
        CHECK(EVP_CIPHER_CTX_get_params(ctx, params) <= 0);
        for (size_t j = 0; j < sizeof(sentinel); j++)
            CHECK(sentinel[j] == 0xa5);
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    CHECK(completed_encrypt_ctx(cipher, &ctx));
    {
        int wrong_type = 0;
        OSSL_PARAM params[] = {
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD_TAG, &wrong_type),
            OSSL_PARAM_END
        };
        CHECK(EVP_CIPHER_CTX_get_params(ctx, params) <= 0);
    }
    for (i = 0; i < ARRAY_SIZE(query_sizes); i++) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL,
                query_sizes[i]),
            OSSL_PARAM_END
        };
        CHECK(EVP_CIPHER_CTX_get_params(ctx, params) > 0);
        CHECK(params[0].return_size == 16);
    }
    for (i = 0; i < ARRAY_SIZE(bad_sizes); i++) {
        unsigned char sentinel[32];
        OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, sentinel,
                bad_sizes[i]),
            OSSL_PARAM_END
        };
        memset(sentinel, 0xa5, sizeof(sentinel));
        CHECK(EVP_CIPHER_CTX_get_params(ctx, params) <= 0);
        CHECK(params[0].return_size == 16);
        for (size_t j = 0; j < sizeof(sentinel); j++)
            CHECK(sentinel[j] == 0xa5);
    }
    {
        unsigned char tag[16];
        memset(tag, 0xa5, sizeof(tag));
        CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) > 0);
        CHECK(memcmp(tag, tag1, sizeof(tag)) == 0);
    }
    {
        static const int bad_args[] = { 0, 1, 15, 17, INT_MAX, -1, INT_MIN };
        unsigned char sentinel[32];

        for (i = 0; i < ARRAY_SIZE(bad_args); i++) {
            memset(sentinel, 0xa5, sizeof(sentinel));
            CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, bad_args[i],
                      sentinel)
                <= 0);
            for (size_t j = 0; j < sizeof(sentinel); j++)
                CHECK(sentinel[j] == 0xa5);
        }
    }
    {
        static const int null_args[] = {
            INT_MIN, -1, 0, 1, 15, 16, 17, INT_MAX
        };

        for (i = 0; i < ARRAY_SIZE(null_args); i++)
            CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                      null_args[i], NULL)
                > 0);
    }
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_lifecycle(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char output[sizeof(plaintext1)];
    unsigned char tag[16];
    unsigned char iv2[sizeof(iv)];
    int outl = 123;
    int ok = 0;

    memcpy(iv2, iv, sizeof(iv2));
    iv2[sizeof(iv2) - 1] ^= 1U;
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    CHECK(EVP_EncryptUpdate(ctx, NULL, &outl, NULL, 0) > 0 && outl == 0);
    CHECK(EVP_EncryptUpdate(ctx, output, &outl, plaintext1,
              (int)sizeof(plaintext1))
        > 0);
    CHECK(EVP_EncryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) <= 0);
    CHECK(EVP_EncryptFinal_ex(ctx, output, &outl) > 0 && outl == 0);
    CHECK(get_tag(ctx, tag));
    CHECK(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv2, NULL) > 0);
    CHECK(EVP_EncryptFinal_ex(ctx, output, &outl) > 0 && outl == 0);
    CHECK(get_tag(ctx, tag));
    CHECK(EVP_EncryptFinal_ex(ctx, output, &outl) <= 0);
    CHECK(EVP_EncryptUpdate(ctx, output, &outl, plaintext1, 1) <= 0);

    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    CHECK(EVP_DecryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) > 0);
    CHECK(EVP_DecryptUpdate(ctx, output, &outl, ciphertext1,
              (int)sizeof(ciphertext1))
        > 0);
    CHECK(EVP_DecryptFinal_ex(ctx, output, &outl) <= 0);
    CHECK(!set_tag(ctx, tag1));
    CHECK(EVP_DecryptFinal_ex(ctx, output, &outl) <= 0);
    CHECK(EVP_DecryptInit_ex2(ctx, NULL, NULL, iv, NULL) > 0);
    CHECK(set_tag(ctx, tag1));
    CHECK(EVP_DecryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) > 0);
    CHECK(EVP_DecryptUpdate(ctx, output, &outl, ciphertext1,
              (int)sizeof(ciphertext1))
        > 0);
    CHECK(EVP_DecryptFinal_ex(ctx, output + outl, &outl) > 0);
    CHECK(memcmp(output, plaintext1, sizeof(plaintext1)) == 0);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int descriptor_is(const OSSL_PARAM *params, const char *param_name,
    unsigned int data_type)
{
    const OSSL_PARAM *param = OSSL_PARAM_locate_const(params, param_name);

    return param != NULL && param->data_type == data_type;
}

static size_t descriptor_count(const OSSL_PARAM *params)
{
    size_t count = 0;

    while (params != NULL && params[count].key != NULL)
        count++;
    return count;
}

static int test_parameter_surface(EVP_CIPHER *cipher)
{
    static const int bad_key_lengths[] = { INT_MIN, -1, 16, 31, 33, INT_MAX };
    static const int bad_iv_lengths[] = { -1, 0, 11, 13, INT_MAX };
    const OSSL_PARAM *algorithm = EVP_CIPHER_gettable_params(cipher);
    const OSSL_PARAM *gettable = EVP_CIPHER_gettable_ctx_params(cipher);
    const OSSL_PARAM *settable = EVP_CIPHER_settable_ctx_params(cipher);
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i;
    int ok = 0;

    CHECK(descriptor_is(algorithm, OSSL_CIPHER_PARAM_MODE,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(algorithm, OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(algorithm, OSSL_CIPHER_PARAM_IVLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(algorithm, OSSL_CIPHER_PARAM_BLOCK_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(algorithm, OSSL_CIPHER_PARAM_AEAD,
        OSSL_PARAM_INTEGER));
    CHECK(descriptor_is(algorithm, OSSL_CIPHER_PARAM_CUSTOM_IV,
        OSSL_PARAM_INTEGER));
    CHECK(descriptor_is(gettable, OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(gettable, OSSL_CIPHER_PARAM_IVLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(gettable, OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(gettable, OSSL_CIPHER_PARAM_AEAD_TAG,
        OSSL_PARAM_OCTET_STRING));
    CHECK(descriptor_is(settable, OSSL_CIPHER_PARAM_IVLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(settable, OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(settable, OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_PARAM_UNSIGNED_INTEGER));
    CHECK(descriptor_is(settable, OSSL_CIPHER_PARAM_AEAD_TAG,
        OSSL_PARAM_OCTET_STRING));
    CHECK(descriptor_count(settable) == 4);

    for (i = 0; i < ARRAY_SIZE(bad_key_lengths); i++) {
        int result;

        ctx = EVP_CIPHER_CTX_new();
        CHECK(ctx != NULL);
        CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, NULL, NULL) > 0);
        result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH,
            bad_key_lengths[i], NULL);
        if (result > 0)
            fprintf(stderr, "unexpected accepted key length: %d\n",
                bad_key_lengths[i]);
        CHECK(result <= 0);
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) > 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, 32, NULL) > 0);
    CHECK(EVP_CIPHER_CTX_set_key_length(ctx, 32) > 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    for (i = 0; i < ARRAY_SIZE(bad_iv_lengths); i++) {
        ctx = EVP_CIPHER_CTX_new();
        CHECK(ctx != NULL);
        CHECK(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) > 0);
        CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                  bad_iv_lengths[i], NULL)
            <= 0);
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) > 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    {
        size_t key_length = 32;
        OSSL_PARAM params[] = {
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_length),
            OSSL_PARAM_END
        };

        ctx = EVP_CIPHER_CTX_new();
        CHECK(ctx != NULL);
        CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) > 0);
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    {
        unsigned char tag[16] = { 0 };
        OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag,
                sizeof(tag)),
            OSSL_PARAM_END
        };

        ctx = EVP_CIPHER_CTX_new();
        CHECK(ctx != NULL);
        CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
        CHECK(EVP_CIPHER_CTX_set_params(ctx, params) <= 0);
        EVP_CIPHER_CTX_free(ctx);
        ctx = EVP_CIPHER_CTX_new();
        CHECK(ctx != NULL);
        CHECK(EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
        CHECK(EVP_CIPHER_CTX_set_params(ctx, params) > 0);
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    {
        static const size_t bad_values[] = { 0, 16, 31, 33, SIZE_MAX };

        for (i = 0; i < ARRAY_SIZE(bad_values); i++) {
            size_t bad = bad_values[i];
            OSSL_PARAM params[] = {
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &bad),
                OSSL_PARAM_END
            };

            ctx = EVP_CIPHER_CTX_new();
            CHECK(ctx != NULL);
            CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) <= 0);
            EVP_CIPHER_CTX_free(ctx);
            ctx = NULL;
        }
    }
    {
        size_t key_length = 0, iv_length = 0, tag_length = 0;
        unsigned int unknown = 0x947U;
        OSSL_PARAM params[] = {
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_length),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_length),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tag_length),
            OSSL_PARAM_uint("g301-unknown", &unknown),
            OSSL_PARAM_END
        };

        ctx = EVP_CIPHER_CTX_new();
        CHECK(ctx != NULL);
        CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
        CHECK(EVP_CIPHER_CTX_get_params(ctx, params) > 0);
        CHECK(key_length == 32 && iv_length == 12 && tag_length == 16);
        CHECK(unknown == 0x947U);
        CHECK(EVP_CIPHER_CTX_get_params(ctx, NULL) > 0);
        CHECK(EVP_CIPHER_CTX_set_params(ctx, NULL) > 0);
    }
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int update_aad(EVP_CIPHER_CTX *ctx, const unsigned char *aad,
    size_t aad_len, int split)
{
    int outl = -1;
    size_t first;

    if (aad_len == 0)
        return 1;
    if (!split || aad_len == 1)
        return EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)aad_len) > 0
            && outl == (int)aad_len;
    first = aad_len / 2;
    return EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)first) > 0
        && outl == (int)first
        && EVP_CipherUpdate(ctx, NULL, &outl, aad + first,
               (int)(aad_len - first))
        > 0
        && outl == (int)(aad_len - first);
}

static int update_payload(EVP_CIPHER_CTX *ctx, unsigned char *output,
    const unsigned char *input, size_t input_len, int split, int in_place)
{
    size_t offsets[4];
    size_t chunks[3];
    size_t count = 1;
    size_t i;
    int outl = -1;

    if (input_len == 0)
        return 1;
    chunks[0] = input_len;
    if (split && input_len > 1) {
        chunks[0] = 1;
        chunks[1] = input_len > 17 ? 16 : input_len - 1;
        chunks[2] = input_len - chunks[0] - chunks[1];
        count = chunks[2] == 0 ? 2 : 3;
    }
    offsets[0] = 0;
    for (i = 1; i <= count; i++)
        offsets[i] = offsets[i - 1] + chunks[i - 1];
    if (in_place)
        memmove(output, input, input_len);
    for (i = 0; i < count; i++) {
        const unsigned char *chunk_in = in_place
            ? output + offsets[i]
            : input + offsets[i];

        if (EVP_CipherUpdate(ctx, output + offsets[i], &outl, chunk_in,
                (int)chunks[i])
                <= 0
            || outl != (int)chunks[i])
            return 0;
    }
    return offsets[count] == input_len;
}

static int encrypt_profile_case(EVP_CIPHER *cipher,
    const unsigned char *aad_prefix, size_t prefix_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *plaintext, size_t plaintext_len,
    int split, int in_place, unsigned char *ciphertext,
    unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = -1;
    int ok = 0;

    if (prefix_len > (size_t)INT_MAX || aad_len > (size_t)INT_MAX
        || plaintext_len > (size_t)INT_MAX)
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0
        || !update_aad(ctx, aad_prefix, prefix_len, split)
        || !update_aad(ctx, aad, aad_len, split)
        || !update_payload(ctx, ciphertext, plaintext, plaintext_len, split,
            in_place)
        || EVP_EncryptFinal_ex(ctx, ciphertext + plaintext_len, &outl) <= 0
        || outl != 0 || !get_tag(ctx, tag))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int decrypt_profile_case(EVP_CIPHER *cipher,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char tag[16], int split, int in_place,
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = -1;
    int ok = 0;

    if (aad_len > (size_t)INT_MAX || ciphertext_len > (size_t)INT_MAX)
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0
        || !set_tag(ctx, tag)
        || !update_aad(ctx, aad, aad_len, split)
        || !update_payload(ctx, plaintext, ciphertext, ciphertext_len, split,
            in_place)
        || EVP_DecryptFinal_ex(ctx, plaintext + ciphertext_len, &outl) <= 0
        || outl != 0)
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_segmentation_and_sizes(EVP_CIPHER *wrapper,
    EVP_CIPHER *reference)
{
    static const size_t sizes[] = { 0, 1, 16, 16385 };
    unsigned char aad_long[37];
    unsigned char *plaintext = NULL;
    unsigned char *wrapper_ct = NULL;
    unsigned char *reference_ct = NULL;
    unsigned char *recovered = NULL;
    size_t capacity = sizes[ARRAY_SIZE(sizes) - 1] + EVP_MAX_BLOCK_LENGTH;
    size_t i, j;
    int ok = 0;

    plaintext = OPENSSL_malloc(capacity);
    wrapper_ct = OPENSSL_malloc(capacity);
    reference_ct = OPENSSL_malloc(capacity);
    recovered = OPENSSL_malloc(capacity);
    CHECK(plaintext != NULL && wrapper_ct != NULL && reference_ct != NULL
        && recovered != NULL);
    for (i = 0; i < capacity; i++)
        plaintext[i] = (unsigned char)((i * 131U + 17U) & 0xffU);
    for (i = 0; i < sizeof(aad_long); i++)
        aad_long[i] = (unsigned char)(0x80U + (unsigned int)i);

    for (i = 0; i < ARRAY_SIZE(sizes); i++) {
        const unsigned char *caller_aad = i == 0 ? NULL
                                                 : (i == 2 ? aad_long : aad1);
        size_t caller_aad_len = i == 0 ? 0
                                       : (i == 2 ? sizeof(aad_long) : sizeof(aad1));
        int split = i >= 2;
        int in_place = (i & 1U) != 0;
        unsigned char wrapper_tag[16];
        unsigned char reference_tag[16];

        memset(wrapper_ct, 0xa5, capacity);
        memset(reference_ct, 0x5a, capacity);
        CHECK(encrypt_profile_case(wrapper, NULL, 0, caller_aad,
            caller_aad_len, plaintext, sizes[i], split, in_place, wrapper_ct,
            wrapper_tag));
        CHECK(encrypt_profile_case(reference, manifest, sizeof(manifest),
            caller_aad, caller_aad_len, plaintext, sizes[i], split, in_place,
            reference_ct, reference_tag));
        CHECK(memcmp(wrapper_ct, reference_ct, sizes[i]) == 0);
        CHECK(memcmp(wrapper_tag, reference_tag, sizeof(wrapper_tag)) == 0);

        memset(recovered, 0xc3, capacity);
        CHECK(decrypt_profile_case(wrapper, caller_aad, caller_aad_len,
            wrapper_ct, sizes[i], wrapper_tag, split, in_place, recovered));
        CHECK(memcmp(recovered, plaintext, sizes[i]) == 0);
        for (j = sizes[i]; j < sizes[i] + 8; j++)
            CHECK(recovered[j] == 0xc3);
    }
    ok = 1;
end:
    OPENSSL_free(recovered);
    OPENSSL_free(reference_ct);
    OPENSSL_free(wrapper_ct);
    OPENSSL_free(plaintext);
    return ok;
}

static int test_staged_initialization(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[sizeof(plaintext1) + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];
    size_t iv_length = 12;
    OSSL_PARAM iv_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_length),
        OSSL_PARAM_END
    };
    int outl = -1;
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) > 0);
    CHECK(EVP_CIPHER_CTX_set_params(ctx, iv_params) > 0);
    CHECK(EVP_EncryptInit_ex2(ctx, NULL, key, NULL, NULL) > 0);
    CHECK(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL) > 0);
    CHECK(EVP_EncryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) > 0);
    CHECK(outl == (int)sizeof(aad1));
    CHECK(EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext1,
              (int)sizeof(plaintext1))
        > 0);
    CHECK(outl == (int)sizeof(plaintext1));
    CHECK(EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl) > 0 && outl == 0);
    CHECK(get_tag(ctx, tag));
    CHECK(memcmp(ciphertext, ciphertext1, sizeof(ciphertext1)) == 0);
    CHECK(memcmp(tag, tag1, sizeof(tag1)) == 0);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_forbidden_legacy_controls(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char tls_aad[EVP_AEAD_TLS1_AAD_LEN] = { 0 };
    unsigned char scratch[64] = { 0 };
    EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM multiblock = {
        scratch, scratch, sizeof(scratch), 1
    };
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
              (int)sizeof(tls_aad), tls_aad)
        <= 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, 4,
              scratch)
        <= 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, 8, scratch) <= 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_INV, 8,
              scratch)
        <= 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, 16,
              scratch)
        <= 0);
#if !defined(OPENSSL_NO_MULTIBLOCK)
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE,
              1024, NULL)
        <= 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_AAD,
              (int)sizeof(multiblock), &multiblock)
        <= 0);
    CHECK(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT,
              (int)sizeof(multiblock), &multiblock)
        <= 0);
#endif
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_forbidden_init_params(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char tls_aad[EVP_AEAD_TLS1_AAD_LEN] = { 0 };
    unsigned char tls_iv_fixed[EVP_GCM_TLS_FIXED_IV_LEN] = { 0 };
    OSSL_PARAM tls_aad_params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, tls_aad,
            sizeof(tls_aad)),
        OSSL_PARAM_END
    };
    OSSL_PARAM tls_iv_params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
            tls_iv_fixed, sizeof(tls_iv_fixed)),
        OSSL_PARAM_END
    };
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, tls_aad_params) <= 0);
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, tls_iv_params) <= 0);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_default_provider_absent(const char *module_dir)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *provider = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    libctx = OSSL_LIB_CTX_new();
    CHECK(libctx != NULL);
    CHECK(OSSL_PROVIDER_set_default_search_path(libctx, module_dir) > 0);
    provider = OSSL_PROVIDER_load(libctx, "g301");
    CHECK(provider != NULL);
    cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME, PROPERTY_QUERY);
    CHECK(cipher != NULL);
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(libctx);
    return ok;
}

static int test_fips_inheritance(OSSL_LIB_CTX *libctx)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    CHECK(EVP_set_default_properties(libctx, "fips=yes") > 0);
    cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME,
        "provider=g301,fips=no");
    CHECK(cipher != NULL);
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0);
    CHECK(EVP_set_default_properties(libctx, NULL) > 0);
    ok = 1;
end:
    if (!ok)
        (void)EVP_set_default_properties(libctx, NULL);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int test_provider_property_inheritance(OSSL_LIB_CTX *libctx)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    CHECK(EVP_set_default_properties(libctx, "provider=fips") > 0);
    cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME,
        "provider=g301,fips=no");
    CHECK(cipher != NULL);
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    /* The explicit inner provider=default clause overrides inherited provider. */
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    CHECK(EVP_set_default_properties(libctx, NULL) > 0);
    ok = 1;
end:
    if (!ok)
        (void)EVP_set_default_properties(libctx, NULL);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int test_provider_unload_with_live_context(const char *module_dir)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[sizeof(plaintext1) + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];
    int outl = -1;
    int ok = 0;

    libctx = OSSL_LIB_CTX_new();
    CHECK(libctx != NULL);
    CHECK(OSSL_PROVIDER_set_default_search_path(libctx, module_dir) > 0);
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    g301_provider = OSSL_PROVIDER_load(libctx, "g301");
    CHECK(default_provider != NULL && g301_provider != NULL);
    cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME, PROPERTY_QUERY);
    CHECK(cipher != NULL);
    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    CHECK(OSSL_PROVIDER_unload(g301_provider) > 0);
    g301_provider = NULL;
    CHECK(EVP_EncryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) > 0);
    CHECK(EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext1,
              (int)sizeof(plaintext1))
        > 0);
    CHECK(EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl) > 0 && outl == 0);
    CHECK(get_tag(ctx, tag));
    CHECK(memcmp(ciphertext, ciphertext1, sizeof(ciphertext1)) == 0);
    CHECK(memcmp(tag, tag1, sizeof(tag1)) == 0);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return ok;
}

/* OpenSSL provider-lifecycle pattern: repeated fresh libctx load/use/unload. */
static int test_repeated_load_unload(const char *module_dir)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    EVP_CIPHER *cipher = NULL;
    size_t iteration;
    int ok = 0;

    for (iteration = 0; iteration < 100; iteration++) {
        unsigned char ciphertext[sizeof(plaintext1)] = { 0 };
        unsigned char tag[16] = { 0 };

        libctx = OSSL_LIB_CTX_new();
        CHECK(libctx != NULL);
        CHECK(OSSL_PROVIDER_set_default_search_path(libctx, module_dir) > 0);
        default_provider = OSSL_PROVIDER_load(libctx, "default");
        g301_provider = OSSL_PROVIDER_load(libctx, "g301");
        CHECK(default_provider != NULL && g301_provider != NULL);
        cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME, PROPERTY_QUERY);
        CHECK(cipher != NULL);
        CHECK(encrypt_with_aad(cipher, NULL, 0, &kats[0], ciphertext, tag));
        CHECK(memcmp(ciphertext, ciphertext1, sizeof(ciphertext1)) == 0);
        CHECK(memcmp(tag, tag1, sizeof(tag1)) == 0);

        EVP_CIPHER_free(cipher);
        cipher = NULL;
        CHECK(OSSL_PROVIDER_unload(g301_provider) > 0);
        g301_provider = NULL;
        CHECK(OSSL_PROVIDER_unload(default_provider) > 0);
        default_provider = NULL;
        OSSL_LIB_CTX_free(libctx);
        libctx = NULL;
    }
    ok = 1;
end:
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return ok;
}

/* OpenSSL libctx-isolation pattern: two provider instances, reverse teardown. */
static int test_two_library_contexts(const char *module_dir)
{
    OSSL_LIB_CTX *libctx[2] = { NULL, NULL };
    OSSL_PROVIDER *default_provider[2] = { NULL, NULL };
    OSSL_PROVIDER *g301_provider[2] = { NULL, NULL };
    EVP_CIPHER *cipher[2] = { NULL, NULL };
    unsigned char ciphertext[2][sizeof(plaintext1)] = { { 0 }, { 0 } };
    unsigned char tag[2][16] = { { 0 }, { 0 } };
    size_t i;
    int ok = 0;

    for (i = 0; i < ARRAY_SIZE(libctx); i++) {
        libctx[i] = OSSL_LIB_CTX_new();
        CHECK(libctx[i] != NULL);
        CHECK(OSSL_PROVIDER_set_default_search_path(libctx[i], module_dir)
            > 0);
        default_provider[i] = OSSL_PROVIDER_load(libctx[i], "default");
        g301_provider[i] = OSSL_PROVIDER_load(libctx[i], "g301");
        CHECK(default_provider[i] != NULL && g301_provider[i] != NULL);
        cipher[i] = EVP_CIPHER_fetch(libctx[i], WORKING_NAME, PROPERTY_QUERY);
        CHECK(cipher[i] != NULL);
        CHECK(encrypt_with_aad(cipher[i], NULL, 0, &kats[0], ciphertext[i],
            tag[i]));
        CHECK(memcmp(ciphertext[i], ciphertext1, sizeof(ciphertext1)) == 0);
        CHECK(memcmp(tag[i], tag1, sizeof(tag1)) == 0);
    }

    EVP_CIPHER_free(cipher[1]);
    cipher[1] = NULL;
    CHECK(OSSL_PROVIDER_unload(g301_provider[1]) > 0);
    g301_provider[1] = NULL;
    CHECK(OSSL_PROVIDER_unload(default_provider[1]) > 0);
    default_provider[1] = NULL;
    OSSL_LIB_CTX_free(libctx[1]);
    libctx[1] = NULL;

    memset(ciphertext[0], 0, sizeof(ciphertext[0]));
    memset(tag[0], 0, sizeof(tag[0]));
    CHECK(encrypt_with_aad(cipher[0], NULL, 0, &kats[0], ciphertext[0],
        tag[0]));
    CHECK(memcmp(ciphertext[0], ciphertext1, sizeof(ciphertext1)) == 0);
    CHECK(memcmp(tag[0], tag1, sizeof(tag1)) == 0);
    ok = 1;
end:
    for (i = 0; i < ARRAY_SIZE(libctx); i++) {
        EVP_CIPHER_free(cipher[i]);
        OSSL_PROVIDER_unload(g301_provider[i]);
        OSSL_PROVIDER_unload(default_provider[i]);
        OSSL_LIB_CTX_free(libctx[i]);
    }
    return ok;
}

static int test_dupctx_clean_failure(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *duplicate = NULL;
    unsigned char output[sizeof(plaintext1)];
    int outl = -1;
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL);
    CHECK(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0);
    CHECK(EVP_EncryptUpdate(ctx, NULL, &outl, aad1, (int)sizeof(aad1)) > 0);
    duplicate = EVP_CIPHER_CTX_new();
    if (duplicate != NULL && EVP_CIPHER_CTX_copy(duplicate, ctx) <= 0) {
        EVP_CIPHER_CTX_free(duplicate);
        duplicate = NULL;
    }
    CHECK(duplicate == NULL);
    ERR_clear_error();
    CHECK(EVP_EncryptUpdate(ctx, output, &outl, plaintext1,
              (int)sizeof(plaintext1))
        > 0);
    CHECK(outl == (int)sizeof(plaintext1));
    ok = 1;
end:
    EVP_CIPHER_CTX_free(duplicate);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

typedef struct thread_case_st {
    EVP_CIPHER *cipher;
    int ok;
} THREAD_CASE;

static void *run_thread_case(void *arg)
{
    THREAD_CASE *thread_case = arg;
    size_t iteration;

    thread_case->ok = 0;
    for (iteration = 0; iteration < 100; iteration++) {
        unsigned char ciphertext[sizeof(plaintext1)] = { 0 };
        unsigned char tag[16] = { 0 };

        if (!encrypt_with_aad(thread_case->cipher, NULL, 0, &kats[0],
                ciphertext, tag)
            || memcmp(ciphertext, ciphertext1, sizeof(ciphertext1)) != 0
            || memcmp(tag, tag1, sizeof(tag1)) != 0)
            return NULL;
    }
    thread_case->ok = 1;
    return NULL;
}

static int test_independent_concurrent_contexts(EVP_CIPHER *cipher)
{
    pthread_t threads[4];
    THREAD_CASE cases[ARRAY_SIZE(threads)];
    size_t created = 0;
    size_t i;
    int ok = 0;

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        cases[i].cipher = cipher;
        cases[i].ok = 0;
        if (pthread_create(&threads[i], NULL, run_thread_case, &cases[i]) != 0)
            goto end;
        created++;
    }
    for (i = 0; i < created; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(cases[i].ok);
    }
    created = 0;
    ok = 1;
end:
    for (i = 0; i < created; i++)
        (void)pthread_join(threads[i], NULL);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    OSSL_PROVIDER *g301_provider_second = NULL;
    EVP_CIPHER *wrapper = NULL;
    EVP_CIPHER *reference = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }
    libctx = OSSL_LIB_CTX_new();
    CHECK(libctx != NULL);
    CHECK(OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) > 0);
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    CHECK(default_provider != NULL);
    g301_provider = OSSL_PROVIDER_load(libctx, "g301");
    CHECK(g301_provider != NULL);
    g301_provider_second = OSSL_PROVIDER_load(libctx, "g301");
    CHECK(g301_provider_second != NULL);

    wrapper = EVP_CIPHER_fetch(libctx, WORKING_NAME, PROPERTY_QUERY);
    reference = EVP_CIPHER_fetch(libctx, "AES-256-GCM", "provider=default");
    CHECK(wrapper != NULL && reference != NULL);
    CHECK(test_fetch_and_params(libctx, wrapper));
    CHECK(test_kats(wrapper, reference));
    CHECK(test_fixed_tag_getter(wrapper));
    CHECK(test_lifecycle(wrapper));
    CHECK(test_parameter_surface(wrapper));
    CHECK(test_segmentation_and_sizes(wrapper, reference));
    CHECK(test_staged_initialization(wrapper));
    CHECK(test_forbidden_legacy_controls(wrapper));
    CHECK(test_forbidden_init_params(wrapper));
    CHECK(test_dupctx_clean_failure(wrapper));
    CHECK(test_independent_concurrent_contexts(wrapper));
    CHECK(test_provider_property_inheritance(libctx));
    CHECK(test_fips_inheritance(libctx));
    CHECK(test_default_provider_absent(argv[1]));
    CHECK(test_provider_unload_with_live_context(argv[1]));
    CHECK(test_repeated_load_unload(argv[1]));
    CHECK(test_two_library_contexts(argv[1]));

end:
    EVP_CIPHER_free(reference);
    EVP_CIPHER_free(wrapper);
    OSSL_PROVIDER_unload(g301_provider_second);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    if (failures != 0) {
        fprintf(stderr, "%d integration assertion(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("g301 integration tests: ok");
    return EXIT_SUCCESS;
}
