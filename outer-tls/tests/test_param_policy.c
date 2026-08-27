/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "g301_internal.h"

#define G301_NAME "G301-AES-256-GCM-V1"
#define G301_QUERY "provider=g301,fips=no"
#define G301_CIPHER_PARAM_ENCRYPT_THEN_MAC "encrypt-then-mac"

typedef enum param_type_st {
    PARAM_INT,
    PARAM_SIZE,
    PARAM_OCTET_PTR
} PARAM_TYPE;

typedef struct rejected_param_st {
    const char *name;
    PARAM_TYPE type;
} REJECTED_PARAM;

static const unsigned char key[32] = { 0x30, 0x01 };
static const unsigned char iv[12] = { 0x30, 0x01 };

static const REJECTED_PARAM rejected[] = {
    { OSSL_CIPHER_PARAM_TLS_VERSION, PARAM_INT },
    { OSSL_CIPHER_PARAM_TLS_MAC_SIZE, PARAM_SIZE },
    { OSSL_CIPHER_PARAM_TLS_MAC, PARAM_OCTET_PTR },
    { G301_CIPHER_PARAM_ENCRYPT_THEN_MAC, PARAM_INT }
};

static int error_queue_contains_reason(int expected_reason)
{
    unsigned long error;
    int found = 0;

    while ((error = ERR_get_error()) != 0) {
        if (ERR_GET_REASON(error) == expected_reason)
            found = 1;
    }
    return found;
}

static OSSL_PARAM make_rejected_param(const REJECTED_PARAM *entry,
    int *int_value, size_t *size_value, void **pointer_value,
    unsigned char *buffer, size_t buffer_size)
{
    switch (entry->type) {
    case PARAM_INT:
        return OSSL_PARAM_construct_int(entry->name, int_value);
    case PARAM_SIZE:
        return OSSL_PARAM_construct_size_t(entry->name, size_value);
    case PARAM_OCTET_PTR:
        *pointer_value = buffer;
        return OSSL_PARAM_construct_octet_ptr(entry->name, pointer_value,
            buffer_size);
    }
    return OSSL_PARAM_construct_end();
}

static EVP_CIPHER_CTX *new_initialized(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL || EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int rejected_on_all_surfaces(EVP_CIPHER *cipher,
    const REJECTED_PARAM *entry)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char buffer[20] = { 0 };
    void *pointer_value = buffer;
    size_t size_value = sizeof(buffer);
    int int_value = 0x0303;
    OSSL_PARAM params[2];
    int ok = 0;

    params[0] = make_rejected_param(entry, &int_value, &size_value,
        &pointer_value, buffer, sizeof(buffer));
    params[1] = OSSL_PARAM_construct_end();
    ERR_clear_error();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    EVP_CIPHER_CTX_free(ctx);
    ctx = new_initialized(cipher);
    ERR_clear_error();
    if (ctx == NULL || EVP_CIPHER_CTX_set_params(ctx, params) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    EVP_CIPHER_CTX_free(ctx);
    ctx = new_initialized(cipher);
    ERR_clear_error();
    if (ctx == NULL || EVP_CIPHER_CTX_get_params(ctx, params) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    return ok;
}

static int exact_tag_length_policy(EVP_CIPHER *cipher)
{
    EVP_CIPHER_CTX *ctx = NULL;
    size_t taglen8 = 8;
    size_t taglen16 = 16;
    size_t returned = 0;
    unsigned char wrong_type[sizeof(size_t)] = { 0 };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen8),
        OSSL_PARAM_END
    };
    OSSL_PARAM good[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen16),
        OSSL_PARAM_END
    };
    OSSL_PARAM duplicate[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen16),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen16),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAGLEN, wrong_type,
            sizeof(wrong_type)),
        OSSL_PARAM_END
    };
    OSSL_PARAM get[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &returned),
        OSSL_PARAM_END
    };
    OSSL_PARAM get_duplicate[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &returned),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &returned),
        OSSL_PARAM_END
    };
    OSSL_PARAM get_wrong[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAGLEN, wrong_type,
            sizeof(wrong_type)),
        OSSL_PARAM_END
    };
    int ok = 0;

    ERR_clear_error();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex2(ctx, cipher, key, iv, bad) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex2(ctx, cipher, key, iv, wrong) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_EncryptInit_ex2(ctx, cipher, key, iv, duplicate) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex2(ctx, cipher, key, iv, good) <= 0)
        goto end;
    if (EVP_CIPHER_CTX_get_params(ctx, get) <= 0 || returned != 16)
        goto end;
    ERR_clear_error();
    if (EVP_CIPHER_CTX_get_params(ctx, get_duplicate) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    ERR_clear_error();
    if (EVP_CIPHER_CTX_get_params(ctx, get_wrong) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    ERR_clear_error();
    if (EVP_CIPHER_CTX_set_params(ctx, bad) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    ERR_clear_error();
    if (EVP_CIPHER_CTX_set_params(ctx, wrong) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    ERR_clear_error();
    if (EVP_CIPHER_CTX_set_params(ctx, duplicate) > 0
        || !error_queue_contains_reason(G301_R_INVALID_PARAMETER))
        goto end;
    ERR_clear_error();
    if (EVP_CIPHER_CTX_set_params(ctx, good) <= 0)
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    EVP_CIPHER *cipher = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE_DIR\n", argv[0]);
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
    cipher = EVP_CIPHER_fetch(libctx, G301_NAME, G301_QUERY);
    if (cipher == NULL)
        goto end;
    for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        if (!rejected_on_all_surfaces(cipher, &rejected[i])) {
            fprintf(stderr, "parameter was not rejected: %s\n",
                rejected[i].name);
            goto end;
        }
    }
    if (!exact_tag_length_policy(cipher)) {
        fputs("tag-length policy failed\n", stderr);
        goto end;
    }
    ok = 1;
end:
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    if (ok)
        puts("g301 parameter policy: 12 forbidden surfaces and fixed tag length ok");
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
