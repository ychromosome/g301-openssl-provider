/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include "g301_tls_capability.h"

#define G301_EXPECTED_PARAMETER_COUNT 6U

typedef struct capability_result_st {
    unsigned int calls;
    int valid;
} CAPABILITY_RESULT;

static int check_utf8(const OSSL_PARAM params[], const char *key,
    const char *expected)
{
    const OSSL_PARAM *param = OSSL_PARAM_locate_const(params, key);

    return param != NULL && param->data_type == OSSL_PARAM_UTF8_STRING
        && param->data != NULL
        && param->data_size == strlen(expected) + 1U
        && strcmp(param->data, expected) == 0;
}

static int check_uint(const OSSL_PARAM params[], const char *key,
    unsigned int expected)
{
    const OSSL_PARAM *param = OSSL_PARAM_locate_const(params, key);
    unsigned int value = 0;

    return param != NULL && param->data_type == OSSL_PARAM_UNSIGNED_INTEGER
        && param->data_size == sizeof(value)
        && OSSL_PARAM_get_uint(param, &value) > 0 && value == expected;
}

static int inspect_capability(const OSSL_PARAM params[], void *arg)
{
    CAPABILITY_RESULT *result = arg;
    size_t count = 0;

    result->calls++;
    while (params[count].key != NULL)
        count++;
    result->valid = result->calls == 1U
        && count == G301_EXPECTED_PARAMETER_COUNT
        && check_utf8(params, OSSL_CAPABILITY_TLS_CIPHERSUITE_NAME,
            G301_WORKING_NAME)
        && check_uint(params, OSSL_CAPABILITY_TLS_CIPHERSUITE_CODE_POINT,
            G301_TLS_WORKING_CODE_POINT)
        && check_utf8(params, OSSL_CAPABILITY_TLS_CIPHERSUITE_AEAD_NAME,
            G301_WORKING_NAME)
        && check_utf8(params, OSSL_CAPABILITY_TLS_CIPHERSUITE_DIGEST_NAME,
            G301_TLS_DIGEST_NAME)
        && check_uint(params, OSSL_CAPABILITY_TLS_CIPHERSUITE_TAG_LENGTH,
            (unsigned int)G301_TAG_LENGTH)
        && check_uint(params, OSSL_CAPABILITY_TLS_CIPHERSUITE_SECURITY_BITS,
            G301_TLS_SECURITY_BITS);
    return result->valid;
}

static int reject_capability(const OSSL_PARAM params[], void *arg)
{
    unsigned int *calls = arg;

    (void)params;
    (*calls)++;
    return 0;
}

static int count_unexpected_callback(const OSSL_PARAM params[], void *arg)
{
    unsigned int *calls = arg;

    (void)params;
    (*calls)++;
    return 1;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    CAPABILITY_RESULT result = { 0, 0 };
    unsigned int rejecting_calls = 0;
    unsigned int unexpected_calls = 0;
    int ok = 0;

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

    if (OSSL_PROVIDER_get_capabilities(g301_provider,
            G301_TLS_CIPHERSUITE_CAPABILITY, inspect_capability, &result)
            <= 0
        || result.calls != 1U || !result.valid)
        goto end;
    if (OSSL_PROVIDER_get_capabilities(g301_provider,
            G301_TLS_CIPHERSUITE_CAPABILITY, reject_capability,
            &rejecting_calls)
            != 0
        || rejecting_calls != 1U)
        goto end;
    if (OSSL_PROVIDER_get_capabilities(g301_provider, "TLS-GROUP",
            count_unexpected_callback, &unexpected_calls)
            != 0
        || unexpected_calls != 0U)
        goto end;
    if (OSSL_PROVIDER_get_capabilities(g301_provider, NULL,
            count_unexpected_callback, &unexpected_calls)
            != 0
        || unexpected_calls != 0U)
        goto end;
    if (OSSL_PROVIDER_get_capabilities(g301_provider,
            G301_TLS_CIPHERSUITE_CAPABILITY, NULL, &unexpected_calls)
            != 0
        || unexpected_calls != 0U)
        goto end;

    ok = 1;
end:
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    if (!ok) {
        fputs("g301 capability test: failed\n", stderr);
        return EXIT_FAILURE;
    }
    puts("g301 capability test: ok (descriptor only; patched libssl required)");
    return EXIT_SUCCESS;
}
