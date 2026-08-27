/* SPDX-License-Identifier: Apache-2.0 */

#include "g301_internal.h"
#include "g301_tls_capability.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

#if defined(__GNUC__) || defined(__clang__)
#define G301_EXPORT __attribute__((visibility("default")))
#else
#define G301_EXPORT
#endif

static const OSSL_PARAM g301_provider_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *g301_provider_gettable_params(void *provctx)
{
    (void)provctx;
    return g301_provider_param_types;
}

static int g301_provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *param;

    (void)provctx;
    if (params == NULL)
        return 1;

    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (param != NULL
        && !OSSL_PARAM_set_utf8_ptr(param,
            "G301 Alpha/Beta EVP-only provider"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, "0.1.0-alpha"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (param != NULL
        && !OSSL_PARAM_set_utf8_ptr(param,
            "bounded EVP prototype; provider-defined TLS suite descriptor; "
            "requires compatible patched libssl"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (param != NULL && !OSSL_PARAM_set_int(param, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM g301_ciphers[] = {
    { G301_WORKING_NAME,
        G301_PROPERTY_DEFINITION,
        g301_cipher_functions,
        "Alpha/Beta fixed-manifest AES-256-GCM EVP decorator" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ITEM g301_reason_strings[] = {
    { G301_R_INVALID_PARAMETER, "invalid parameter" },
    { G301_R_INVALID_STATE, "invalid cipher state" },
    { G301_R_OUTPUT_BUFFER_TOO_SMALL, "output buffer too small" },
    { G301_R_INTERNAL_ERROR, "internal cipher contract violation" },
    { 0, NULL }
};

static const OSSL_ITEM *g301_provider_get_reason_strings(void *provctx)
{
    (void)provctx;
    return g301_reason_strings;
}

#ifdef OSSL_FUNC_PROVIDER_GET_CAPABILITIES
static unsigned int g301_tls_working_code_point = G301_TLS_WORKING_CODE_POINT;
static unsigned int g301_tls_tag_length = (unsigned int)G301_TAG_LENGTH;
static unsigned int g301_tls_security_bits = G301_TLS_SECURITY_BITS;

static const OSSL_PARAM g301_tls_ciphersuite_params[] = {
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_CIPHERSUITE_NAME,
        G301_WORKING_NAME, sizeof(G301_WORKING_NAME)),
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_CIPHERSUITE_CODE_POINT,
        &g301_tls_working_code_point),
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_CIPHERSUITE_AEAD_NAME,
        G301_WORKING_NAME, sizeof(G301_WORKING_NAME)),
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_CIPHERSUITE_DIGEST_NAME,
        G301_TLS_DIGEST_NAME, sizeof(G301_TLS_DIGEST_NAME)),
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_CIPHERSUITE_TAG_LENGTH,
        &g301_tls_tag_length),
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_CIPHERSUITE_SECURITY_BITS,
        &g301_tls_security_bits),
    OSSL_PARAM_END
};

static int g301_provider_get_capabilities(void *provctx,
    const char *capability, OSSL_CALLBACK *cb, void *arg)
{
    (void)provctx;
    if (capability == NULL || cb == NULL)
        return 0;
    if (strcmp(capability, G301_TLS_CIPHERSUITE_CAPABILITY) != 0)
        return 0;
    return cb(g301_tls_ciphersuite_params, arg);
}
#endif

static const OSSL_ALGORITHM *g301_provider_query_operation(void *provctx,
    int operation_id, int *no_cache)
{
    (void)provctx;
    if (no_cache != NULL)
        *no_cache = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return g301_ciphers;
    return NULL;
}

static void g301_provider_teardown(void *vprovctx)
{
    G301_PROVIDER_CTX *provctx = vprovctx;

    if (provctx == NULL)
        return;
    OSSL_LIB_CTX_free(provctx->child_libctx);
    OPENSSL_clear_free(provctx, sizeof(*provctx));
}

static const OSSL_DISPATCH g301_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))g301_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))g301_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
        (void (*)(void))g301_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        (void (*)(void))g301_provider_query_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
        (void (*)(void))g301_provider_get_reason_strings },
#ifdef OSSL_FUNC_PROVIDER_GET_CAPABILITIES
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))g301_provider_get_capabilities },
#endif
    OSSL_DISPATCH_END
};

G301_EXPORT OSSL_provider_init_fn OSSL_provider_init;

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    G301_PROVIDER_CTX *ctx;
    const OSSL_DISPATCH *dispatch;

    if (in == NULL || out == NULL || provctx == NULL)
        return 0;
    *out = NULL;
    *provctx = NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;
    ctx->handle = handle;
    for (dispatch = in; dispatch->function_id != 0; dispatch++) {
        switch (dispatch->function_id) {
        case OSSL_FUNC_CORE_NEW_ERROR:
            ctx->core_new_error = OSSL_FUNC_core_new_error(dispatch);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            ctx->core_set_error_debug = OSSL_FUNC_core_set_error_debug(
                dispatch);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            ctx->core_vset_error = OSSL_FUNC_core_vset_error(dispatch);
            break;
        default:
            break;
        }
    }
    if (ctx->core_new_error == NULL || ctx->core_set_error_debug == NULL
        || ctx->core_vset_error == NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return 0;
    }
    ctx->child_libctx = OSSL_LIB_CTX_new_child(handle, in);
    if (ctx->child_libctx == NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return 0;
    }
    ctx->inner_ops = &g301_evp_inner_ops;
    ctx->inner_arg = ctx->child_libctx;

    *provctx = ctx;
    *out = g301_provider_functions;
    return 1;
}
