/* SPDX-License-Identifier: Apache-2.0 */

#include "g301_internal.h"

#include <openssl/evp.h>

typedef struct g301_evp_inner_ctx_st {
    EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *cipher_ctx;
    int initialized;
} G301_EVP_INNER_CTX;

static void *g301_evp_newctx(void *arg)
{
    OSSL_LIB_CTX *libctx = arg;
    G301_EVP_INNER_CTX *inner = OPENSSL_zalloc(sizeof(*inner));

    if (inner == NULL)
        return NULL;

    inner->cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM",
        "provider=default");
    inner->cipher_ctx = EVP_CIPHER_CTX_new();
    if (inner->cipher == NULL || inner->cipher_ctx == NULL) {
        EVP_CIPHER_CTX_free(inner->cipher_ctx);
        EVP_CIPHER_free(inner->cipher);
        OPENSSL_clear_free(inner, sizeof(*inner));
        return NULL;
    }
    return inner;
}

static void g301_evp_freectx(void *vinner)
{
    G301_EVP_INNER_CTX *inner = vinner;

    if (inner == NULL)
        return;
    EVP_CIPHER_CTX_free(inner->cipher_ctx);
    EVP_CIPHER_free(inner->cipher);
    OPENSSL_clear_free(inner, sizeof(*inner));
}

static int g301_evp_init(void *vinner, const unsigned char *key,
    const unsigned char *iv, int encrypt, const OSSL_PARAM params[])
{
    G301_EVP_INNER_CTX *inner = vinner;
    const EVP_CIPHER *cipher = inner->initialized ? NULL : inner->cipher;
    int ok;

    ok = EVP_CipherInit_ex2(inner->cipher_ctx, cipher, key, iv, encrypt,
        params);
    if (ok > 0)
        inner->initialized = 1;
    return ok > 0;
}

static int g301_evp_update(void *vinner, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{
    G301_EVP_INNER_CTX *inner = vinner;

    return EVP_CipherUpdate(inner->cipher_ctx, out, outl, in, inl) > 0;
}

static int g301_evp_final(void *vinner, unsigned char *out, int *outl)
{
    G301_EVP_INNER_CTX *inner = vinner;

    return EVP_CipherFinal_ex(inner->cipher_ctx, out, outl) > 0;
}

static int g301_evp_get_params(void *vinner, OSSL_PARAM params[])
{
    G301_EVP_INNER_CTX *inner = vinner;

    return EVP_CIPHER_CTX_get_params(inner->cipher_ctx, params) > 0;
}

static int g301_evp_set_params(void *vinner, const OSSL_PARAM params[])
{
    G301_EVP_INNER_CTX *inner = vinner;

    return EVP_CIPHER_CTX_set_params(inner->cipher_ctx, params) > 0;
}

const G301_INNER_OPS g301_evp_inner_ops = {
    g301_evp_newctx,
    g301_evp_freectx,
    g301_evp_init,
    g301_evp_update,
    g301_evp_final,
    g301_evp_get_params,
    g301_evp_set_params
};
