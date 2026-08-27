/* SPDX-License-Identifier: Apache-2.0 */

#ifndef G301_INTERNAL_H
#define G301_INTERNAL_H

#include <stddef.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#define G301_WORKING_NAME "G301-AES-256-GCM-V1"
#define G301_PROPERTY_DEFINITION "provider=g301,fips=no"
#define G301_KEY_LENGTH ((size_t)32)
#define G301_IV_LENGTH ((size_t)12)
#define G301_TAG_LENGTH ((size_t)16)
#define G301_MANIFEST_LENGTH ((size_t)32)

typedef struct g301_inner_ops_st {
    void *(*newctx)(void *arg);
    void (*freectx)(void *inner);
    int (*init)(void *inner, const unsigned char *key,
        const unsigned char *iv, int encrypt,
        const OSSL_PARAM params[]);
    int (*update)(void *inner, unsigned char *out, int *outl,
        const unsigned char *in, int inl);
    int (*final)(void *inner, unsigned char *out, int *outl);
    int (*get_params)(void *inner, OSSL_PARAM params[]);
    int (*set_params)(void *inner, const OSSL_PARAM params[]);
} G301_INNER_OPS;

typedef struct g301_provider_ctx_st {
    OSSL_LIB_CTX *child_libctx;
    const G301_INNER_OPS *inner_ops;
    void *inner_arg;
    const OSSL_CORE_HANDLE *handle;
    OSSL_FUNC_core_new_error_fn *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *core_vset_error;
} G301_PROVIDER_CTX;

enum {
    G301_R_INVALID_PARAMETER = 1,
    G301_R_INVALID_STATE,
    G301_R_OUTPUT_BUFFER_TOO_SMALL,
    G301_R_INTERNAL_ERROR
};

extern const G301_INNER_OPS g301_evp_inner_ops;
extern const OSSL_DISPATCH g301_cipher_functions[];

#ifdef G301_TESTING
void *g301_test_cipher_newctx(G301_PROVIDER_CTX *provctx);
void g301_test_cipher_freectx(void *vctx);
int g301_test_cipher_encrypt_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[]);
int g301_test_cipher_decrypt_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[]);
int g301_test_cipher_update(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl);
int g301_test_cipher_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize);
int g301_test_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int g301_test_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
#endif

#endif
