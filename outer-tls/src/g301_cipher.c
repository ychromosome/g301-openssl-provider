/* SPDX-License-Identifier: Apache-2.0 */

#include "g301_internal.h"

#include <limits.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

/* Public cipher parameter added by OpenSSL 4; reject it on ABI 3 as well. */
#define G301_CIPHER_PARAM_ENCRYPT_THEN_MAC "encrypt-then-mac"
/* Public on newer OpenSSL; retain the wire spelling for ABI-3 denylisting. */
#define G301_CIPHER_PARAM_PIPELINE_AEAD_TAG "pipeline-tag"

typedef enum g301_phase_st {
    G301_PHASE_NO_RECORD = 0,
    G301_PHASE_MANIFEST_PENDING,
    G301_PHASE_ACTIVE,
    G301_PHASE_FINALIZED
} G301_PHASE;

typedef struct g301_cipher_ctx_st {
    const G301_INNER_OPS *ops;
    void *inner;
    const OSSL_CORE_HANDLE *handle;
    OSSL_FUNC_core_new_error_fn *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *core_vset_error;
    G301_PHASE phase;
    int encrypt;
    int direction_set;
    int key_valid;
    int needs_reinit;
    int decrypt_tag_current;
    int payload_started;
    CRYPTO_RWLOCK *usage_lock;
    unsigned char current_key[G301_KEY_LENGTH];
    unsigned char usage_key[G301_KEY_LENGTH];
    int encrypted_records;
    int record_limit;
    int current_key_valid;
    int current_key_changed;
    int usage_key_valid;
    int usage_exhausted;
    int record_reserved;
} G301_CIPHER_CTX;

static void g301_raise_error(G301_CIPHER_CTX *ctx, uint32_t reason,
    const char *file, int line, const char *func, const char *fmt, ...)
{
    va_list args;

    if (ctx == NULL || ctx->core_new_error == NULL
        || ctx->core_set_error_debug == NULL || ctx->core_vset_error == NULL)
        return;
    ctx->core_new_error(ctx->handle);
    ctx->core_set_error_debug(ctx->handle, file, line, func);
    va_start(args, fmt);
    ctx->core_vset_error(ctx->handle, reason, fmt, args);
    va_end(args);
}

#define G301_RAISE(ctx, reason) \
    g301_raise_error((ctx), (reason), __FILE__, __LINE__, __func__, NULL)

static const unsigned char g301_manifest[G301_MANIFEST_LENGTH] = {
    0x47, 0x33, 0x30, 0x31, 0x2d, 0x54, 0x4c, 0x53,
    0x31, 0x33, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x01,
    0x04, 0x01, 0x01, 0x2d, 0x01, 0x00, 0x63, 0x01,
    0x01, 0x74, 0x01, 0x00, 0xaf, 0x02, 0x03, 0xb3
};

_Static_assert(sizeof(g301_manifest) == G301_MANIFEST_LENGTH,
    "the Alpha/Beta manifest must remain exactly 32 bytes");
_Static_assert(G301_ENCRYPT_RECORD_LIMIT <= INT_MAX,
    "the write-key record limit must fit CRYPTO_atomic_add");

static void g301_invalidate_record(G301_CIPHER_CTX *ctx)
{
    ctx->phase = G301_PHASE_NO_RECORD;
    ctx->payload_started = 0;
    ctx->decrypt_tag_current = 0;
}

static void g301_poison(G301_CIPHER_CTX *ctx)
{
    ctx->needs_reinit = 1;
    ctx->decrypt_tag_current = 0;
}

static int g301_record_current_key(G301_CIPHER_CTX *ctx,
    const unsigned char key[G301_KEY_LENGTH])
{
    int changed;

    if (!CRYPTO_THREAD_write_lock(ctx->usage_lock))
        return 0;
    changed = !ctx->current_key_valid
        || CRYPTO_memcmp(ctx->current_key, key, G301_KEY_LENGTH) != 0;
    if (changed) {
        memcpy(ctx->current_key, key, G301_KEY_LENGTH);
        ctx->current_key_valid = 1;
        ctx->current_key_changed = 1;
    }
    CRYPTO_THREAD_unlock(ctx->usage_lock);
    return 1;
}

static int g301_install_write_key(G301_CIPHER_CTX *ctx)
{
    int same_key;

    if (!ctx->current_key_valid)
        return 0;
    if (ctx->usage_key_valid && !ctx->current_key_changed) {
        ctx->record_reserved = 0;
        return 1;
    }
    if (!CRYPTO_THREAD_write_lock(ctx->usage_lock))
        return 0;
    if (!ctx->current_key_valid) {
        CRYPTO_THREAD_unlock(ctx->usage_lock);
        return 0;
    }
    same_key = ctx->usage_key_valid
        && CRYPTO_memcmp(ctx->usage_key, ctx->current_key,
               G301_KEY_LENGTH)
            == 0;
    if (!same_key) {
        memcpy(ctx->usage_key, ctx->current_key, G301_KEY_LENGTH);
        ctx->usage_key_valid = 1;
        ctx->encrypted_records = 0;
        ctx->usage_exhausted = 0;
    }
    ctx->current_key_changed = 0;
    ctx->record_reserved = 0;
    CRYPTO_THREAD_unlock(ctx->usage_lock);
    return 1;
}

static int g301_reserve_encryption_record(G301_CIPHER_CTX *ctx)
{
    int records;

    if (ctx->record_reserved)
        return 1;
    if (!ctx->usage_key_valid || ctx->usage_exhausted) {
        g301_poison(ctx);
        g301_invalidate_record(ctx);
        G301_RAISE(ctx, G301_R_KEY_USAGE_LIMIT_EXCEEDED);
        return 0;
    }
    if (!CRYPTO_atomic_add(&ctx->encrypted_records, 1, &records,
            ctx->usage_lock)) {
        g301_poison(ctx);
        g301_invalidate_record(ctx);
        G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
        return 0;
    }
    if (records <= ctx->record_limit) {
        ctx->record_reserved = 1;
        return 1;
    }
    ctx->usage_exhausted = 1;
    g301_poison(ctx);
    g301_invalidate_record(ctx);
    G301_RAISE(ctx, G301_R_KEY_USAGE_LIMIT_EXCEEDED);
    return 0;
}

static int g301_has_duplicate(const OSSL_PARAM params[], const char *name)
{
    const OSSL_PARAM *param;
    size_t count = 0;

    if (params == NULL)
        return 0;
    for (param = params; param->key != NULL; param++) {
        if (strcmp(param->key, name) == 0 && ++count > 1)
            return 1;
    }
    return 0;
}

static int g301_has_forbidden_legacy_param(const OSSL_PARAM params[])
{
    static const char *const forbidden[] = {
        OSSL_CIPHER_PARAM_AEAD_MAC_KEY,
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD,
        OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
        OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
        G301_CIPHER_PARAM_PIPELINE_AEAD_TAG,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE,
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT,
        OSSL_CIPHER_PARAM_TLS_VERSION,
        OSSL_CIPHER_PARAM_TLS_MAC,
        OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
        G301_CIPHER_PARAM_ENCRYPT_THEN_MAC
    };
    const OSSL_PARAM *param;
    size_t i;

    if (params == NULL)
        return 0;
    for (param = params; param->key != NULL; param++) {
        for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
            if (strcmp(param->key, forbidden[i]) == 0)
                return 1;
        }
    }
    return 0;
}

static int g301_init_params_have_duplicates(const OSSL_PARAM params[])
{
    return g301_has_duplicate(params, OSSL_CIPHER_PARAM_KEYLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_IVLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
}

static int g301_get_ctx_params_have_duplicates(const OSSL_PARAM params[])
{
    return g301_has_duplicate(params, OSSL_CIPHER_PARAM_KEYLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_IVLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
}

static int g301_validate_init_params(const OSSL_PARAM params[], int encrypt,
    int new_record, int *has_tag)
{
    const OSSL_PARAM *param;
    const OSSL_PARAM *tag_param;
    size_t value;

    *has_tag = 0;
    if (params == NULL)
        return 1;
    tag_param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    *has_tag = tag_param != NULL;
    if (g301_has_forbidden_legacy_param(params)
        || g301_init_params_have_duplicates(params))
        return 0;

    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (param != NULL
        && (!OSSL_PARAM_get_size_t(param, &value)
            || value != G301_KEY_LENGTH))
        return 0;

    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (param != NULL
        && (!OSSL_PARAM_get_size_t(param, &value) || value != G301_IV_LENGTH))
        return 0;

    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (param != NULL
        && (!OSSL_PARAM_get_size_t(param, &value)
            || value != G301_TAG_LENGTH))
        return 0;

    if (tag_param != NULL) {
        if (encrypt || !new_record
            || tag_param->data_type != OSSL_PARAM_OCTET_STRING
            || tag_param->data == NULL
            || tag_param->data_size != G301_TAG_LENGTH)
            return 0;
    }
    return 1;
}

static int g301_init(void *vctx, const unsigned char *key, size_t keylen,
    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[],
    int encrypt)
{
    G301_CIPHER_CTX *ctx = vctx;
    const int has_key = key != NULL;
    const int has_iv = iv != NULL;
    const OSSL_PARAM *iv_param;
    const OSSL_PARAM *tag_param;
    OSSL_PARAM filtered_params[3];
    size_t filtered_count = 0;
    size_t fixed_ivlen = G301_IV_LENGTH;
    int has_tag = 0;
    int direction_change;

    if (ctx == NULL)
        return 0;
    direction_change = ctx->direction_set && ctx->encrypt != encrypt;

    tag_param = params == NULL ? NULL
                               : OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (tag_param != NULL)
        ctx->decrypt_tag_current = 0;

    if ((has_key && keylen != G301_KEY_LENGTH)
        || (!has_key && keylen != 0)
        || (has_iv && ivlen != G301_IV_LENGTH)
        || (!has_iv && ivlen != 0)) {
        if (tag_param != NULL && (has_key || direction_change))
            g301_invalidate_record(ctx);
        if (direction_change)
            ctx->decrypt_tag_current = 0;
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }

    if (!g301_validate_init_params(params, encrypt,
            has_iv && (has_key || ctx->key_valid), &has_tag)) {
        if (has_tag && (has_key || direction_change))
            g301_invalidate_record(ctx);
        if (direction_change || has_tag)
            ctx->decrypt_tag_current = 0;
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }

    if (has_tag && (!has_iv || (!has_key && !ctx->key_valid))) {
        ctx->decrypt_tag_current = 0;
        if (has_key || direction_change)
            g301_invalidate_record(ctx);
        G301_RAISE(ctx, G301_R_INVALID_STATE);
        return 0;
    }
    if (has_iv && !has_key && !ctx->key_valid) {
        G301_RAISE(ctx, G301_R_INVALID_STATE);
        return 0;
    }

    if (direction_change || has_key)
        g301_invalidate_record(ctx);
    if (has_key)
        ctx->key_valid = 0;

    iv_param = params == NULL ? NULL
                              : OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (iv_param != NULL) {
        filtered_params[filtered_count++] = OSSL_PARAM_construct_size_t(
            OSSL_CIPHER_PARAM_IVLEN, &fixed_ivlen);
    }
    if (tag_param != NULL) {
        filtered_params[filtered_count++] = OSSL_PARAM_construct_octet_string(
            OSSL_CIPHER_PARAM_AEAD_TAG, tag_param->data,
            G301_TAG_LENGTH);
    }
    filtered_params[filtered_count] = OSSL_PARAM_construct_end();

    if (!ctx->ops->init(ctx->inner, key, iv, encrypt, filtered_params)) {
        if (has_key)
            ctx->key_valid = 0;
        g301_poison(ctx);
        g301_invalidate_record(ctx);
        return 0;
    }

    if (has_key && !g301_record_current_key(ctx, key)) {
        g301_poison(ctx);
        g301_invalidate_record(ctx);
        G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
        return 0;
    }

    ctx->encrypt = encrypt;
    ctx->direction_set = 1;
    if (has_key)
        ctx->key_valid = 1;

    if (has_iv) {
        if (!ctx->key_valid) {
            g301_poison(ctx);
            g301_invalidate_record(ctx);
            G301_RAISE(ctx, G301_R_INVALID_STATE);
            return 0;
        }
        if (encrypt && !g301_install_write_key(ctx)) {
            g301_poison(ctx);
            g301_invalidate_record(ctx);
            G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
            return 0;
        }
        ctx->phase = G301_PHASE_MANIFEST_PENDING;
        ctx->payload_started = 0;
        ctx->decrypt_tag_current = (!encrypt && has_tag);
        ctx->needs_reinit = 0;
    } else {
        g301_invalidate_record(ctx);
    }

    return 1;
}

static void *g301_cipher_newctx(void *vprovctx)
{
    G301_PROVIDER_CTX *provctx = vprovctx;
    G301_CIPHER_CTX *ctx;

    if (provctx == NULL || provctx->inner_ops == NULL)
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->ops = provctx->inner_ops;
    ctx->handle = provctx->handle;
    ctx->core_new_error = provctx->core_new_error;
    ctx->core_set_error_debug = provctx->core_set_error_debug;
    ctx->core_vset_error = provctx->core_vset_error;
    ctx->record_limit = (int)G301_ENCRYPT_RECORD_LIMIT;
    ctx->usage_lock = CRYPTO_THREAD_lock_new();
    ctx->inner = ctx->ops->newctx(provctx->inner_arg);
    if (ctx->usage_lock == NULL || ctx->inner == NULL) {
        ctx->ops->freectx(ctx->inner);
        CRYPTO_THREAD_lock_free(ctx->usage_lock);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return NULL;
    }
    return ctx;
}

static void g301_cipher_freectx(void *vctx)
{
    G301_CIPHER_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    ctx->ops->freectx(ctx->inner);
    CRYPTO_THREAD_lock_free(ctx->usage_lock);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int g301_cipher_encrypt_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    return g301_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int g301_cipher_decrypt_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    return g301_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int g301_inject_manifest(G301_CIPHER_CTX *ctx)
{
    int inner_outl = 0;

    if (ctx->phase != G301_PHASE_MANIFEST_PENDING)
        return ctx->phase == G301_PHASE_ACTIVE;
    if (ctx->encrypt && !g301_reserve_encryption_record(ctx))
        return 0;
    if (!ctx->ops->update(ctx->inner, NULL, &inner_outl, g301_manifest,
            (int)G301_MANIFEST_LENGTH)) {
        g301_poison(ctx);
        return 0;
    }
    if (inner_outl != (int)G301_MANIFEST_LENGTH) {
        g301_poison(ctx);
        G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
        return 0;
    }
    ctx->phase = G301_PHASE_ACTIVE;
    return 1;
}

static int g301_cipher_update(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    G301_CIPHER_CTX *ctx = vctx;
    int inner_outl = 0;
    int inlen;

    if (outl == NULL)
        return 0;
    *outl = 0;
    if (ctx == NULL)
        return 0;
    if (ctx->needs_reinit
        || ctx->phase == G301_PHASE_NO_RECORD
        || ctx->phase == G301_PHASE_FINALIZED) {
        G301_RAISE(ctx, G301_R_INVALID_STATE);
        return 0;
    }
    if ((in == NULL && inl != 0) || inl > (size_t)INT_MAX) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    if (inl == 0)
        return 1;
    if (out != NULL && outsize < inl) {
        G301_RAISE(ctx, G301_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (out == NULL && ctx->payload_started) {
        G301_RAISE(ctx, G301_R_INVALID_STATE);
        return 0;
    }

    inlen = (int)inl;
    if (!g301_inject_manifest(ctx))
        return 0;
    if (!ctx->ops->update(ctx->inner, out, &inner_outl, in, inlen)) {
        g301_poison(ctx);
        return 0;
    }
    if (inner_outl < 0 || inner_outl != inlen
        || (out != NULL && (size_t)inner_outl > outsize)) {
        g301_poison(ctx);
        G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
        return 0;
    }

    if (out != NULL)
        ctx->payload_started = 1;
    *outl = inl;
    return 1;
}

static int g301_cipher_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize)
{
    G301_CIPHER_CTX *ctx = vctx;
    unsigned char private_out[EVP_MAX_BLOCK_LENGTH];
    int inner_outl = 0;
    int ok;

    (void)out;
    (void)outsize;
    if (ctx == NULL)
        return 0;
    if (outl == NULL) {
        if (!ctx->needs_reinit
            && (ctx->phase == G301_PHASE_MANIFEST_PENDING
                || ctx->phase == G301_PHASE_ACTIVE))
            g301_poison(ctx);
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    *outl = 0;
    if (ctx->needs_reinit
        || ctx->phase == G301_PHASE_NO_RECORD
        || ctx->phase == G301_PHASE_FINALIZED) {
        G301_RAISE(ctx, G301_R_INVALID_STATE);
        return 0;
    }
    if (!ctx->encrypt && !ctx->decrypt_tag_current) {
        g301_poison(ctx);
        G301_RAISE(ctx, G301_R_INVALID_STATE);
        return 0;
    }
    if (!g301_inject_manifest(ctx))
        return 0;

    ctx->decrypt_tag_current = 0;
    memset(private_out, 0, sizeof(private_out));
    ok = ctx->ops->final(ctx->inner, private_out, &inner_outl);
    OPENSSL_cleanse(private_out, sizeof(private_out));
    if (!ok) {
        g301_poison(ctx);
        return 0;
    }
    if (inner_outl != 0) {
        g301_poison(ctx);
        G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
        return 0;
    }
    ctx->phase = G301_PHASE_FINALIZED;
    return 1;
}

static int g301_cipher_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *param;
    unsigned int mode = EVP_CIPH_GCM_MODE;
    int one = 1;

    if (params == NULL)
        return 1;
    if (g301_has_duplicate(params, OSSL_CIPHER_PARAM_MODE)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_KEYLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_IVLEN)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_AEAD)
        || g301_has_duplicate(params, OSSL_CIPHER_PARAM_CUSTOM_IV))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (param != NULL && !OSSL_PARAM_set_uint(param, mode))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, G301_KEY_LENGTH))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, G301_IV_LENGTH))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, 1))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (param != NULL && !OSSL_PARAM_set_int(param, one))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (param != NULL && !OSSL_PARAM_set_int(param, one))
        return 0;
    return 1;
}

static int g301_get_encryption_tag(G301_CIPHER_CTX *ctx, OSSL_PARAM *param)
{
    unsigned char private_tag[G301_TAG_LENGTH];
    OSSL_PARAM inner_params[2];
    int ok;

    if (param->data_type != OSSL_PARAM_OCTET_STRING) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    if (param->data == NULL) {
        param->return_size = G301_TAG_LENGTH;
        return 1;
    }
    if (param->data_size != G301_TAG_LENGTH) {
        param->return_size = G301_TAG_LENGTH;
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }

    memset(private_tag, 0, sizeof(private_tag));
    inner_params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, private_tag, sizeof(private_tag));
    inner_params[1] = OSSL_PARAM_construct_end();
    ok = ctx->ops->get_params(ctx->inner, inner_params);
    if (!ok) {
        g301_poison(ctx);
        OPENSSL_cleanse(private_tag, sizeof(private_tag));
        return 0;
    }
    if (inner_params[0].return_size != G301_TAG_LENGTH) {
        g301_poison(ctx);
        OPENSSL_cleanse(private_tag, sizeof(private_tag));
        G301_RAISE(ctx, G301_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(param->data, private_tag, G301_TAG_LENGTH);
    param->return_size = G301_TAG_LENGTH;
    OPENSSL_cleanse(private_tag, sizeof(private_tag));
    return 1;
}

static int g301_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    G301_CIPHER_CTX *ctx = vctx;
    OSSL_PARAM *param;

    if (params == NULL)
        return 1;
    if (ctx == NULL)
        return 0;
    if (g301_has_forbidden_legacy_param(params)
        || g301_get_ctx_params_have_duplicates(params)) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, G301_IV_LENGTH)) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, G301_KEY_LENGTH)) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, G301_TAG_LENGTH)) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (param != NULL) {
        if (!ctx->encrypt || ctx->phase != G301_PHASE_FINALIZED
            || ctx->needs_reinit) {
            G301_RAISE(ctx, G301_R_INVALID_STATE);
            return 0;
        }
        if (!g301_get_encryption_tag(ctx, param))
            return 0;
    }
    return 1;
}

static int g301_validate_set_params(G301_CIPHER_CTX *ctx,
    const OSSL_PARAM params[], const OSSL_PARAM **tag_param)
{
    const OSSL_PARAM *param;
    size_t value;

    *tag_param = NULL;
    if (params == NULL)
        return 1;
    if (g301_init_params_have_duplicates(params))
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (param != NULL
        && (!OSSL_PARAM_get_size_t(param, &value)
            || value != G301_KEY_LENGTH))
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (param != NULL
        && (!OSSL_PARAM_get_size_t(param, &value) || value != G301_IV_LENGTH))
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (param != NULL
        && (!OSSL_PARAM_get_size_t(param, &value)
            || value != G301_TAG_LENGTH))
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (param != NULL) {
        *tag_param = param;
        if (ctx->encrypt || ctx->needs_reinit
            || (ctx->phase != G301_PHASE_MANIFEST_PENDING
                && ctx->phase != G301_PHASE_ACTIVE)
            || param->data_type != OSSL_PARAM_OCTET_STRING
            || param->data == NULL || param->data_size != G301_TAG_LENGTH)
            return 0;
    }
    return 1;
}

static int g301_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    G301_CIPHER_CTX *ctx = vctx;
    const OSSL_PARAM *iv_param;
    const OSSL_PARAM *tag_param;
    OSSL_PARAM filtered_params[3];
    size_t filtered_count = 0;
    size_t fixed_ivlen = G301_IV_LENGTH;

    if (params == NULL)
        return 1;
    if (ctx == NULL)
        return 0;
    tag_param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (tag_param != NULL)
        ctx->decrypt_tag_current = 0;
    if (g301_has_forbidden_legacy_param(params)) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    if (!g301_validate_set_params(ctx, params, &tag_param)) {
        G301_RAISE(ctx, G301_R_INVALID_PARAMETER);
        return 0;
    }
    iv_param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (tag_param == NULL)
        return 1;

    if (iv_param != NULL) {
        filtered_params[filtered_count++] = OSSL_PARAM_construct_size_t(
            OSSL_CIPHER_PARAM_IVLEN, &fixed_ivlen);
    }
    if (tag_param != NULL) {
        filtered_params[filtered_count++] = OSSL_PARAM_construct_octet_string(
            OSSL_CIPHER_PARAM_AEAD_TAG, tag_param->data,
            G301_TAG_LENGTH);
    }
    filtered_params[filtered_count] = OSSL_PARAM_construct_end();

    if (!ctx->ops->set_params(ctx->inner, filtered_params)) {
        g301_poison(ctx);
        return 0;
    }
    if (tag_param != NULL)
        ctx->decrypt_tag_current = 1;
    return 1;
}

static const OSSL_PARAM g301_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *g301_cipher_gettable_params(void *provctx)
{
    (void)provctx;
    return g301_gettable_params;
}

static const OSSL_PARAM g301_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *g301_cipher_gettable_ctx_params(void *cctx,
    void *provctx)
{
    (void)cctx;
    (void)provctx;
    return g301_gettable_ctx_params;
}

static const OSSL_PARAM g301_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *g301_cipher_settable_ctx_params(void *cctx,
    void *provctx)
{
    (void)cctx;
    (void)provctx;
    return g301_settable_ctx_params;
}

const OSSL_DISPATCH g301_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))g301_cipher_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))g301_cipher_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))g301_cipher_get_params },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,
        (void (*)(void))g301_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,
        (void (*)(void))g301_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))g301_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))g301_cipher_final },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))g301_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        (void (*)(void))g301_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))g301_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))g301_cipher_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))g301_cipher_settable_ctx_params },
    { 0, NULL }
};

#ifdef G301_TESTING
void *g301_test_cipher_newctx(G301_PROVIDER_CTX *provctx)
{
    return g301_cipher_newctx(provctx);
}

void g301_test_cipher_freectx(void *vctx)
{
    g301_cipher_freectx(vctx);
}

int g301_test_cipher_encrypt_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    return g301_cipher_encrypt_init(vctx, key, keylen, iv, ivlen, params);
}

int g301_test_cipher_decrypt_init(void *vctx, const unsigned char *key,
    size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    return g301_cipher_decrypt_init(vctx, key, keylen, iv, ivlen, params);
}

int g301_test_cipher_update(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    return g301_cipher_update(vctx, out, outl, outsize, in, inl);
}

int g301_test_cipher_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsize)
{
    return g301_cipher_final(vctx, out, outl, outsize);
}

int g301_test_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    return g301_cipher_get_ctx_params(vctx, params);
}

int g301_test_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return g301_cipher_set_ctx_params(vctx, params);
}

int g301_test_cipher_set_record_limit(void *vctx, uint64_t limit)
{
    G301_CIPHER_CTX *ctx = vctx;

    if (ctx == NULL || limit == 0 || limit > (uint64_t)INT_MAX)
        return 0;
    ctx->record_limit = (int)limit;
    return 1;
}
#endif
