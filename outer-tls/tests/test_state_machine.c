/* SPDX-License-Identifier: Apache-2.0 */

#include "g301_internal.h"

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            failures++;                                                     \
            goto end;                                                       \
        }                                                                   \
    } while (0)

typedef struct fixture_st {
    int init_calls;
    int update_calls;
    int manifest_calls;
    int aad_calls;
    int payload_calls;
    int final_calls;
    int get_calls;
    int set_calls;
    int last_final_out_nonnull;
    int last_init_unknown;
    int last_set_unknown;
    int fail_init;
    int fail_manifest;
    int fail_aad;
    int fail_payload;
    int fail_final;
    int fail_get;
    int fail_set;
    int force_manifest_outl;
    int forced_manifest_outl;
    int force_aad_outl;
    int forced_aad_outl;
    int force_payload_outl;
    int forced_payload_outl;
    int forced_final_outl;
    size_t get_return_size;
    uint32_t last_reason;
    unsigned char tag[16];
} FIXTURE;

static FIXTURE *error_fixture;

static const unsigned char key_a[32] = { 1 };
static const unsigned char key_b[32] = { 2 };
static const unsigned char iv_a[12] = { 3 };
static const unsigned char iv_b[12] = { 4 };
static const unsigned char aad[5] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
static const unsigned char payload[4] = { 7, 8, 9, 10 };
static const unsigned char manifest[32] = {
    0x47, 0x33, 0x30, 0x31, 0x2d, 0x54, 0x4c, 0x53,
    0x31, 0x33, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x01,
    0x04, 0x01, 0x01, 0x2d, 0x01, 0x00, 0x63, 0x01,
    0x01, 0x74, 0x01, 0x00, 0xaf, 0x02, 0x03, 0xb3
};

static void fixture_reset(FIXTURE *fixture)
{
    size_t i;

    memset(fixture, 0, sizeof(*fixture));
    fixture->get_return_size = 16;
    for (i = 0; i < sizeof(fixture->tag); i++)
        fixture->tag[i] = (unsigned char)(0xa0U + (unsigned int)i);
}

static void fixture_new_error(const OSSL_CORE_HANDLE *handle)
{
    (void)handle;
    if (error_fixture != NULL)
        error_fixture->last_reason = 0;
}

static void fixture_set_error_debug(const OSSL_CORE_HANDLE *handle,
    const char *file, int line, const char *function)
{
    (void)handle;
    (void)file;
    (void)line;
    (void)function;
}

static void fixture_vset_error(const OSSL_CORE_HANDLE *handle,
    uint32_t reason, const char *format, va_list arguments)
{
    (void)handle;
    (void)format;
    (void)arguments;
    if (error_fixture != NULL)
        error_fixture->last_reason = reason;
}

static void *fixture_newctx(void *arg)
{
    return arg;
}

static void fixture_freectx(void *inner)
{
    (void)inner;
}

static int params_contain_only(const OSSL_PARAM params[], const char *first,
    const char *second)
{
    const OSSL_PARAM *param;

    if (params == NULL)
        return 1;
    for (param = params; param->key != NULL; param++) {
        if ((first == NULL || strcmp(param->key, first) != 0)
            && (second == NULL || strcmp(param->key, second) != 0))
            return 0;
    }
    return 1;
}

static int fixture_init(void *inner, const unsigned char *key,
    const unsigned char *iv, int encrypt, const OSSL_PARAM params[])
{
    FIXTURE *fixture = inner;

    (void)key;
    (void)iv;
    (void)encrypt;
    fixture->init_calls++;
    fixture->last_init_unknown = !params_contain_only(params,
        OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (fixture->fail_init) {
        fixture->fail_init = 0;
        return 0;
    }
    return 1;
}

static int fixture_update(void *inner, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{
    FIXTURE *fixture = inner;

    fixture->update_calls++;
    if (out == NULL && inl == (int)sizeof(manifest)
        && memcmp(in, manifest, sizeof(manifest)) == 0) {
        fixture->manifest_calls++;
        if (fixture->fail_manifest) {
            fixture->fail_manifest = 0;
            return 0;
        }
        *outl = fixture->force_manifest_outl
            ? fixture->forced_manifest_outl
            : inl;
    } else if (out == NULL) {
        fixture->aad_calls++;
        if (fixture->fail_aad) {
            fixture->fail_aad = 0;
            return 0;
        }
        *outl = fixture->force_aad_outl
            ? fixture->forced_aad_outl
            : inl;
    } else {
        fixture->payload_calls++;
        if (fixture->fail_payload) {
            fixture->fail_payload = 0;
            return 0;
        }
        if (inl > 0)
            memmove(out, in, (size_t)inl);
        *outl = fixture->force_payload_outl
            ? fixture->forced_payload_outl
            : inl;
    }
    return 1;
}

static int fixture_final(void *inner, unsigned char *out, int *outl)
{
    FIXTURE *fixture = inner;

    fixture->final_calls++;
    fixture->last_final_out_nonnull = out != NULL;
    if (fixture->fail_final) {
        fixture->fail_final = 0;
        return 0;
    }
    *outl = fixture->forced_final_outl;
    return 1;
}

static int fixture_get(void *inner, OSSL_PARAM params[])
{
    FIXTURE *fixture = inner;
    OSSL_PARAM *param;

    fixture->get_calls++;
    if (fixture->fail_get) {
        fixture->fail_get = 0;
        return 0;
    }
    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (param == NULL || param->data == NULL || param->data_size != 16)
        return 0;
    memcpy(param->data, fixture->tag, sizeof(fixture->tag));
    param->return_size = fixture->get_return_size;
    return 1;
}

static int fixture_set(void *inner, const OSSL_PARAM params[])
{
    FIXTURE *fixture = inner;

    fixture->set_calls++;
    fixture->last_set_unknown = !params_contain_only(params,
        OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (fixture->fail_set) {
        fixture->fail_set = 0;
        return 0;
    }
    return 1;
}

static const G301_INNER_OPS fixture_ops = {
    fixture_newctx,
    fixture_freectx,
    fixture_init,
    fixture_update,
    fixture_final,
    fixture_get,
    fixture_set
};

static void *new_outer(FIXTURE *fixture)
{
    G301_PROVIDER_CTX provider_ctx = {
        .child_libctx = NULL,
        .inner_ops = &fixture_ops,
        .inner_arg = fixture,
        .handle = NULL,
        .core_new_error = fixture_new_error,
        .core_set_error_debug = fixture_set_error_debug,
        .core_vset_error = fixture_vset_error
    };

    error_fixture = fixture;
    return g301_test_cipher_newctx(&provider_ctx);
}

static int begin_encrypt(void *ctx)
{
    return g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL);
}

static int finalize_encrypt(void *ctx)
{
    size_t outl = SIZE_MAX;

    return g301_test_cipher_final(ctx, NULL, &outl, 0) && outl == 0;
}

static int set_current_tag(void *ctx, const unsigned char value[16])
{
    unsigned char copy[16];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, copy,
            sizeof(copy)),
        OSSL_PARAM_END
    };

    memcpy(copy, value, sizeof(copy));
    return g301_test_cipher_set_ctx_params(ctx, params);
}

static int get_current_tag(void *ctx, unsigned char output[16])
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, output, 16),
        OSSL_PARAM_END
    };

    return g301_test_cipher_get_ctx_params(ctx, params);
}

static int complete_encrypt_record(void *ctx, const unsigned char *key_value,
    const unsigned char iv_value[12])
{
    unsigned char output[sizeof(payload)];
    unsigned char tag[16];
    size_t outl = 0;
    size_t key_length = key_value == NULL ? 0 : sizeof(key_a);

    return g301_test_cipher_encrypt_init(ctx, key_value, key_length,
               iv_value, sizeof(iv_a), NULL)
        && g301_test_cipher_update(ctx, output, &outl, sizeof(output),
            payload, sizeof(payload))
        && outl == sizeof(payload) && finalize_encrypt(ctx)
        && get_current_tag(ctx, tag);
}

static int complete_decrypt_record(void *ctx, const unsigned char *key_value,
    const unsigned char iv_value[12])
{
    unsigned char output[sizeof(payload)];
    unsigned char tag[16] = { 0 };
    size_t outl = 0;
    size_t key_length = key_value == NULL ? 0 : sizeof(key_a);

    return g301_test_cipher_decrypt_init(ctx, key_value, key_length,
               iv_value, sizeof(iv_a), NULL)
        && set_current_tag(ctx, tag)
        && g301_test_cipher_update(ctx, output, &outl, sizeof(output),
            payload, sizeof(payload))
        && outl == sizeof(payload)
        && g301_test_cipher_final(ctx, NULL, &outl, 0);
}

static int test_write_key_usage_limit(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char output[sizeof(payload)];
    size_t outl = SIZE_MAX;
    int before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && g301_test_cipher_set_record_limit(ctx, UINT64_C(3)));
    CHECK(complete_encrypt_record(ctx, key_a, iv_a));
    CHECK(complete_encrypt_record(ctx, NULL, iv_b));
    CHECK(complete_encrypt_record(ctx, key_a, iv_a));

    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    before = fixture.update_calls;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output),
        payload, sizeof(payload)));
    CHECK(outl == 0 && fixture.update_calls == before
        && fixture.last_reason == G301_R_KEY_USAGE_LIMIT_EXCEEDED);
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output),
        payload, sizeof(payload)));
    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output),
        payload, sizeof(payload)));

    CHECK(complete_encrypt_record(ctx, key_b, iv_b));
    CHECK(complete_encrypt_record(ctx, NULL, iv_a));
    fixture.fail_init = 1;
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_b,
        sizeof(iv_b), NULL));
    CHECK(complete_encrypt_record(ctx, key_b, iv_b));
    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), NULL, 0,
        NULL));
    CHECK(g301_test_cipher_encrypt_init(ctx, key_b, sizeof(key_b), iv_a,
        sizeof(iv_a), NULL));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output),
        payload, sizeof(payload)));
    g301_test_cipher_freectx(ctx);
    ctx = NULL;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && g301_test_cipher_set_record_limit(ctx, UINT64_C(3)));
    CHECK(complete_decrypt_record(ctx, key_a, iv_a));
    CHECK(complete_decrypt_record(ctx, NULL, iv_b));
    CHECK(complete_decrypt_record(ctx, NULL, iv_a));
    CHECK(complete_decrypt_record(ctx, NULL, iv_b));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_exactly_once_and_boundaries(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char output[sizeof(payload)];
    size_t outl = SIZE_MAX;
    int before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && begin_encrypt(ctx));
    CHECK(fixture.manifest_calls == 0);
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, NULL, 0));
    CHECK(outl == 0 && fixture.manifest_calls == 0);
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(outl == sizeof(aad));
    CHECK(fixture.manifest_calls == 1 && fixture.aad_calls == 1);
    CHECK(g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(outl == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0);
    CHECK(fixture.manifest_calls == 1 && fixture.payload_calls == 1);

    before = fixture.update_calls;
    outl = SIZE_MAX;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        (size_t)INT_MAX + 1U));
    CHECK(outl == 0 && fixture.update_calls == before);
    outl = SIZE_MAX;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output) - 1,
        payload, sizeof(payload)));
    CHECK(outl == 0 && fixture.update_calls == before);
    CHECK(!g301_test_cipher_update(ctx, output, NULL, sizeof(output), payload,
        sizeof(payload)));
    CHECK(fixture.update_calls == before);

    CHECK(finalize_encrypt(ctx));
    CHECK(fixture.final_calls == 1 && fixture.last_final_out_nonnull);
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_manifest_failure_and_recovery(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    size_t outl = SIZE_MAX;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && begin_encrypt(ctx));
    fixture.fail_manifest = 1;
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(outl == 0 && fixture.manifest_calls == 1 && fixture.aad_calls == 0);
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, NULL, 0));

    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), NULL, 0,
        NULL));
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, NULL, 0));
    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(fixture.manifest_calls == 2 && fixture.aad_calls == 1);
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_key_valid_failure(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    size_t outl = 0;
    int before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && begin_encrypt(ctx));
    before = fixture.init_calls;
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_b, sizeof(key_b) - 1,
        NULL, 0, NULL));
    CHECK(fixture.init_calls == before);
    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));

    fixture.fail_init = 1;
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_b, sizeof(key_b), NULL, 0,
        NULL));
    CHECK(!g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), NULL, 0,
        NULL));
    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_tag_freshness(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char output[sizeof(payload)];
    unsigned char tag[16] = { 0 };
    size_t outl = SIZE_MAX;
    int before_update;
    int before_final;
    int ok = 0;

    fixture_reset(&fixture);
    memset(tag, 0x5a, sizeof(tag));
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    before_final = fixture.final_calls;
    CHECK(!g301_test_cipher_final(ctx, NULL, NULL, 0));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.final_calls == before_final);
    CHECK(!set_current_tag(ctx, tag));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    before_update = fixture.update_calls;
    before_final = fixture.final_calls;
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == before_update
        && fixture.final_calls == before_final);
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == before_update
        && fixture.final_calls == before_final);

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));

    {
        unsigned char tag2[16] = { 1 };
        OSSL_PARAM duplicate[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, 16),
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag2, 16),
            OSSL_PARAM_END
        };
        CHECK(!g301_test_cipher_set_ctx_params(ctx, duplicate));
    }
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_fixed_tag_private_copy(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char output[16];
    size_t i;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && begin_encrypt(ctx) && finalize_encrypt(ctx));

    memset(output, 0x5a, sizeof(output));
    fixture.fail_get = 1;
    CHECK(!get_current_tag(ctx, output));
    CHECK(fixture.get_calls == 1);
    for (i = 0; i < sizeof(output); i++)
        CHECK(output[i] == 0x5a);
    CHECK(!get_current_tag(ctx, output));
    CHECK(fixture.get_calls == 1);

    CHECK(begin_encrypt(ctx) && finalize_encrypt(ctx));
    fixture.get_return_size = 15;
    CHECK(!get_current_tag(ctx, output));
    CHECK(fixture.last_reason == G301_R_INTERNAL_ERROR);
    CHECK(fixture.get_calls == 2);
    for (i = 0; i < sizeof(output); i++)
        CHECK(output[i] == 0x5a);
    CHECK(!get_current_tag(ctx, output));
    CHECK(fixture.get_calls == 2);

    CHECK(begin_encrypt(ctx) && finalize_encrypt(ctx));
    fixture.get_return_size = 16;
    CHECK(get_current_tag(ctx, output));
    CHECK(fixture.get_calls == 3);
    CHECK(memcmp(output, fixture.tag, sizeof(output)) == 0);
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_parameter_filtering_and_poison(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    size_t ivlen = 12;
    unsigned int unknown_value = 947;
    OSSL_PARAM init_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_uint("g301-unknown", &unknown_value),
        OSSL_PARAM_END
    };
    OSSL_PARAM set_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_uint("g301-unknown", &unknown_value),
        OSSL_PARAM_END
    };
    size_t outl = 0;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), init_params));
    CHECK(!fixture.last_init_unknown);
    CHECK(g301_test_cipher_set_ctx_params(ctx, set_params));
    CHECK(fixture.set_calls == 0 && !fixture.last_set_unknown);

    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    fixture.fail_set = 1;
    CHECK(!set_current_tag(ctx, fixture.tag));
    CHECK(fixture.set_calls == 1);
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_malformed_inner_lengths(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char output[sizeof(payload)];
    size_t outl = SIZE_MAX;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && begin_encrypt(ctx));
    fixture.force_manifest_outl = 1;
    fixture.forced_manifest_outl = 31;
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(fixture.last_reason == G301_R_INTERNAL_ERROR);
    CHECK(outl == 0 && fixture.manifest_calls == 1 && fixture.aad_calls == 0);

    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    fixture.force_manifest_outl = 0;
    fixture.force_aad_outl = 1;
    fixture.forced_aad_outl = 4;
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(fixture.last_reason == G301_R_INTERNAL_ERROR);
    CHECK(outl == 0 && fixture.aad_calls == 1);

    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    fixture.force_aad_outl = 0;
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    fixture.force_payload_outl = 1;
    fixture.forced_payload_outl = 3;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(fixture.last_reason == G301_R_INTERNAL_ERROR);
    CHECK(outl == 0);

    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    fixture.force_payload_outl = 0;
    fixture.forced_final_outl = 1;
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.last_reason == G301_R_INTERNAL_ERROR);
    CHECK(outl == 0);
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_inner_update_failures_and_recovery(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char output[sizeof(payload)];
    size_t outl = SIZE_MAX;
    int before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL && begin_encrypt(ctx));
    CHECK(g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    fixture.fail_aad = 1;
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(outl == 0 && fixture.aad_calls == 2);
    before = fixture.update_calls;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(outl == 0 && fixture.update_calls == before);

    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    fixture.fail_payload = 1;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(outl == 0 && fixture.payload_calls == 1);
    before = fixture.update_calls;
    CHECK(!g301_test_cipher_update(ctx, NULL, &outl, 0, aad, sizeof(aad)));
    CHECK(fixture.update_calls == before);

    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    fixture.fail_final = 1;
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(outl == 0 && fixture.final_calls == 1);
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.final_calls == 1);
    CHECK(g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_atomic_iv_tag_and_wrong_types(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char tag[16] = { 0x5a };
    unsigned int wrong_ivlen = 12;
    size_t canonical_ivlen = 12;
    OSSL_PARAM atomic_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &canonical_ivlen),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_type[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IVLEN, &wrong_ivlen,
            sizeof(wrong_ivlen)),
        OSSL_PARAM_END
    };
    OSSL_PARAM duplicate_ivlen[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &canonical_ivlen),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &canonical_ivlen),
        OSSL_PARAM_END
    };
    size_t outl = SIZE_MAX;
    int before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), atomic_params));
    CHECK(!fixture.last_init_unknown);
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    before = fixture.init_calls;
    CHECK(!g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        wrong_type));
    CHECK(fixture.init_calls == before);
    CHECK(!g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        duplicate_ivlen));
    CHECK(fixture.init_calls == before);
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_full_parameter_validation(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    size_t keylen = 32;
    size_t bad_keylen = 31;
    size_t ivlen = 12;
    size_t bad_ivlen = 11;
    unsigned int compatible_keylen = 32;
    unsigned int compatible_ivlen = 12;
    int negative = -1;
    unsigned char octets[sizeof(size_t)] = { 0 };
    unsigned char tag[16] = { 0x5a };
    unsigned int unknown_value = 947;
    OSSL_PARAM unknown[] = {
        OSSL_PARAM_uint("g301-unknown", &unknown_value),
        OSSL_PARAM_END
    };
    OSSL_PARAM good_keylen[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen),
        OSSL_PARAM_END
    };
    OSSL_PARAM good_compatible_keylen[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_KEYLEN, &compatible_keylen),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_key_value[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &bad_keylen),
        OSSL_PARAM_END
    };
    OSSL_PARAM negative_key[] = {
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, &negative),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_key_type[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_KEYLEN, octets,
            sizeof(octets)),
        OSSL_PARAM_END
    };
    OSSL_PARAM duplicate_key[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen),
        OSSL_PARAM_END
    };
    OSSL_PARAM good_ivlen[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_IVLEN, &compatible_ivlen),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_iv_value[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &bad_ivlen),
        OSSL_PARAM_END
    };
    OSSL_PARAM negative_iv[] = {
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_IVLEN, &negative),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_iv_type[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IVLEN, octets,
            sizeof(octets)),
        OSSL_PARAM_END
    };
    OSSL_PARAM duplicate_iv[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_tag_type[] = {
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD_TAG, &negative),
        OSSL_PARAM_END
    };
    OSSL_PARAM duplicate_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    int before;
    int init_before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_set_ctx_params(ctx, NULL));
    CHECK(g301_test_cipher_get_ctx_params(ctx, NULL));
    CHECK(g301_test_cipher_set_ctx_params(ctx, unknown));
    CHECK(fixture.set_calls == 0 && fixture.init_calls == 0);
    CHECK(g301_test_cipher_set_ctx_params(ctx, good_keylen));
    CHECK(g301_test_cipher_set_ctx_params(ctx, good_compatible_keylen));
    CHECK(g301_test_cipher_set_ctx_params(ctx, good_ivlen));
    CHECK(fixture.set_calls == 0 && fixture.init_calls == 0);

    CHECK(!g301_test_cipher_set_ctx_params(ctx, bad_key_value));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, negative_key));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, wrong_key_type));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, duplicate_key));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, bad_iv_value));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, negative_iv));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, wrong_iv_type));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, duplicate_iv));
    CHECK(fixture.set_calls == 0 && fixture.init_calls == 0);

    before = fixture.init_calls;
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), bad_key_value));
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), negative_key));
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), wrong_key_type));
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), duplicate_key));
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), bad_iv_value));
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), duplicate_iv));
    CHECK(fixture.init_calls == before);
    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), good_keylen));
    CHECK(g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), good_compatible_keylen));
    CHECK(fixture.init_calls == before + 2);

    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    before = fixture.set_calls;
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_set_ctx_params(ctx, wrong_tag_type));
    CHECK(!g301_test_cipher_set_ctx_params(ctx, duplicate_tag));
    CHECK(fixture.set_calls == before);
    CHECK(!g301_test_cipher_encrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), duplicate_tag));
    CHECK(fixture.init_calls == init_before);
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_rejected_key_or_direction_tag_invalidates_record(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char tag[16] = { 0x5a };
    unsigned char output[sizeof(payload)];
    OSSL_PARAM tag_params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    size_t outl = SIZE_MAX;
    int init_before;
    int update_before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    CHECK(set_current_tag(ctx, tag));

    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_decrypt_init(ctx, key_b, sizeof(key_b), NULL, 0,
        tag_params));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_encrypt_init(ctx, NULL, 0, NULL, 0, tag_params));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_denylist_tag_ordering(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char tag[16] = { 0x5a };
    unsigned char alternate_tag[16] = { 0xa5 };
    unsigned char tls_aad[13] = { 0 };
    unsigned char output[sizeof(payload)];
    OSSL_PARAM tag_and_forbidden[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, alternate_tag,
            sizeof(alternate_tag)),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, tls_aad,
            sizeof(tls_aad)),
        OSSL_PARAM_END
    };
    OSSL_PARAM duplicate_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, alternate_tag,
            sizeof(alternate_tag)),
        OSSL_PARAM_END
    };
    size_t outl = SIZE_MAX;
    int update_before;
    int final_before;
    int init_before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    CHECK(set_current_tag(ctx, tag));

    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!g301_test_cipher_set_ctx_params(ctx, tag_and_forbidden));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_decrypt_init(ctx, key_b, sizeof(key_b), NULL, 0,
        tag_and_forbidden));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_decrypt_init(ctx, key_b, sizeof(key_b), NULL, 0,
        duplicate_tag));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_decrypt_init(ctx, key_b, sizeof(key_b), iv_b,
        sizeof(iv_b), tag_and_forbidden));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_encrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        duplicate_tag));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

static int test_length_rejection_tag_ordering(void)
{
    FIXTURE fixture;
    void *ctx = NULL;
    unsigned char tag[16] = { 0x5a };
    unsigned char output[sizeof(payload)];
    unsigned char short_iv[11] = { 0 };
    OSSL_PARAM tag_params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    size_t outl = SIZE_MAX;
    int init_before;
    int update_before;
    int final_before;
    int ok = 0;

    fixture_reset(&fixture);
    ctx = new_outer(&fixture);
    CHECK(ctx != NULL);
    CHECK(g301_test_cipher_decrypt_init(ctx, key_a, sizeof(key_a), iv_a,
        sizeof(iv_a), NULL));
    CHECK(set_current_tag(ctx, tag));

    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_decrypt_init(ctx, key_b, sizeof(key_b) - 1,
        NULL, 0, tag_params));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!set_current_tag(ctx, tag));
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));

    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_a, sizeof(iv_a),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    init_before = fixture.init_calls;
    CHECK(!g301_test_cipher_encrypt_init(ctx, NULL, 0, short_iv,
        sizeof(short_iv), tag_params));
    CHECK(fixture.init_calls == init_before);
    update_before = fixture.update_calls;
    final_before = fixture.final_calls;
    CHECK(!g301_test_cipher_update(ctx, output, &outl, sizeof(output), payload,
        sizeof(payload)));
    CHECK(!g301_test_cipher_final(ctx, NULL, &outl, 0));
    CHECK(fixture.update_calls == update_before
        && fixture.final_calls == final_before);
    CHECK(g301_test_cipher_decrypt_init(ctx, NULL, 0, iv_b, sizeof(iv_b),
        NULL));
    CHECK(set_current_tag(ctx, tag));
    CHECK(g301_test_cipher_final(ctx, NULL, &outl, 0));
    ok = 1;
end:
    g301_test_cipher_freectx(ctx);
    return ok;
}

int main(void)
{
    if (!test_write_key_usage_limit())
        goto end;
    if (!test_exactly_once_and_boundaries())
        goto end;
    if (!test_manifest_failure_and_recovery())
        goto end;
    if (!test_key_valid_failure())
        goto end;
    if (!test_tag_freshness())
        goto end;
    if (!test_fixed_tag_private_copy())
        goto end;
    if (!test_parameter_filtering_and_poison())
        goto end;
    if (!test_malformed_inner_lengths())
        goto end;
    if (!test_inner_update_failures_and_recovery())
        goto end;
    if (!test_atomic_iv_tag_and_wrong_types())
        goto end;
    if (!test_full_parameter_validation())
        goto end;
    if (!test_rejected_key_or_direction_tag_invalidates_record())
        goto end;
    if (!test_denylist_tag_ordering())
        goto end;
    if (!test_length_rejection_tag_ordering())
        goto end;
end:
    if (failures != 0) {
        fprintf(stderr, "%d state-machine assertion(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("g301 state-machine fixture tests: ok");
    return EXIT_SUCCESS;
}
