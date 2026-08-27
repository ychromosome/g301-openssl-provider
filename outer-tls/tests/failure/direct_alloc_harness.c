/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define WORKING_NAME "G301-AES-256-GCM-V1"
#define PROPERTY_QUERY "provider=g301,fips=no"
#define SENTINEL 0xa5U

typedef size_t (*size_getter_fn)(void);
typedef uintptr_t (*offset_getter_fn)(size_t);
typedef size_t (*call_size_getter_fn)(size_t);
typedef unsigned int (*uint_getter_fn)(size_t);

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

static const unsigned char aad[] = { 0x17, 0x03, 0x03, 0x00, 0x20 };

static const unsigned char plaintext[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x17
};

static const unsigned char expected_ciphertext[] = {
    0x47, 0x03, 0xd4, 0x18, 0xc1, 0xe0, 0xc4, 0x1c,
    0x85, 0x48, 0x9d, 0x80, 0xbd, 0xe4, 0x76, 0x7a
};

static const unsigned char expected_tag[] = {
    0xd1, 0x3e, 0x69, 0x0f, 0x20, 0xbc, 0x38, 0x92,
    0x3e, 0xa2, 0xb8, 0x54, 0xe2, 0x58, 0xe3, 0x2d
};

static int changed(const unsigned char *buffer, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++) {
        if (buffer[i] != SENTINEL)
            return 1;
    }
    return 0;
}

static int load_function(void *destination, size_t destination_size,
    const char *name)
{
    void *symbol = dlsym(RTLD_DEFAULT, name);

    if (symbol == NULL || destination_size != sizeof(symbol))
        return 0;
    memcpy(destination, &symbol, sizeof(symbol));
    return 1;
}

static void report_calls(size_t count, offset_getter_fn get_offset,
    call_size_getter_fn get_size, uint_getter_fn get_kind,
    uint_getter_fn get_failed)
{
    size_t i;

    for (i = 0; i < count; i++) {
        printf("call=%zu kind=%u size=%zu offset=0x%zx failed=%u\n",
            i + 1U, get_kind(i), get_size(i), (size_t)get_offset(i),
            get_failed(i));
    }
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc_ctx = NULL;
    EVP_CIPHER_CTX *dec_ctx = NULL;
    unsigned char ciphertext[64];
    unsigned char tag[16];
    unsigned char recovered[64];
    unsigned char tag_copy[sizeof(expected_tag)];
    size_t ivlen = sizeof(iv);
    OSSL_PARAM enc_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_END
    };
    OSSL_PARAM tag_params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
            tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    OSSL_PARAM dec_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
            tag_copy, sizeof(tag_copy)),
        OSSL_PARAM_END
    };
    size_getter_fn get_direct_count;
    size_getter_fn get_fail_hits;
    size_getter_fn get_fail_nth;
    size_getter_fn get_total_calls;
    size_getter_fn get_dladdr_failures;
    size_getter_fn get_name_mismatches;
    offset_getter_fn get_offset;
    call_size_getter_fn get_size;
    uint_getter_fn get_kind;
    uint_getter_fn get_failed;
    const char *failure_stage = "none";
    const char *classification;
    int enc_total = 0;
    int dec_total = 0;
    int outl = 0;
    int ret;
    int partial_output = 0;
    int end_to_end_valid = 0;
    int exit_code;
    size_t direct_count;
    size_t fail_hits;
    size_t requested;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE_DIR\n", argv[0]);
        return 2;
    }
    if (!load_function(&get_direct_count, sizeof(get_direct_count),
            "g301fi_direct_count")
        || !load_function(&get_fail_hits, sizeof(get_fail_hits),
            "g301fi_fail_hits")
        || !load_function(&get_fail_nth, sizeof(get_fail_nth),
            "g301fi_fail_nth")
        || !load_function(&get_total_calls, sizeof(get_total_calls),
            "g301fi_total_interposed_calls")
        || !load_function(&get_dladdr_failures,
            sizeof(get_dladdr_failures), "g301fi_dladdr_failures")
        || !load_function(&get_name_mismatches,
            sizeof(get_name_mismatches), "g301fi_target_name_mismatches")
        || !load_function(&get_offset, sizeof(get_offset),
            "g301fi_call_offset")
        || !load_function(&get_size, sizeof(get_size),
            "g301fi_call_size")
        || !load_function(&get_kind, sizeof(get_kind),
            "g301fi_call_kind")
        || !load_function(&get_failed, sizeof(get_failed),
            "g301fi_call_failed")) {
        fprintf(stderr, "interposer control symbols unavailable\n");
        return 40;
    }

    memset(ciphertext, SENTINEL, sizeof(ciphertext));
    memset(tag, SENTINEL, sizeof(tag));
    memset(recovered, SENTINEL, sizeof(recovered));
    memcpy(tag_copy, expected_tag, sizeof(tag_copy));

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        failure_stage = "libctx_new";
        goto end;
    }
    if (OSSL_PROVIDER_set_default_search_path(libctx, argv[1]) <= 0) {
        failure_stage = "search_path";
        goto end;
    }
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    if (default_provider == NULL) {
        failure_stage = "default_load";
        goto end;
    }
    g301_provider = OSSL_PROVIDER_load(libctx, "g301");
    if (g301_provider == NULL) {
        failure_stage = "g301_load";
        goto end;
    }
    cipher = EVP_CIPHER_fetch(libctx, WORKING_NAME, PROPERTY_QUERY);
    if (cipher == NULL) {
        failure_stage = "fetch";
        goto end;
    }

    enc_ctx = EVP_CIPHER_CTX_new();
    if (enc_ctx == NULL) {
        failure_stage = "enc_ctx_new";
        goto end;
    }
    if (EVP_EncryptInit_ex2(enc_ctx, cipher, key, iv, enc_params) <= 0) {
        failure_stage = "enc_init";
        partial_output = changed(ciphertext, sizeof(ciphertext))
            || changed(tag, sizeof(tag));
        goto end;
    }
    if (EVP_EncryptUpdate(enc_ctx, NULL, &outl, aad,
            (int)sizeof(aad))
            <= 0
        || outl != (int)sizeof(aad)) {
        failure_stage = "enc_aad";
        goto end;
    }
    if (EVP_EncryptUpdate(enc_ctx, ciphertext, &outl, plaintext,
            (int)sizeof(plaintext))
            <= 0
        || outl != (int)sizeof(plaintext)) {
        failure_stage = "enc_payload";
        partial_output = changed(ciphertext, sizeof(ciphertext));
        goto end;
    }
    enc_total = outl;
    if (EVP_EncryptFinal_ex(enc_ctx, ciphertext + enc_total, &outl) <= 0
        || outl != 0) {
        failure_stage = "enc_final";
        partial_output = outl > 0;
        goto end;
    }
    enc_total += outl;
    if (EVP_CIPHER_CTX_get_params(enc_ctx, tag_params) <= 0
        || tag_params[0].return_size != sizeof(tag)) {
        failure_stage = "tag_get";
        partial_output = changed(tag, sizeof(tag));
        goto end;
    }
    if (enc_total != (int)sizeof(expected_ciphertext)
        || memcmp(ciphertext, expected_ciphertext,
               sizeof(expected_ciphertext))
            != 0
        || memcmp(tag, expected_tag, sizeof(expected_tag)) != 0) {
        failure_stage = "enc_kat";
        goto end;
    }

    dec_ctx = EVP_CIPHER_CTX_new();
    if (dec_ctx == NULL) {
        failure_stage = "dec_ctx_new";
        goto end;
    }
    if (EVP_DecryptInit_ex2(dec_ctx, cipher, key, iv, dec_params) <= 0) {
        failure_stage = "dec_init";
        partial_output = changed(recovered, sizeof(recovered));
        goto end;
    }
    if (EVP_DecryptUpdate(dec_ctx, NULL, &outl, aad,
            (int)sizeof(aad))
            <= 0
        || outl != (int)sizeof(aad)) {
        failure_stage = "dec_aad";
        goto end;
    }
    if (EVP_DecryptUpdate(dec_ctx, recovered, &outl, ciphertext,
            enc_total)
            <= 0
        || outl != enc_total) {
        failure_stage = "dec_payload";
        partial_output = changed(recovered, sizeof(recovered));
        goto end;
    }
    dec_total = outl;
    if (EVP_DecryptFinal_ex(dec_ctx, recovered + dec_total, &outl) <= 0
        || outl != 0) {
        failure_stage = "dec_final";
        partial_output = outl > 0;
        goto end;
    }
    dec_total += outl;
    end_to_end_valid = dec_total == (int)sizeof(plaintext)
        && memcmp(recovered, plaintext, sizeof(plaintext)) == 0;

end:
    direct_count = get_direct_count();
    fail_hits = get_fail_hits();
    requested = get_fail_nth();
    if (requested == 0) {
        classification = end_to_end_valid
            ? "BASELINE_VALID"
            : "BASELINE_FAILURE";
        exit_code = end_to_end_valid ? 0 : 31;
    } else if (fail_hits == 0) {
        classification = "INJECTION_NOT_REACHED";
        exit_code = 21;
    } else if (end_to_end_valid) {
        classification = "FALSE_SUCCESS";
        exit_code = 20;
    } else if (partial_output) {
        classification = "CONTROLLED_FAILURE_PARTIAL_OUTPUT";
        exit_code = 12;
    } else {
        classification = "CONTROLLED_FAILURE_NO_OUTPUT";
        exit_code = 10;
    }

    printf("classification=%s fail_nth=%zu direct_count=%zu fail_hits=%zu "
           "failure_stage=%s partial_output=%d end_to_end_valid=%d "
           "total_interposed_calls=%zu dladdr_failures=%zu "
           "target_name_mismatches=%zu\n",
        classification, requested, direct_count, fail_hits, failure_stage,
        partial_output, end_to_end_valid, get_total_calls(),
        get_dladdr_failures(), get_name_mismatches());
    report_calls(direct_count, get_offset, get_size, get_kind, get_failed);

    EVP_CIPHER_CTX_free(dec_ctx);
    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    ret = exit_code;
    return ret;
}
