/* SPDX-License-Identifier: Apache-2.0 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define G301_NAME "G301-AES-256-GCM-V1"
#define G301_QUERY "provider=g301,fips=no"
#define REFERENCE_QUERY "provider=default"
#define TAG_LENGTH ((size_t)16)
#define IV_LENGTH ((size_t)12)
#define KEY_LENGTH ((size_t)32)
#define AAD_LENGTH ((size_t)5)
#define MANIFEST_LENGTH ((size_t)32)
#define EXPLICIT_AAD_LENGTH (MANIFEST_LENGTH + AAD_LENGTH)
#define CORPUS_RECORDS ((size_t)256)
#define PATH_COUNT ((size_t)4)
#define PAYLOAD_COUNT ((size_t)4)

typedef enum path_id_st {
    PATH_DEFAULT_A = 0,
    PATH_DEFAULT_MA_PREBUILT = 1,
    PATH_DEFAULT_SPLIT_MA = 2,
    PATH_G301_A = 3
} PATH_ID;

typedef struct path_st {
    PATH_ID id;
    const char *name;
    EVP_CIPHER *cipher;
} PATH;

typedef struct corpus_st {
    size_t payload_size;
    unsigned char *ciphertexts;
    unsigned char tags[CORPUS_RECORDS][TAG_LENGTH];
    unsigned char ivs[CORPUS_RECORDS][IV_LENGTH];
} CORPUS;

typedef struct runner_st {
    EVP_CIPHER_CTX *ctx;
    const PATH *path;
    const CORPUS *corpus;
    unsigned char *output;
    unsigned char *plaintext;
    size_t payload_size;
    uint64_t record_index;
    uint64_t checksum;
    unsigned char caller_aad[AAD_LENGTH];
    unsigned char explicit_aad[EXPLICIT_AAD_LENGTH];
    unsigned char last_tag[TAG_LENGTH];
    int encrypt;
} RUNNER;

static const unsigned char key[KEY_LENGTH] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char manifest[MANIFEST_LENGTH] = {
    0x47, 0x33, 0x30, 0x31, 0x2d, 0x54, 0x4c, 0x53,
    0x31, 0x33, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x01,
    0x04, 0x01, 0x01, 0x2d, 0x01, 0x00, 0x63, 0x01,
    0x01, 0x74, 0x01, 0x00, 0xaf, 0x02, 0x03, 0xb3
};

static const size_t payload_sizes[PAYLOAD_COUNT] = {
    1, 16, 1024, 16385
};

static void print_errors(const char *where)
{
    fprintf(stderr, "benchmark failure: %s\n", where);
    ERR_print_errors_fp(stderr);
}

static int make_iv(uint64_t counter, unsigned char iv[IV_LENGTH])
{
    size_t i;

    memset(iv, 0, IV_LENGTH);
    iv[0] = 0x47;
    iv[1] = 0x33;
    iv[2] = 0x30;
    iv[3] = 0x31;
    for (i = 0; i < sizeof(counter); i++)
        iv[IV_LENGTH - 1 - i] = (unsigned char)(counter >> (i * 8));
    return 1;
}

static int set_tag(EVP_CIPHER_CTX *ctx, const unsigned char tag[TAG_LENGTH])
{
    unsigned char copy[TAG_LENGTH];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
            copy, sizeof(copy)),
        OSSL_PARAM_END
    };

    memcpy(copy, tag, sizeof(copy));
    return EVP_CIPHER_CTX_set_params(ctx, params) > 0;
}

static int get_tag(EVP_CIPHER_CTX *ctx, unsigned char tag[TAG_LENGTH])
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
            tag, TAG_LENGTH),
        OSSL_PARAM_END
    };

    return EVP_CIPHER_CTX_get_params(ctx, params) > 0
        && params[0].return_size == TAG_LENGTH;
}

static int build_aad(size_t payload_size,
    unsigned char caller_aad[AAD_LENGTH],
    unsigned char explicit_aad[EXPLICIT_AAD_LENGTH])
{
    size_t ciphertext_size = payload_size + TAG_LENGTH;

    if (ciphertext_size > UINT16_MAX)
        return 0;
    caller_aad[0] = 0x17;
    caller_aad[1] = 0x03;
    caller_aad[2] = 0x03;
    caller_aad[3] = (unsigned char)(ciphertext_size >> 8);
    caller_aad[4] = (unsigned char)ciphertext_size;
    memcpy(explicit_aad, manifest, MANIFEST_LENGTH);
    memcpy(explicit_aad + MANIFEST_LENGTH, caller_aad, AAD_LENGTH);
    return 1;
}

static int aad_call(EVP_CIPHER_CTX *ctx, int encrypt,
    const unsigned char *aad, size_t aad_len)
{
    int outl = 0;
    int ret;

    if (encrypt)
        ret = EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);
    else
        ret = EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);
    return ret > 0 && outl == (int)aad_len;
}

static int aad_update(EVP_CIPHER_CTX *ctx, int encrypt, PATH_ID path,
    const unsigned char caller_aad[AAD_LENGTH],
    const unsigned char explicit_aad[EXPLICIT_AAD_LENGTH])
{
    switch (path) {
    case PATH_DEFAULT_A:
    case PATH_G301_A:
        return aad_call(ctx, encrypt, caller_aad, AAD_LENGTH);
    case PATH_DEFAULT_MA_PREBUILT:
        return aad_call(ctx, encrypt, explicit_aad, EXPLICIT_AAD_LENGTH);
    case PATH_DEFAULT_SPLIT_MA:
        return aad_call(ctx, encrypt, manifest, MANIFEST_LENGTH)
            && aad_call(ctx, encrypt, caller_aad, AAD_LENGTH);
    }
    return 0;
}

static int encrypt_once(EVP_CIPHER *cipher, PATH_ID path,
    const unsigned char iv[IV_LENGTH], const unsigned char *plaintext,
    size_t payload_size, unsigned char *ciphertext,
    unsigned char tag[TAG_LENGTH])
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char caller_aad[AAD_LENGTH];
    unsigned char explicit_aad[EXPLICIT_AAD_LENGTH];
    size_t iv_len = IV_LENGTH;
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len),
        OSSL_PARAM_END
    };
    int outl = 0;
    int total = 0;
    int ok = 0;

    if (payload_size > (size_t)INT_MAX
        || !build_aad(payload_size, caller_aad, explicit_aad))
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) <= 0
        || !aad_update(ctx, 1, path, caller_aad, explicit_aad)
        || EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext,
               (int)payload_size)
            <= 0)
        goto end;
    total = outl;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &outl) <= 0)
        goto end;
    total += outl;
    if ((size_t)total != payload_size || !get_tag(ctx, tag))
        goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int decrypt_once(EVP_CIPHER *cipher, PATH_ID path,
    const unsigned char iv[IV_LENGTH], const unsigned char *ciphertext,
    size_t payload_size, const unsigned char tag[TAG_LENGTH],
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char caller_aad[AAD_LENGTH];
    unsigned char explicit_aad[EXPLICIT_AAD_LENGTH];
    size_t iv_len = IV_LENGTH;
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len),
        OSSL_PARAM_END
    };
    int outl = 0;
    int total = 0;
    int ok = 0;

    if (payload_size > (size_t)INT_MAX
        || !build_aad(payload_size, caller_aad, explicit_aad))
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || EVP_DecryptInit_ex2(ctx, cipher, key, iv, params) <= 0
        || !set_tag(ctx, tag)
        || !aad_update(ctx, 0, path, caller_aad, explicit_aad)
        || EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext,
               (int)payload_size)
            <= 0)
        goto end;
    total = outl;
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &outl) <= 0)
        goto end;
    total += outl;
    ok = (size_t)total == payload_size;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int correctness_check(PATH paths[PATH_COUNT], size_t payload_size)
{
    unsigned char iv[IV_LENGTH];
    unsigned char *plaintext = NULL;
    unsigned char *recovered = NULL;
    unsigned char *ciphertexts[PATH_COUNT] = { NULL, NULL, NULL, NULL };
    unsigned char tags[PATH_COUNT][TAG_LENGTH];
    size_t i;
    int ok = 0;

    plaintext = OPENSSL_malloc(payload_size);
    recovered = OPENSSL_malloc(payload_size);
    if (plaintext == NULL || recovered == NULL)
        goto end;
    for (i = 0; i < payload_size; i++)
        plaintext[i] = (unsigned char)((i * 131U + payload_size) & 0xffU);
    make_iv(UINT64_C(0x100000000) + payload_size, iv);
    for (i = 0; i < PATH_COUNT; i++) {
        ciphertexts[i] = OPENSSL_malloc(payload_size);
        if (ciphertexts[i] == NULL
            || !encrypt_once(paths[i].cipher, paths[i].id, iv, plaintext,
                payload_size, ciphertexts[i], tags[i])
            || !decrypt_once(paths[i].cipher, paths[i].id, iv,
                ciphertexts[i], payload_size, tags[i], recovered)
            || CRYPTO_memcmp(plaintext, recovered, payload_size) != 0)
            goto end;
    }
    if (CRYPTO_memcmp(ciphertexts[PATH_DEFAULT_A],
            ciphertexts[PATH_DEFAULT_MA_PREBUILT], payload_size)
            != 0
        || CRYPTO_memcmp(ciphertexts[PATH_DEFAULT_MA_PREBUILT],
               ciphertexts[PATH_DEFAULT_SPLIT_MA], payload_size)
            != 0
        || CRYPTO_memcmp(ciphertexts[PATH_DEFAULT_SPLIT_MA],
               ciphertexts[PATH_G301_A], payload_size)
            != 0
        || CRYPTO_memcmp(tags[PATH_DEFAULT_MA_PREBUILT],
               tags[PATH_DEFAULT_SPLIT_MA], TAG_LENGTH)
            != 0
        || CRYPTO_memcmp(tags[PATH_DEFAULT_SPLIT_MA], tags[PATH_G301_A],
               TAG_LENGTH)
            != 0
        || CRYPTO_memcmp(tags[PATH_DEFAULT_A], tags[PATH_G301_A],
               TAG_LENGTH)
            == 0)
        goto end;
    ok = 1;
end:
    for (i = 0; i < PATH_COUNT; i++)
        OPENSSL_free(ciphertexts[i]);
    OPENSSL_free(recovered);
    OPENSSL_free(plaintext);
    if (!ok)
        print_errors("correctness preflight");
    return ok;
}

static int corpus_init(CORPUS *corpus, const PATH *path,
    const unsigned char *plaintext, size_t payload_size)
{
    size_t i;

    memset(corpus, 0, sizeof(*corpus));
    corpus->payload_size = payload_size;
    if (payload_size > SIZE_MAX / CORPUS_RECORDS)
        return 0;
    corpus->ciphertexts = OPENSSL_malloc(payload_size * CORPUS_RECORDS);
    if (corpus->ciphertexts == NULL)
        return 0;
    for (i = 0; i < CORPUS_RECORDS; i++) {
        make_iv(UINT64_C(0x200000000) + (uint64_t)i,
            corpus->ivs[i]);
        if (!encrypt_once(path->cipher, path->id, corpus->ivs[i],
                plaintext, payload_size,
                corpus->ciphertexts + i * payload_size, corpus->tags[i])) {
            print_errors("decryption corpus generation");
            return 0;
        }
    }
    return 1;
}

static void corpus_cleanup(CORPUS *corpus)
{
    OPENSSL_clear_free(corpus->ciphertexts,
        corpus->payload_size * CORPUS_RECORDS);
    corpus->ciphertexts = NULL;
}

static int runner_init(RUNNER *runner, const PATH *path,
    const CORPUS *corpus, const unsigned char *plaintext,
    size_t payload_size, int encrypt)
{
    unsigned char initial_iv[IV_LENGTH];
    size_t iv_len = IV_LENGTH;
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len),
        OSSL_PARAM_END
    };

    memset(runner, 0, sizeof(*runner));
    runner->path = path;
    runner->corpus = corpus;
    runner->plaintext = OPENSSL_malloc(payload_size);
    runner->output = OPENSSL_malloc(payload_size + TAG_LENGTH);
    runner->payload_size = payload_size;
    runner->encrypt = encrypt;
    runner->checksum = UINT64_C(0xcbf29ce484222325);
    runner->ctx = EVP_CIPHER_CTX_new();
    if (runner->plaintext == NULL || runner->output == NULL
        || runner->ctx == NULL
        || !build_aad(payload_size, runner->caller_aad,
            runner->explicit_aad))
        return 0;
    memcpy(runner->plaintext, plaintext, payload_size);
    make_iv(UINT64_C(0x300000000), initial_iv);
    if (encrypt) {
        if (EVP_EncryptInit_ex2(runner->ctx, path->cipher, key,
                initial_iv, params)
            <= 0)
            return 0;
    } else if (EVP_DecryptInit_ex2(runner->ctx, path->cipher, key,
                   initial_iv, params)
        <= 0) {
        return 0;
    }
    return 1;
}

static void runner_cleanup(RUNNER *runner)
{
    EVP_CIPHER_CTX_free(runner->ctx);
    OPENSSL_clear_free(runner->output, runner->payload_size + TAG_LENGTH);
    OPENSSL_clear_free(runner->plaintext, runner->payload_size);
    memset(runner, 0, sizeof(*runner));
}

static uint64_t checksum_mix(uint64_t state, uint64_t value)
{
    state ^= value + UINT64_C(0x9e3779b97f4a7c15)
        + (state << 6) + (state >> 2);
    state = (state << 17) | (state >> 47);
    return state * UINT64_C(0x100000001b3);
}

static int run_encrypt_record(RUNNER *runner)
{
    unsigned char iv[IV_LENGTH];
    unsigned char tag[TAG_LENGTH];
    int outl = 0;
    int total = 0;

    make_iv(UINT64_C(0x400000000) + runner->record_index, iv);
    if (EVP_EncryptInit_ex2(runner->ctx, NULL, NULL, iv, NULL) <= 0
        || !aad_update(runner->ctx, 1, runner->path->id,
            runner->caller_aad, runner->explicit_aad)
        || EVP_EncryptUpdate(runner->ctx, runner->output, &outl,
               runner->plaintext, (int)runner->payload_size)
            <= 0)
        return 0;
    total = outl;
    if (EVP_EncryptFinal_ex(runner->ctx, runner->output + total, &outl) <= 0)
        return 0;
    total += outl;
    if ((size_t)total != runner->payload_size
        || !get_tag(runner->ctx, tag))
        return 0;
    memcpy(runner->last_tag, tag, TAG_LENGTH);
    runner->checksum = checksum_mix(runner->checksum, runner->record_index);
    runner->checksum = checksum_mix(runner->checksum, runner->output[0]);
    runner->checksum = checksum_mix(runner->checksum,
        runner->output[runner->payload_size / 2]);
    runner->checksum = checksum_mix(runner->checksum,
        runner->output[runner->payload_size - 1]);
    runner->checksum = checksum_mix(runner->checksum, tag[0]);
    runner->checksum = checksum_mix(runner->checksum, tag[TAG_LENGTH - 1]);
    runner->record_index++;
    return 1;
}

static int run_decrypt_record(RUNNER *runner)
{
    size_t slot = (size_t)(runner->record_index % CORPUS_RECORDS);
    int outl = 0;
    int total = 0;

    if (EVP_DecryptInit_ex2(runner->ctx, NULL, NULL,
            runner->corpus->ivs[slot], NULL)
            <= 0
        || !set_tag(runner->ctx, runner->corpus->tags[slot])
        || !aad_update(runner->ctx, 0, runner->path->id,
            runner->caller_aad, runner->explicit_aad)
        || EVP_DecryptUpdate(runner->ctx, runner->output, &outl,
               runner->corpus->ciphertexts + slot * runner->payload_size,
               (int)runner->payload_size)
            <= 0)
        return 0;
    total = outl;
    if (EVP_DecryptFinal_ex(runner->ctx, runner->output + total, &outl) <= 0)
        return 0;
    total += outl;
    if ((size_t)total != runner->payload_size)
        return 0;
    runner->checksum = checksum_mix(runner->checksum, runner->record_index);
    runner->checksum = checksum_mix(runner->checksum, runner->output[0]);
    runner->checksum = checksum_mix(runner->checksum,
        runner->output[runner->payload_size / 2]);
    runner->checksum = checksum_mix(runner->checksum,
        runner->output[runner->payload_size - 1]);
    runner->checksum = checksum_mix(runner->checksum,
        runner->corpus->tags[slot][0]);
    runner->checksum = checksum_mix(runner->checksum,
        runner->corpus->tags[slot][TAG_LENGTH - 1]);
    runner->record_index++;
    return 1;
}

static int run_records(RUNNER *runner, uint64_t records)
{
    uint64_t i;

    for (i = 0; i < records; i++) {
        if (runner->encrypt) {
            if (!run_encrypt_record(runner))
                return 0;
        } else if (!run_decrypt_record(runner)) {
            return 0;
        }
    }
    return 1;
}

static int monotonic_ns(uint64_t *value)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
        return 0;
    *value = (uint64_t)ts.tv_sec * UINT64_C(1000000000)
        + (uint64_t)ts.tv_nsec;
    return 1;
}

static uint64_t records_for_size(size_t payload_size)
{
    if (payload_size <= 16)
        return UINT64_C(20000);
    if (payload_size <= 1024)
        return UINT64_C(4000);
    return UINT64_C(500);
}

static uint64_t warmup_for_size(size_t payload_size)
{
    if (payload_size <= 16)
        return UINT64_C(4000);
    if (payload_size <= 1024)
        return UINT64_C(1000);
    return UINT64_C(200);
}

static int verify_sample_outputs(RUNNER runners[PATH_COUNT], int encrypt)
{
    const RUNNER *base = &runners[PATH_DEFAULT_A];
    const RUNNER *prebuilt = &runners[PATH_DEFAULT_MA_PREBUILT];
    const RUNNER *split = &runners[PATH_DEFAULT_SPLIT_MA];
    const RUNNER *wrapper = &runners[PATH_G301_A];
    size_t i;

    for (i = 0; i < PATH_COUNT; i++) {
        if (runners[i].checksum == 0
            || runners[i].record_index != base->record_index)
            return 0;
    }
    if (prebuilt->checksum != split->checksum
        || split->checksum != wrapper->checksum
        || base->checksum == wrapper->checksum)
        return 0;
    if (!encrypt)
        return 1;
    if (CRYPTO_memcmp(base->output, prebuilt->output,
            base->payload_size)
            != 0
        || CRYPTO_memcmp(prebuilt->output, split->output,
               base->payload_size)
            != 0
        || CRYPTO_memcmp(split->output, wrapper->output,
               base->payload_size)
            != 0
        || CRYPTO_memcmp(prebuilt->last_tag, split->last_tag,
               TAG_LENGTH)
            != 0
        || CRYPTO_memcmp(split->last_tag, wrapper->last_tag,
               TAG_LENGTH)
            != 0
        || CRYPTO_memcmp(base->last_tag, wrapper->last_tag,
               TAG_LENGTH)
            == 0)
        return 0;
    return 1;
}

static int benchmark_direction(const char *mode, PATH paths[PATH_COUNT],
    size_t payload_size, int encrypt, unsigned int samples)
{
    CORPUS corpora[PATH_COUNT];
    RUNNER runners[PATH_COUNT];
    unsigned char *plaintext = NULL;
    uint64_t records = records_for_size(payload_size);
    uint64_t warmup = warmup_for_size(payload_size);
    unsigned int sample;
    size_t i;
    int ok = 0;

    memset(corpora, 0, sizeof(corpora));
    memset(runners, 0, sizeof(runners));
    plaintext = OPENSSL_malloc(payload_size);
    if (plaintext == NULL)
        goto end;
    for (i = 0; i < payload_size; i++)
        plaintext[i] = (unsigned char)((i * 131U + payload_size) & 0xffU);
    for (i = 0; i < PATH_COUNT; i++) {
        if (!encrypt
            && !corpus_init(&corpora[i], &paths[i], plaintext, payload_size))
            goto end;
        if (!runner_init(&runners[i], &paths[i],
                encrypt ? NULL : &corpora[i], plaintext, payload_size,
                encrypt)) {
            print_errors("runner initialization");
            goto end;
        }
        if (!run_records(&runners[i], warmup)) {
            print_errors("warmup");
            goto end;
        }
    }
    for (sample = 0; sample < samples; sample++) {
        for (i = 0; i < PATH_COUNT; i++) {
            size_t path_index = ((size_t)sample + i) % PATH_COUNT;
            RUNNER *runner = &runners[path_index];
            uint64_t begin;
            uint64_t end_time;
            uint64_t elapsed;
            double ns_per_record;
            double mib_per_second;

            if (!monotonic_ns(&begin)
                || !run_records(runner, records)
                || !monotonic_ns(&end_time)) {
                print_errors("timed sample");
                goto end;
            }
            if (!encrypt
                && CRYPTO_memcmp(runner->output, runner->plaintext,
                       runner->payload_size)
                    != 0) {
                print_errors("post-sample plaintext check");
                goto end;
            }
            elapsed = end_time - begin;
            ns_per_record = (double)elapsed / (double)records;
            mib_per_second = ((double)payload_size * (double)records
                                 / (1024.0 * 1024.0))
                / ((double)elapsed / 1.0e9);
            printf("%s,%s,%s,%zu,%" PRIu64 ",%" PRIu64
                   ",%u,%zu,%" PRIu64 ",%.6f,%.6f,0x%016" PRIx64 "\n",
                mode, encrypt ? "encrypt" : "decrypt",
                runner->path->name, payload_size, warmup, records,
                sample, i, elapsed, ns_per_record, mib_per_second,
                runner->checksum);
            fflush(stdout);
        }
        if (!verify_sample_outputs(runners, encrypt)) {
            print_errors("post-sample cross-path output/checksum gate");
            goto end;
        }
    }
    ok = 1;
end:
    for (i = 0; i < PATH_COUNT; i++) {
        runner_cleanup(&runners[i]);
        corpus_cleanup(&corpora[i]);
    }
    OPENSSL_clear_free(plaintext, payload_size);
    return ok;
}

static int parse_samples(const char *text, unsigned int *samples)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0'
        || value < 8UL || value > 1000UL || value > (unsigned long)UINT_MAX
        || value % PATH_COUNT != 0)
        return 0;
    *samples = (unsigned int)value;
    return 1;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    PATH paths[PATH_COUNT] = {
        { PATH_DEFAULT_A, "default_a", NULL },
        { PATH_DEFAULT_MA_PREBUILT, "default_ma_prebuilt", NULL },
        { PATH_DEFAULT_SPLIT_MA, "default_split_ma", NULL },
        { PATH_G301_A, "g301_a", NULL }
    };
    const char *mode;
    unsigned int samples = 48;
    size_t i;
    int exit_status = EXIT_FAILURE;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s MODE [SAMPLES]\n", argv[0]);
        return EXIT_FAILURE;
    }
    mode = argv[1];
    if (strchr(mode, ',') != NULL
        || (argc == 3 && !parse_samples(argv[2], &samples))) {
        fprintf(stderr, "invalid mode or sample count\n");
        return EXIT_FAILURE;
    }
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        goto end;
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    g301_provider = OSSL_PROVIDER_load(libctx, "g301");
    if (default_provider == NULL || g301_provider == NULL) {
        print_errors("provider load");
        goto end;
    }
    paths[PATH_DEFAULT_A].cipher = EVP_CIPHER_fetch(libctx,
        "AES-256-GCM", REFERENCE_QUERY);
    paths[PATH_DEFAULT_MA_PREBUILT].cipher = EVP_CIPHER_fetch(libctx,
        "AES-256-GCM", REFERENCE_QUERY);
    paths[PATH_DEFAULT_SPLIT_MA].cipher = EVP_CIPHER_fetch(libctx,
        "AES-256-GCM", REFERENCE_QUERY);
    paths[PATH_G301_A].cipher = EVP_CIPHER_fetch(libctx,
        G301_NAME, G301_QUERY);
    if (paths[PATH_DEFAULT_A].cipher == NULL
        || paths[PATH_DEFAULT_MA_PREBUILT].cipher == NULL
        || paths[PATH_DEFAULT_SPLIT_MA].cipher == NULL
        || paths[PATH_G301_A].cipher == NULL) {
        print_errors("cipher fetch");
        goto end;
    }
    printf("mode,direction,path,payload_size,warmup_records,records_per_sample,"
           "sample_index,position,elapsed_ns,ns_per_record,throughput_mib_s,checksum\n");
    for (i = 0; i < PAYLOAD_COUNT; i++) {
        if (!correctness_check(paths, payload_sizes[i])
            || !benchmark_direction(mode, paths, payload_sizes[i], 1, samples)
            || !benchmark_direction(mode, paths, payload_sizes[i], 0, samples))
            goto end;
    }
    exit_status = EXIT_SUCCESS;
end:
    for (i = 0; i < PATH_COUNT; i++)
        EVP_CIPHER_free(paths[i].cipher);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return exit_status;
}
