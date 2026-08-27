/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#define MAX_RECORDED_CALLS 32U

typedef void *(*zalloc_fn)(size_t, const char *, int);
typedef void *(*malloc_fn)(size_t, const char *, int);
typedef void *(*realloc_fn)(void *, size_t, const char *, int);

typedef struct direct_call_st {
    uintptr_t module_offset;
    size_t size;
    unsigned int kind;
    unsigned int failed;
} DIRECT_CALL;

static zalloc_fn real_zalloc;
static malloc_fn real_malloc;
static realloc_fn real_realloc;
static const char *target_module;
static size_t fail_nth;
static size_t direct_count;
static size_t fail_hits;
static size_t total_interposed_calls;
static size_t dladdr_failures;
static size_t target_name_mismatches;
static DIRECT_CALL calls[MAX_RECORDED_CALLS];

static size_t parse_size(const char *text)
{
    size_t value = 0;

    if (text == NULL || *text == '\0')
        return 0;
    while (*text != '\0') {
        unsigned int digit;

        if (*text < '0' || *text > '9')
            return 0;
        digit = (unsigned int)(*text - '0');
        if (value > (SIZE_MAX - digit) / 10U)
            return 0;
        value = value * 10U + digit;
        text++;
    }
    return value;
}

__attribute__((constructor)) static void g301fi_initialize(void)
{
    void *symbol;

    _Static_assert(sizeof(real_zalloc) == sizeof(symbol),
        "dlsym function pointer size mismatch");
    _Static_assert(sizeof(real_malloc) == sizeof(symbol),
        "dlsym function pointer size mismatch");
    _Static_assert(sizeof(real_realloc) == sizeof(symbol),
        "dlsym function pointer size mismatch");
    /* Resolve the default symbol version on either OpenSSL ABI major. */
    symbol = dlsym(RTLD_NEXT, "CRYPTO_zalloc");
    memcpy(&real_zalloc, &symbol, sizeof(real_zalloc));
    symbol = dlsym(RTLD_NEXT, "CRYPTO_malloc");
    memcpy(&real_malloc, &symbol, sizeof(real_malloc));
    symbol = dlsym(RTLD_NEXT, "CRYPTO_realloc");
    memcpy(&real_realloc, &symbol, sizeof(real_realloc));
    target_module = getenv("G301_FI_TARGET_MODULE");
    fail_nth = parse_size(getenv("G301_FI_FAIL_NTH"));
}

static int classify_direct_call(void *caller, uintptr_t *offset)
{
    Dl_info info;

    if (target_module == NULL || *target_module == '\0')
        return 0;
    if (dladdr(caller, &info) == 0 || info.dli_fname == NULL
        || info.dli_fbase == NULL) {
        dladdr_failures++;
        return 0;
    }
    if (strcmp(info.dli_fname, target_module) != 0) {
        target_name_mismatches++;
        return 0;
    }
    *offset = (uintptr_t)caller - (uintptr_t)info.dli_fbase;
    return 1;
}

static int record_direct(void *caller, size_t size, unsigned int kind)
{
    uintptr_t offset = 0;
    size_t index;
    int fail;

    total_interposed_calls++;
    if (!classify_direct_call(caller, &offset))
        return 0;

    direct_count++;
    index = direct_count - 1U;
    fail = fail_nth != 0 && direct_count == fail_nth;
    if (index < MAX_RECORDED_CALLS) {
        calls[index].module_offset = offset;
        calls[index].size = size;
        calls[index].kind = kind;
        calls[index].failed = (unsigned int)fail;
    }
    if (fail)
        fail_hits++;
    return fail;
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *caller = __builtin_extract_return_addr(__builtin_return_address(0));

    if (record_direct(caller, num, 1U))
        return NULL;
    if (real_zalloc == NULL)
        return NULL;
    return real_zalloc(num, file, line);
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    void *caller = __builtin_extract_return_addr(__builtin_return_address(0));

    if (record_direct(caller, num, 2U))
        return NULL;
    if (real_malloc == NULL)
        return NULL;
    return real_malloc(num, file, line);
}

void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line)
{
    void *caller = __builtin_extract_return_addr(__builtin_return_address(0));

    if (record_direct(caller, num, 3U))
        return NULL;
    if (real_realloc == NULL)
        return NULL;
    return real_realloc(addr, num, file, line);
}

size_t g301fi_direct_count(void)
{
    return direct_count;
}

size_t g301fi_fail_hits(void)
{
    return fail_hits;
}

size_t g301fi_fail_nth(void)
{
    return fail_nth;
}

size_t g301fi_total_interposed_calls(void)
{
    return total_interposed_calls;
}

size_t g301fi_dladdr_failures(void)
{
    return dladdr_failures;
}

size_t g301fi_target_name_mismatches(void)
{
    return target_name_mismatches;
}

uintptr_t g301fi_call_offset(size_t index)
{
    return index < direct_count && index < MAX_RECORDED_CALLS
        ? calls[index].module_offset
        : 0U;
}

size_t g301fi_call_size(size_t index)
{
    return index < direct_count && index < MAX_RECORDED_CALLS
        ? calls[index].size
        : 0U;
}

unsigned int g301fi_call_kind(size_t index)
{
    return index < direct_count && index < MAX_RECORDED_CALLS
        ? calls[index].kind
        : 0U;
}

unsigned int g301fi_call_failed(size_t index)
{
    return index < direct_count && index < MAX_RECORDED_CALLS
        ? calls[index].failed
        : 0U;
}
