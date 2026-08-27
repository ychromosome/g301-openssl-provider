/* SPDX-License-Identifier: Apache-2.0 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

typedef struct manifest_field_st {
    unsigned char kind;
    unsigned int value;
} MANIFEST_FIELD;

static const MANIFEST_FIELD data_fields[] = {
    { 0x01, 301 },
    { 0x01, 99 },
    { 0x01, 372 },
    { 0x01, 175 }
};

static const MANIFEST_FIELD control_trailer = { 0x02, 947 };

static const unsigned char expected_manifest[32] = {
    0x47, 0x33, 0x30, 0x31, 0x2d, 0x54, 0x4c, 0x53,
    0x31, 0x33, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x01,
    0x04, 0x01, 0x01, 0x2d, 0x01, 0x00, 0x63, 0x01,
    0x01, 0x74, 0x01, 0x00, 0xaf, 0x02, 0x03, 0xb3
};

static const unsigned char expected_sha256[32] = {
    0x08, 0xab, 0x7a, 0xb1, 0x7f, 0x47, 0x31, 0xf9,
    0xbc, 0x74, 0x4c, 0x3e, 0x9e, 0x6e, 0xeb, 0xc5,
    0xeb, 0x20, 0xa8, 0xfe, 0xdd, 0xd6, 0x65, 0x4b,
    0x9d, 0x8c, 0x13, 0x9a, 0x11, 0x16, 0x5c, 0x4c
};

static int append_u16be(unsigned char output[32], size_t *offset,
    unsigned int value)
{
    if (value > 0xffffU || *offset > 30)
        return 0;
    output[(*offset)++] = (unsigned char)(value >> 8);
    output[(*offset)++] = (unsigned char)(value & 0xffU);
    return 1;
}

static int reconstruct(unsigned char output[32])
{
    static const unsigned char label[] = "G301-TLS13-AEAD";
    size_t offset = 0;
    size_t i;

    if (sizeof(label) - 1 != 15)
        return 0;
    memcpy(output + offset, label, sizeof(label) - 1);
    offset += sizeof(label) - 1;
    output[offset++] = 0x01;
    if (sizeof(data_fields) / sizeof(data_fields[0]) > UCHAR_MAX)
        return 0;
    output[offset++] = (unsigned char)(sizeof(data_fields) / sizeof(data_fields[0]));
    for (i = 0; i < sizeof(data_fields) / sizeof(data_fields[0]); i++) {
        if (data_fields[i].kind != 0x01)
            return 0;
        output[offset++] = data_fields[i].kind;
        if (!append_u16be(output, &offset, data_fields[i].value))
            return 0;
    }
    if (control_trailer.kind != 0x02)
        return 0;
    output[offset++] = control_trailer.kind;
    if (!append_u16be(output, &offset, control_trailer.value))
        return 0;
    return offset == 32;
}

static int sha256(const unsigned char *input, size_t input_len,
    unsigned char output[32])
{
    size_t output_len = 0;

    return EVP_Q_digest(NULL, "SHA2-256", "provider=default", input,
               input_len, output, &output_len)
        > 0
        && output_len == 32;
}

int main(void)
{
    unsigned char manifest[32];
    unsigned char digest[32];
    size_t i;

    if (!reconstruct(manifest)) {
        fputs("manifest reconstruction failed\n", stderr);
        return EXIT_FAILURE;
    }
    if (memcmp(manifest, expected_manifest, sizeof(manifest)) != 0) {
        fputs("manifest bytes mismatch\n", stderr);
        return EXIT_FAILURE;
    }
    if (!sha256(manifest, sizeof(manifest), digest)) {
        fputs("manifest SHA-256 calculation failed\n", stderr);
        return EXIT_FAILURE;
    }
    if (memcmp(digest, expected_sha256, sizeof(digest)) != 0) {
        fputs("manifest SHA-256 mismatch\n", stderr);
        return EXIT_FAILURE;
    }

    for (i = 0; i < sizeof(manifest); i++) {
        unsigned char mutation[sizeof(manifest)];
        unsigned char mutation_digest[sizeof(digest)];

        memcpy(mutation, manifest, sizeof(mutation));
        mutation[i] ^= 1U;
        if (memcmp(mutation, manifest, sizeof(mutation)) == 0
            || !sha256(mutation, sizeof(mutation), mutation_digest)
            || memcmp(mutation_digest, expected_sha256,
                   sizeof(mutation_digest))
                == 0) {
            fprintf(stderr, "manifest mutation %zu was not distinguished\n", i);
            return EXIT_FAILURE;
        }
    }

    puts("g301 manifest reconstruction and 32 byte mutations: ok");
    return EXIT_SUCCESS;
}
