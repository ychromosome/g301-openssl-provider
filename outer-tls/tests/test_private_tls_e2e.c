/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>

#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_NAME
#error "This harness requires the patched private OpenSSL TLS capability API"
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "g301_tls_capability.h"

#define G301_E2E_STEP_LIMIT 10000U
#define G301_EXPORTER_LENGTH 64U

static void report_failure(const char *operation)
{
    fprintf(stderr, "g301 private TLS E2E: %s failed\n", operation);
    ERR_print_errors_fp(stderr);
}

static int ssl_retryable(SSL *ssl, int result)
{
    int error = SSL_get_error(ssl, result);

    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

static int load_provider_from(OSSL_LIB_CTX *libctx, const char *directory,
    const char *name, OSSL_PROVIDER **provider)
{
    if (directory != NULL
        && OSSL_PROVIDER_set_default_search_path(libctx, directory) <= 0)
        return 0;
    *provider = OSSL_PROVIDER_load(libctx, name);
    return *provider != NULL;
}

static int make_server_identity(OSSL_LIB_CTX *libctx, X509 **certificate_out,
    EVP_PKEY **private_key_out)
{
    static const unsigned char common_name[] = "g301-private-fork-e2e";
    char group_name[] = "P-256";
    OSSL_PARAM key_params[2];
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_MD *digest = NULL;
    X509 *certificate = NULL;
    X509_NAME *subject = NULL;
    int ok = 0;

    key_ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if (key_ctx == NULL || EVP_PKEY_keygen_init(key_ctx) <= 0)
        goto end;
    key_params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    key_params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(key_ctx, key_params) <= 0
        || EVP_PKEY_generate(key_ctx, &private_key) <= 0)
        goto end;

    certificate = X509_new_ex(libctx, NULL);
    if (certificate == NULL
        || X509_set_version(certificate, 2L) <= 0
        || ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1L) <= 0
        || X509_gmtime_adj(X509_getm_notBefore(certificate), 0L) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(certificate), 3600L) == NULL
        || X509_set_pubkey(certificate, private_key) <= 0)
        goto end;

    subject = X509_NAME_new();
    if (subject == NULL
        || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
               common_name, -1, -1, 0)
            <= 0
        || X509_set_subject_name(certificate, subject) <= 0
        || X509_set_issuer_name(certificate, subject) <= 0)
        goto end;

    digest = EVP_MD_fetch(libctx, "SHA2-256", "provider=default");
    if (digest == NULL || X509_sign(certificate, private_key, digest) <= 0)
        goto end;

    *certificate_out = certificate;
    *private_key_out = private_key;
    certificate = NULL;
    private_key = NULL;
    ok = 1;
end:
    X509_NAME_free(subject);
    X509_free(certificate);
    EVP_MD_free(digest);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(key_ctx);
    return ok;
}

static int configure_tls_contexts(OSSL_LIB_CTX *libctx,
    X509 *certificate, EVP_PKEY *private_key,
    SSL_CTX **client_ctx_out, SSL_CTX **server_ctx_out)
{
    SSL_CTX *client_ctx = NULL;
    SSL_CTX *server_ctx = NULL;
    int ok = 0;

    /* Provider ciphersuites are discovered when each SSL_CTX is created. */
    client_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    server_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    if (client_ctx == NULL || server_ctx == NULL
        || SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION) <= 0
        || SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION) <= 0
        || SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION) <= 0
        || SSL_CTX_set_max_proto_version(server_ctx, TLS1_3_VERSION) <= 0
        || SSL_CTX_set_ciphersuites(client_ctx, G301_WORKING_NAME) <= 0
        || SSL_CTX_set_ciphersuites(server_ctx, G301_WORKING_NAME) <= 0
        || SSL_CTX_use_certificate(server_ctx, certificate) <= 0
        || SSL_CTX_use_PrivateKey(server_ctx, private_key) <= 0
        || SSL_CTX_check_private_key(server_ctx) <= 0
        || SSL_CTX_set_num_tickets(server_ctx, 0) <= 0)
        goto end;

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
    *client_ctx_out = client_ctx;
    *server_ctx_out = server_ctx;
    client_ctx = NULL;
    server_ctx = NULL;
    ok = 1;
end:
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    return ok;
}

static int make_ssl_pair(SSL_CTX *client_ctx, SSL_CTX *server_ctx,
    SSL **client_out, SSL **server_out)
{
    SSL *client = NULL;
    SSL *server = NULL;
    BIO *client_bio = NULL;
    BIO *server_bio = NULL;
    int ok = 0;

    client = SSL_new(client_ctx);
    server = SSL_new(server_ctx);
    if (client == NULL || server == NULL
        || BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) <= 0)
        goto end;

    SSL_set_bio(client, client_bio, client_bio);
    client_bio = NULL;
    SSL_set_bio(server, server_bio, server_bio);
    server_bio = NULL;
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    *client_out = client;
    *server_out = server;
    client = NULL;
    server = NULL;
    ok = 1;
end:
    BIO_free(server_bio);
    BIO_free(client_bio);
    SSL_free(server);
    SSL_free(client);
    return ok;
}

static int drive_handshake(SSL *client, SSL *server)
{
    unsigned int step;
    int client_done = 0;
    int server_done = 0;

    for (step = 0; step < G301_E2E_STEP_LIMIT; step++) {
        int result;

        if (!client_done) {
            result = SSL_do_handshake(client);
            if (result == 1)
                client_done = 1;
            else if (!ssl_retryable(client, result)) {
                report_failure("client handshake");
                return 0;
            }
        }
        if (!server_done) {
            result = SSL_do_handshake(server);
            if (result == 1)
                server_done = 1;
            else if (!ssl_retryable(server, result)) {
                report_failure("server handshake");
                return 0;
            }
        }
        if (client_done && server_done
            && SSL_is_init_finished(client)
            && SSL_is_init_finished(server))
            return 1;
    }
    report_failure("bounded handshake progress");
    return 0;
}

static int check_selected_suite(SSL *ssl, const char *side)
{
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const EVP_MD *digest;
    const char *name;
    int algorithm_bits = 0;
    int security_bits;

    if (cipher == NULL) {
        report_failure(side);
        return 0;
    }
    name = SSL_CIPHER_get_name(cipher);
    digest = SSL_CIPHER_get_handshake_digest(cipher);
    security_bits = SSL_CIPHER_get_bits(cipher, &algorithm_bits);
    if (name == NULL || strcmp(name, G301_WORKING_NAME) != 0
        || SSL_CIPHER_get_protocol_id(cipher)
            != (uint16_t)G301_TLS_WORKING_CODE_POINT
        || SSL_CIPHER_is_aead(cipher) != 1
        || security_bits != (int)G301_TLS_SECURITY_BITS
        || algorithm_bits != (int)G301_TLS_SECURITY_BITS
        || digest == NULL
        || EVP_MD_is_a(digest, G301_TLS_DIGEST_NAME) != 1) {
        fprintf(stderr,
            "g301 private TLS E2E: unexpected %s suite: %s/0x%04x\n",
            side, name == NULL ? "(null)" : name,
            cipher == NULL ? 0U
                           : (unsigned int)SSL_CIPHER_get_protocol_id(cipher));
        return 0;
    }
    return 1;
}

static int transfer_exact(SSL *sender, SSL *receiver,
    const unsigned char *message, size_t message_length, const char *label)
{
    unsigned char *received = NULL;
    size_t sent = 0;
    size_t received_length = 0;
    unsigned int step;
    int ok = 0;

    received = OPENSSL_zalloc(message_length);
    if (received == NULL)
        goto end;
    for (step = 0; step < G301_E2E_STEP_LIMIT; step++) {
        if (sent < message_length) {
            size_t written = 0;
            int result = SSL_write_ex(sender, message + sent,
                message_length - sent, &written);

            if (result == 1) {
                if (written == 0)
                    goto end;
                sent += written;
            } else if (!ssl_retryable(sender, result)) {
                report_failure(label);
                goto end;
            }
        }
        if (received_length < message_length) {
            size_t read_length = 0;
            int result = SSL_read_ex(receiver, received + received_length,
                message_length - received_length, &read_length);

            if (result == 1) {
                if (read_length == 0)
                    goto end;
                received_length += read_length;
            } else if (!ssl_retryable(receiver, result)) {
                report_failure(label);
                goto end;
            }
        }
        if (sent == message_length && received_length == message_length) {
            ok = CRYPTO_memcmp(received, message, message_length) == 0;
            break;
        }
    }
end:
    if (!ok)
        fprintf(stderr, "g301 private TLS E2E: %s transfer mismatch\n",
            label);
    OPENSSL_clear_free(received, message_length);
    return ok;
}

static int check_exporter(SSL *client, SSL *server)
{
    static const char label[] = "EXPORTER-G301-private-fork-e2e";
    static const unsigned char context[] = {
        0x47, 0x33, 0x30, 0x31, 0xff, 0x30
    };
    unsigned char client_material[G301_EXPORTER_LENGTH];
    unsigned char server_material[G301_EXPORTER_LENGTH];
    int ok;

    ok = SSL_export_keying_material(client, client_material,
             sizeof(client_material), label, sizeof(label) - 1U,
             context, sizeof(context), 1)
            == 1
        && SSL_export_keying_material(server, server_material,
               sizeof(server_material), label, sizeof(label) - 1U,
               context, sizeof(context), 1)
            == 1
        && CRYPTO_memcmp(client_material, server_material,
               sizeof(client_material))
            == 0;
    OPENSSL_cleanse(server_material, sizeof(server_material));
    OPENSSL_cleanse(client_material, sizeof(client_material));
    if (!ok)
        report_failure("exporter agreement");
    return ok;
}

static int request_key_update(SSL *client)
{
    int result;

    if (SSL_key_update(client, SSL_KEY_UPDATE_REQUESTED) <= 0) {
        report_failure("SSL_key_update");
        return 0;
    }
    result = SSL_do_handshake(client);
    if (result != 1 && !ssl_retryable(client, result)) {
        report_failure("sending KeyUpdate");
        return 0;
    }
    return 1;
}

static int check_selection_without_g301(const char *default_provider_directory)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    SSL_CTX *ctx = NULL;
    int ok = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
        || !load_provider_from(libctx, default_provider_directory, "default",
            &default_provider))
        goto end;
    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (ctx == NULL
        || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) <= 0
        || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) <= 0)
        goto end;

    ERR_clear_error();
    if (SSL_CTX_set_ciphersuites(ctx, G301_WORKING_NAME) != 0)
        goto end;
    if (ERR_peek_error() == 0)
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    SSL_CTX_free(ctx);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    if (!ok)
        report_failure("negative selection without g301 provider");
    return ok;
}

int main(int argc, char **argv)
{
    static const unsigned char client_message[] = "client to server through G301 private TLS";
    static const unsigned char server_message[] = "server to client through G301 private TLS";
    static const unsigned char updated_client_message[] = "client traffic after requested KeyUpdate";
    static const unsigned char updated_server_message[] = "server traffic and KeyUpdate response";
    const char *default_provider_directory = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *g301_provider = NULL;
    EVP_PKEY *private_key = NULL;
    X509 *certificate = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL_CTX *server_ctx = NULL;
    SSL *client = NULL;
    SSL *server = NULL;
    int ok = 0;

    if (argc != 2 && argc != 3) {
        fprintf(stderr,
            "usage: %s G301_MODULE_DIRECTORY [DEFAULT_PROVIDER_DIRECTORY]\n",
            argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 3)
        default_provider_directory = argv[2];

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL
        || !load_provider_from(libctx, default_provider_directory, "default",
            &default_provider)
        || !load_provider_from(libctx, argv[1], "g301", &g301_provider)
        || !make_server_identity(libctx, &certificate, &private_key)
        || !configure_tls_contexts(libctx, certificate, private_key,
            &client_ctx, &server_ctx)
        || !make_ssl_pair(client_ctx, server_ctx, &client, &server)
        || !drive_handshake(client, server)
        || SSL_version(client) != TLS1_3_VERSION
        || SSL_version(server) != TLS1_3_VERSION
        || !check_selected_suite(client, "client")
        || !check_selected_suite(server, "server")
        || !transfer_exact(client, server, client_message,
            sizeof(client_message) - 1U, "client-to-server")
        || !transfer_exact(server, client, server_message,
            sizeof(server_message) - 1U, "server-to-client")
        || !check_exporter(client, server)
        || !request_key_update(client)
        || !transfer_exact(client, server, updated_client_message,
            sizeof(updated_client_message) - 1U,
            "client-to-server after KeyUpdate")
        || !transfer_exact(server, client, updated_server_message,
            sizeof(updated_server_message) - 1U,
            "server-to-client KeyUpdate response")
        || !check_selection_without_g301(default_provider_directory))
        goto end;

    ok = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    OSSL_PROVIDER_unload(g301_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    if (!ok) {
        report_failure("overall private-fork E2E");
        return EXIT_FAILURE;
    }
    puts("g301 private TLS E2E: ok (patched private fork only; TLS 1.3; "
         "G301-AES-256-GCM-V1/0xFF30; bidirectional data; exporter; "
         "requested KeyUpdate; provider-absent rejection)");
    return EXIT_SUCCESS;
}
