/* SPDX-License-Identifier: Apache-2.0 */

#ifndef G301_TLS_CAPABILITY_H
#define G301_TLS_CAPABILITY_H

#include <openssl/core_names.h>

#include "g301_internal.h"

/*
 * Local compatibility names for the proposed generic OpenSSL interface.
 * A future patched header may provide the same definitions.
 */
#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_NAME
#define OSSL_CAPABILITY_TLS_CIPHERSUITE_NAME \
    "tls-ciphersuite-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_CODE_POINT
#define OSSL_CAPABILITY_TLS_CIPHERSUITE_CODE_POINT \
    "tls-ciphersuite-code-point"
#endif
#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_AEAD_NAME
#define OSSL_CAPABILITY_TLS_CIPHERSUITE_AEAD_NAME \
    "tls-ciphersuite-aead-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_DIGEST_NAME
#define OSSL_CAPABILITY_TLS_CIPHERSUITE_DIGEST_NAME \
    "tls-ciphersuite-digest-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_TAG_LENGTH
#define OSSL_CAPABILITY_TLS_CIPHERSUITE_TAG_LENGTH \
    "tls-ciphersuite-tag-length"
#endif
#ifndef OSSL_CAPABILITY_TLS_CIPHERSUITE_SECURITY_BITS
#define OSSL_CAPABILITY_TLS_CIPHERSUITE_SECURITY_BITS \
    "tls-ciphersuite-security-bits"
#endif
#define G301_TLS_CIPHERSUITE_CAPABILITY "TLS-CIPHERSUITE"
#define G301_TLS_WORKING_CODE_POINT 0xff30U
#define G301_TLS_DIGEST_NAME "SHA2-384"
#define G301_TLS_SECURITY_BITS 256U

#endif
