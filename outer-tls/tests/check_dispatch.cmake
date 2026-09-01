# SPDX-License-Identifier: Apache-2.0

file(READ "${SOURCE_FILE}" source)

foreach(name
        NEWCTX FREECTX GET_PARAMS ENCRYPT_INIT DECRYPT_INIT UPDATE FINAL
        GETTABLE_PARAMS GET_CTX_PARAMS SET_CTX_PARAMS GETTABLE_CTX_PARAMS
        SETTABLE_CTX_PARAMS)
    string(REGEX MATCHALL "OSSL_FUNC_CIPHER_${name}," matches "${source}")
    list(LENGTH matches count)
    if(NOT count EQUAL 1)
        message(FATAL_ERROR "expected exactly one dispatch entry for ${name}, got ${count}")
    endif()
endforeach()

foreach(name
        DUPCTX CIPHER ENCRYPT_SKEY_INIT DECRYPT_SKEY_INIT
        PIPELINE_ENCRYPT_INIT PIPELINE_DECRYPT_INIT PIPELINE_UPDATE
        PIPELINE_FINAL)
    string(REGEX MATCHALL "OSSL_FUNC_CIPHER_${name}," matches "${source}")
    list(LENGTH matches count)
    if(NOT count EQUAL 0)
        message(FATAL_ERROR "forbidden first-slice dispatch entry: ${name}")
    endif()
endforeach()

foreach(name
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD
        OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN
        OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED
        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV
        OSSL_CIPHER_PARAM_AEAD_MAC_KEY
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT
        OSSL_CIPHER_PARAM_TLS_VERSION
        OSSL_CIPHER_PARAM_TLS_MAC
        OSSL_CIPHER_PARAM_TLS_MAC_SIZE)
    string(REGEX MATCHALL "${name}[^A-Z0-9_]" matches "${source}")
    list(LENGTH matches count)
    if(NOT count EQUAL 1)
        message(FATAL_ERROR
            "expected exactly one explicit fail-closed legacy denylist entry for ${name}, got ${count}")
    endif()
endforeach()

string(REGEX MATCHALL "G301_CIPHER_PARAM_PIPELINE_AEAD_TAG[^A-Z0-9_]"
    matches "${source}")
list(LENGTH matches count)
if(NOT count EQUAL 2)
    message(FATAL_ERROR
        "expected one definition and one denylist use for the pipeline tag name, got ${count}")
endif()

string(REGEX MATCHALL "G301_CIPHER_PARAM_ENCRYPT_THEN_MAC[^A-Z0-9_]"
    matches "${source}")
list(LENGTH matches count)
if(NOT count EQUAL 2)
    message(FATAL_ERROR
        "expected one definition and one denylist use for the ABI-4 encrypt-then-MAC name, got ${count}")
endif()

message(STATUS "G301 first-slice dispatch surface is exact")
