#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

g301_find_openssl_libdir()
{
    prefix=$1
    if [ -n "${OPENSSL_LIB_DIR:-}" ]; then
        if [ ! -d "$OPENSSL_LIB_DIR" ]; then
            echo "OPENSSL_LIB_DIR is not a directory: $OPENSSL_LIB_DIR" >&2
            return 1
        fi
        CDPATH= cd -- "$OPENSSL_LIB_DIR" && pwd -P
        return
    fi
    for dir in "$prefix/lib64" "$prefix/lib" \
            "$prefix"/lib/*-linux-gnu "$prefix"/lib64/*-linux-gnu; do
        if [ -d "$dir" ] \
            && { [ -e "$dir/libcrypto.so" ] \
                || [ -e "$dir/libcrypto.so.3" ] \
                || [ -e "$dir/libcrypto.so.4" ]; }; then
            CDPATH= cd -- "$dir" && pwd -P
            return
        fi
    done
    echo "cannot locate libcrypto below $prefix; set OPENSSL_LIB_DIR" >&2
    return 1
}

g301_check_openssl_major()
{
    openssl_bin=$1
    library_path=$2
    expected_major=$3
    version=$(LD_LIBRARY_PATH="$library_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$openssl_bin" version | awk '{print $2}') || return 1
    major=${version%%.*}
    if [ "$major" != "$expected_major" ]; then
        echo "expected OpenSSL ABI major $expected_major, got $version" >&2
        return 1
    fi
}
