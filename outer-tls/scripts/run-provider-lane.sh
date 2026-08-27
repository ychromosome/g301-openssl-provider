#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu
export CCACHE_DISABLE=1

if [ "$#" -ne 3 ]; then
    echo "usage: $0 OPENSSL_PREFIX FRESH_BUILD_DIR EXPECTED_MAJOR" >&2
    exit 2
fi

prefix=$1
build_dir=$2
expected_major=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
. "$script_dir/common.sh"
library_path=$(g301_find_openssl_libdir "$prefix")

if [ -e "$build_dir" ]; then
    echo "build directory must not exist: $build_dir" >&2
    exit 2
fi
test -x "$prefix/bin/openssl"
g301_check_openssl_major "$prefix/bin/openssl" "$library_path" \
    "$expected_major"

cmake -S "$source_dir" -B "$build_dir" \
    -DBUILD_TESTING=ON \
    -DG301_ENABLE_MBEDTLS_ORACLE=ON \
    -DG301_ENABLE_PRIVATE_TLS_E2E=OFF \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER="${CC:-cc}" \
    -DOPENSSL_ROOT_DIR="$prefix" \
    -DOPENSSL_USE_STATIC_LIBS=FALSE
cmake --build "$build_dir" --parallel
LD_LIBRARY_PATH="$library_path" \
    ctest --test-dir "$build_dir" --output-on-failure --no-tests=error
"$script_dir/check-provider-surface.sh" \
    "$build_dir/g301.so" "$prefix" "$expected_major"

OPENSSL_MODULES="$build_dir" LD_LIBRARY_PATH="$library_path" \
    "$prefix/bin/openssl" list \
        -provider-path "$build_dir" -provider default -provider g301 \
        -cipher-algorithms -propquery 'provider=g301' \
    | grep -q 'G301-AES-256-GCM-V1'

echo "G301 provider ABI $expected_major lane: PASS"
