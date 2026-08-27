#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 MODULE OPENSSL_PREFIX EXPECTED_MAJOR" >&2
    exit 2
fi

module=$1
prefix=$2
expected_major=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/common.sh"
library_path=$(g301_find_openssl_libdir "$prefix")

test -f "$module"
test -x "$prefix/bin/openssl"

g301_check_openssl_major "$prefix/bin/openssl" "$library_path" \
    "$expected_major"

exports=$(nm -D --defined-only --format=posix "$module" \
    | awk '{ print $1 }')
test "$exports" = "OSSL_provider_init"

loaded_crypto=$(LD_LIBRARY_PATH="$library_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ldd "$module" \
    | awk '/libcrypto[.]so/ { print $3; exit }')
needed_crypto=$(readelf -dW "$module" \
    | awk '/\(NEEDED\).*libcrypto[.]so/ {
        line = $0
        sub(/^.*\[/, "", line)
        sub(/\].*$/, "", line)
        print line
    }')
expected_soname="libcrypto.so.$expected_major"
if [ "$needed_crypto" != "$expected_soname" ]; then
    echo "module needs unexpected libcrypto ABI: ${needed_crypto:-none}" >&2
    exit 1
fi
if [ -z "$loaded_crypto" ] || [ ! -e "$loaded_crypto" ]; then
    echo "module does not resolve libcrypto: ${loaded_crypto:-none}" >&2
    exit 1
fi
loaded_crypto=$(realpath -- "$loaded_crypto")
library_path=$(realpath -- "$library_path")
case "$loaded_crypto" in
    "$library_path"/*) ;;
    *)
        echo "module resolves libcrypto outside the requested lane: $loaded_crypto" >&2
        exit 1
        ;;
esac
loaded_soname=$(readelf -dW "$loaded_crypto" \
    | awk '/\(SONAME\)/ {
        line = $0
        sub(/^.*\[/, "", line)
        sub(/\].*$/, "", line)
        print line
        exit
    }')
if [ "$loaded_soname" != "$expected_soname" ]; then
    echo "resolved libcrypto has unexpected SONAME: ${loaded_soname:-none}" >&2
    exit 1
fi

readelf -dW "$module" | grep -q 'BIND_NOW\|FLAGS.*NOW'
readelf -lW "$module" | grep -q 'GNU_RELRO'
if readelf -lW "$module" | awk '/GNU_STACK/ { print $0 }' | grep -q 'RWE'; then
    echo "module has an executable stack" >&2
    exit 1
fi

python3 - "$module" <<'PY'
import pathlib
import sys

manifest = bytes.fromhex(
    "473330312d544c5331332d41454144010401012d0100630101740100af0203b3"
)
count = pathlib.Path(sys.argv[1]).read_bytes().count(manifest)
if count != 1:
    raise SystemExit(f"expected one embedded G301 manifest, found {count}")
PY

echo "provider surface: PASS (ABI $expected_major, one export, one manifest)"
