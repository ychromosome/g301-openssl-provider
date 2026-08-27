#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export CCACHE_DISABLE=1

if [[ $# -ne 4 ]]; then
    echo "usage: $0 OPENSSL_PREFIX EXPECTED_MAJOR MODULE_DIR FRESH_OUTPUT_DIR" >&2
    exit 2
fi

prefix=$(realpath "$1")
expected_major=$2
module_dir=$(realpath "$3")
output_dir=$4
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(realpath "$script_dir/..")
source "$script_dir/common.sh"
library_path=$(g301_find_openssl_libdir "$prefix")
cc_bin=${CC:-cc}
valgrind_bin=${VALGRIND:-$(command -v valgrind || true)}

if [[ -e "$output_dir" ]]; then
    echo "output path already exists: $output_dir" >&2
    exit 2
fi
test -f "$module_dir/g301.so"
g301_check_openssl_major "$prefix/bin/openssl" "$library_path" \
    "$expected_major"
mkdir -p "$output_dir/logs"
output_dir=$(realpath "$output_dir")

compile_flags=(
    -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror
    -Wconversion -Wformat=2 -Wshadow -Wstrict-prototypes -Wundef
    -fstack-protector-strong -I"$prefix/include"
)
"$cc_bin" "${compile_flags[@]}" -fPIC -shared \
    "$source_dir/tests/failure/direct_alloc_interposer.c" \
    -o "$output_dir/direct_alloc_interposer.so" -ldl \
    -Wl,-z,relro,-z,now
"$cc_bin" "${compile_flags[@]}" \
    "$source_dir/tests/failure/direct_alloc_harness.c" \
    -o "$output_dir/direct_alloc_harness" \
    -L"$library_path" -Wl,-rpath,"$library_path" -lcrypto -ldl

module=$(realpath "$module_dir/g301.so")
interposer="$output_dir/direct_alloc_interposer.so"
harness="$output_dir/direct_alloc_harness"

run_case() {
    local name=$1 target=$2 fail_nth=$3 expected_rc=$4 log=$5
    local rc
    set +e
    if [[ -n "$valgrind_bin" ]]; then
        env LD_PRELOAD="$interposer" LD_LIBRARY_PATH="$library_path" \
            OPENSSL_MODULES="$module_dir" G301_FI_TARGET_MODULE="$target" \
            G301_FI_FAIL_NTH="$fail_nth" \
            "$valgrind_bin" --quiet --error-exitcode=99 --leak-check=full \
                --show-leak-kinds=definite,indirect,possible \
                --errors-for-leak-kinds=definite,indirect,possible \
                "$harness" "$module_dir" >"$log" 2>&1
    else
        env LD_PRELOAD="$interposer" LD_LIBRARY_PATH="$library_path" \
            OPENSSL_MODULES="$module_dir" G301_FI_TARGET_MODULE="$target" \
            G301_FI_FAIL_NTH="$fail_nth" \
            "$harness" "$module_dir" >"$log" 2>&1
    fi
    rc=$?
    set -e
    if [[ "$rc" -ne "$expected_rc" ]]; then
        echo "$name returned $rc, expected $expected_rc" >&2
        cat "$log" >&2
        exit 1
    fi
}

run_case baseline "$module" 0 0 "$output_dir/logs/baseline.log"
direct_count=$(sed -n 's/.* direct_count=\([0-9][0-9]*\) .*/\1/p' \
    "$output_dir/logs/baseline.log" | head -n1)
if [[ "$direct_count" != 5 ]]; then
    echo "expected five direct allocation calls, got ${direct_count:-none}" >&2
    exit 1
fi

printf 'case\tfail_nth\texit\tclassification\tfailure_stage\n' \
    >"$output_dir/CASES.tsv"
printf 'baseline\t0\t0\tBASELINE_VALID\tnone\n' >>"$output_dir/CASES.tsv"
for ((index = 1; index <= direct_count; index++)); do
    log="$output_dir/logs/fail-${index}.log"
    run_case "fail-$index" "$module" "$index" 10 "$log"
    classification=$(sed -n 's/^classification=\([^ ]*\).*/\1/p' "$log")
    stage=$(sed -n 's/.* failure_stage=\([^ ]*\).*/\1/p' "$log")
    if [[ "$classification" != CONTROLLED_FAILURE_NO_OUTPUT ]]; then
        echo "fail-$index was not a no-output controlled failure" >&2
        exit 1
    fi
    printf 'injection\t%s\t10\t%s\t%s\n' \
        "$index" "$classification" "$stage" >>"$output_dir/CASES.tsv"
done

run_case above-range "$module" "$((direct_count + 1))" 21 \
    "$output_dir/logs/above-range.log"
run_case wrong-target /nonexistent/g301.so 1 21 \
    "$output_dir/logs/wrong-target.log"

set +e
LD_LIBRARY_PATH="$library_path" OPENSSL_MODULES="$module_dir" \
    "$harness" "$module_dir" >"$output_dir/logs/no-preload.log" 2>&1
no_preload_rc=$?
set -e
if [[ "$no_preload_rc" -ne 40 ]]; then
    echo "no-preload control returned $no_preload_rc, expected 40" >&2
    exit 1
fi

{
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "openssl_abi_major=$expected_major"
    echo "openssl_prefix=$prefix"
    echo "openssl_libdir=$library_path"
    echo "compiler=$cc_bin"
    echo "valgrind=${valgrind_bin:-BLOCKED}"
    "$prefix/bin/openssl" version -a
    "$cc_bin" --version
    ldd "$module"
    ldd "$harness"
    sha256sum "$module" "$harness" "$interposer" \
        "$source_dir/tests/failure/direct_alloc_harness.c" \
        "$source_dir/tests/failure/direct_alloc_interposer.c" \
        "$script_dir/run-allocation-failure.sh"
} >"$output_dir/ENVIRONMENT.txt" 2>&1

sha256sum "$output_dir"/CASES.tsv "$output_dir"/ENVIRONMENT.txt \
    "$output_dir"/direct_alloc_harness "$output_dir"/direct_alloc_interposer.so \
    "$output_dir"/logs/*.log >"$output_dir/SHA256SUMS.txt"
echo "G301 direct-allocation sweep: PASS (5/5 controlled)"
