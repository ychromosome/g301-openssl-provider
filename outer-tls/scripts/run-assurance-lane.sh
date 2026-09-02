#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu
export CCACHE_DISABLE=1

if [ "$#" -ne 3 ]; then
    echo "usage: $0 OPENSSL_PREFIX EXPECTED_MAJOR FRESH_WORK_DIR" >&2
    exit 2
fi

prefix=$1
expected_major=$2
work_dir=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
. "$script_dir/common.sh"
library_path=$(g301_find_openssl_libdir "$prefix")
clang_bin=${CLANG:-$(command -v clang || true)}
gcc_bin=${GCC_ANALYZER_CC:-$(command -v gcc || true)}
scan_build_bin=${SCAN_BUILD:-$(command -v scan-build || true)}
ccc_analyzer_bin=${CCC_ANALYZER:-$(command -v ccc-analyzer || true)}
valgrind_bin=${VALGRIND:-$(command -v valgrind || true)}
sanitizer_runtime_dir=
blocked=0

if [ -z "$ccc_analyzer_bin" ] && [ -x /usr/libexec/ccc-analyzer ]; then
    ccc_analyzer_bin=/usr/libexec/ccc-analyzer
fi
if [ -z "$ccc_analyzer_bin" ]; then
    for llvm_config in /usr/bin/llvm-config /usr/bin/llvm-config-*; do
        if [ -x "$llvm_config" ]; then
            llvm_libdir=$($llvm_config --libdir 2>/dev/null || true)
            candidate=$(dirname -- "$llvm_libdir")/libexec/ccc-analyzer
            if [ -x "$candidate" ]; then
                ccc_analyzer_bin=$candidate
                break
            fi
        fi
    done
fi

if [ -e "$work_dir" ]; then
    echo "work directory must not exist: $work_dir" >&2
    exit 2
fi
mkdir -p "$work_dir"

    "$script_dir/run-provider-lane.sh" \
    "$prefix" "$work_dir/release" "$expected_major"

if [ -n "$clang_bin" ] && [ -x "$clang_bin" ]; then
    sanitizer_runtime_dir=$("$clang_bin" --print-runtime-dir)
    if [ ! -d "$sanitizer_runtime_dir" ] \
            || ! find "$sanitizer_runtime_dir" -maxdepth 1 -type f \
                -name 'libclang_rt.asan*.so' -print -quit | grep -q .; then
        echo "BLOCKED: Clang shared ASan runtime unavailable in compiler runtime directory" >&2
        exit 77
    fi
    cmake -S "$source_dir" -B "$work_dir/sanitizers" \
        -DBUILD_TESTING=ON \
        -DG301_ENABLE_MBEDTLS_ORACLE=ON \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_COMPILER="$clang_bin" \
        -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -shared-libsan' \
        -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address,undefined -shared-libsan' \
        -DCMAKE_MODULE_LINKER_FLAGS='-fsanitize=address,undefined -shared-libsan' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined -shared-libsan' \
        -DOPENSSL_ROOT_DIR="$prefix" \
        -DOPENSSL_USE_STATIC_LIBS=FALSE
    cmake --build "$work_dir/sanitizers" --parallel
    ASAN_OPTIONS='detect_leaks=0:halt_on_error=1' \
    UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
    LD_LIBRARY_PATH="$sanitizer_runtime_dir:$library_path" \
        ctest --test-dir "$work_dir/sanitizers" \
            --output-on-failure --no-tests=error
else
    echo "BLOCKED: ASan/UBSan (clang unavailable)" >&2
    blocked=1
fi

if [ -n "$gcc_bin" ] && [ -x "$gcc_bin" ]; then
    cmake -S "$source_dir" -B "$work_dir/gcc-analyzer" \
        -DBUILD_TESTING=ON \
        -DG301_ENABLE_MBEDTLS_ORACLE=ON \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER="$gcc_bin" \
        -DCMAKE_C_FLAGS='-fanalyzer' \
        -DOPENSSL_ROOT_DIR="$prefix" \
        -DOPENSSL_USE_STATIC_LIBS=FALSE
    cmake --build "$work_dir/gcc-analyzer" --parallel
else
    echo "BLOCKED: GCC analyzer (gcc unavailable)" >&2
    blocked=1
fi

if [ -n "$scan_build_bin" ] && [ -x "$scan_build_bin" ] \
        && [ -n "$ccc_analyzer_bin" ] && [ -x "$ccc_analyzer_bin" ]; then
    CCACHE_DISABLE=1 cmake -S "$source_dir" -B "$work_dir/clang-analyzer" \
        -DBUILD_TESTING=ON \
        -DG301_ENABLE_MBEDTLS_ORACLE=ON \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER="$ccc_analyzer_bin" \
        -DOPENSSL_ROOT_DIR="$prefix" \
        -DOPENSSL_USE_STATIC_LIBS=FALSE
    CCACHE_DISABLE=1 "$scan_build_bin" --status-bugs \
        -o "$work_dir/clang-analyzer-reports" \
        cmake --build "$work_dir/clang-analyzer" --parallel
else
    echo "BLOCKED: Clang analyzer (scan-build/ccc-analyzer unavailable)" >&2
    blocked=1
fi

run_valgrind()
{
    binary=$1
    shift
    OPENSSL_MODULES="$work_dir/release" LD_LIBRARY_PATH="$library_path" \
        "$valgrind_bin" --error-exitcode=99 --leak-check=full \
            --show-leak-kinds=definite,indirect,possible \
            --errors-for-leak-kinds=definite,indirect,possible \
            "$work_dir/release/$binary" "$@"
}

if [ -n "$valgrind_bin" ] && [ -x "$valgrind_bin" ]; then
    run_valgrind g301_integration_test "$work_dir/release"
    run_valgrind g301_state_machine_test
    run_valgrind g301_manifest_test
    run_valgrind g301_param_policy_test "$work_dir/release"
    run_valgrind g301_capability_test "$work_dir/release"
    run_valgrind g301_mbedtls_oracle_test "$work_dir/release"
else
    echo "BLOCKED: Valgrind (tool unavailable)" >&2
    blocked=1
fi

"$script_dir/run-allocation-failure.sh" "$prefix" "$expected_major" \
    "$work_dir/release" "$work_dir/allocation-failure"

if [ "$blocked" -ne 0 ]; then
    echo "G301 assurance ABI $expected_major: BLOCKED (see individual gates)" >&2
    exit 77
fi
echo "G301 assurance ABI $expected_major: PASS"
