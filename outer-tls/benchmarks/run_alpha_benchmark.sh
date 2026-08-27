#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export CCACHE_DISABLE=1

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 PROVIDER_MODULE_DIRECTORY [OUTPUT_DIRECTORY]" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_dir=$(realpath "$script_dir/..")
source "$source_dir/scripts/common.sh"
provider_dir=$(realpath "$1")
output_dir=${2:-"$script_dir/results/$(date -u +%Y%m%dT%H%M%SZ)"}
samples=${G301_BENCH_SAMPLES:-48}
bench_cpu=${G301_BENCH_CPU:-2}
disabled_caps='~0x200000200000000:~0x60000000000:~0x0:~0x0:~0x0'
cc_bin=${CC:-$(command -v gcc || command -v cc)}

if [[ -e "$output_dir" ]]; then
    echo "output path already exists: $output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"
output_dir=$(realpath "$output_dir")

if [[ ! -f "$provider_dir/g301.so" ]]; then
    echo "g301.so not found in $provider_dir" >&2
    exit 1
fi

compile_flags=(
    -std=c11 -O3 -DNDEBUG
    -Wall -Wextra -Wpedantic -Werror
    -Wcast-qual -Wconversion -Wformat=2 -Wshadow
    -Wstrict-prototypes -Wundef
    -fstack-protector-strong
)
openssl_prefix=${OPENSSL_PREFIX:-}
if [[ -n "$openssl_prefix" ]]; then
    openssl_prefix=$(realpath "$openssl_prefix")
    openssl_libdir=$(g301_find_openssl_libdir "$openssl_prefix")
    openssl_bin="$openssl_prefix/bin/openssl"
    openssl_cflags=("-I$openssl_prefix/include")
    openssl_libs=("-L$openssl_libdir" "-Wl,-rpath,$openssl_libdir" -lcrypto)
else
    openssl_bin=$(command -v openssl)
    read -r -a openssl_cflags <<<"$(pkg-config --cflags libcrypto)"
    read -r -a openssl_libs <<<"$(pkg-config --libs libcrypto)"
fi

if [[ ! -x "$openssl_bin" ]]; then
    echo "OpenSSL executable not found: $openssl_bin" >&2
    exit 1
fi

"$cc_bin" "${compile_flags[@]}" "${openssl_cflags[@]}" \
    "$script_dir/g301_alpha_benchmark.c" \
    -o "$output_dir/g301_alpha_benchmark" "${openssl_libs[@]}"

benchmark_libcrypto=$(ldd "$output_dir/g301_alpha_benchmark" \
    | awk '$1 ~ /^libcrypto\.so/ { print $3; exit }')
provider_libcrypto=$(ldd "$provider_dir/g301.so" \
    | awk '$1 ~ /^libcrypto\.so/ { print $3; exit }')
if [[ -z "$benchmark_libcrypto" || -z "$provider_libcrypto" \
    || ! -f "$benchmark_libcrypto" || ! -f "$provider_libcrypto" \
    || "$(realpath "$benchmark_libcrypto")" != "$(realpath "$provider_libcrypto")" ]]; then
    echo "benchmark and provider do not resolve to the same libcrypto" >&2
    exit 1
fi

file_hash() {
    sha256sum "$1" | awk '{ print $1 }'
}

{
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "samples=$samples"
    echo "bench_cpu=$bench_cpu"
    echo "openssl_lane=$([[ -n "$openssl_prefix" ]] && echo external || echo system)"
    echo "disabled_caps=$disabled_caps"
    echo "compile_flags=${compile_flags[*]}"
    echo "openssl_linkage=dynamic libcrypto from recorded lane hash"
    echo "provider_module_sha256=$(file_hash "$provider_dir/g301.so")"
    echo "benchmark_sha256=$(file_hash "$output_dir/g301_alpha_benchmark")"
    echo "libcrypto_sha256=$(file_hash "$benchmark_libcrypto")"
    echo "compiler_sha256=$(file_hash "$cc_bin")"
    echo "source_manifest_sha256=$(file_hash "$source_dir/SOURCE_MANIFEST.sha256")"
    uname -a
    "$cc_bin" --version
    cmake --version
    if [[ -z "$openssl_prefix" ]]; then
        pkg-config --modversion libcrypto
    fi
    sed -n '1,12p' /etc/os-release
    if command -v rpm >/dev/null 2>&1; then
        rpm -q openssl openssl-libs openssl-devel || true
    fi
    "$openssl_bin" version
    "$openssl_bin" info -cpusettings
    env OPENSSL_ia32cap="$disabled_caps" "$openssl_bin" info -cpusettings
    lscpu
    echo "loadavg=$(< /proc/loadavg)"
    if [[ -r "/sys/devices/system/cpu/cpu$bench_cpu/cpufreq/scaling_governor" ]]; then
        echo "scaling_governor=$(< "/sys/devices/system/cpu/cpu$bench_cpu/cpufreq/scaling_governor")"
    fi
    if [[ -r "/sys/devices/system/cpu/cpu$bench_cpu/cpufreq/scaling_driver" ]]; then
        echo "scaling_driver=$(< "/sys/devices/system/cpu/cpu$bench_cpu/cpufreq/scaling_driver")"
    fi
    taskset -pc "$$"
} >"$output_dir/environment.txt" 2>&1

env -u OPENSSL_ia32cap OPENSSL_MODULES="$provider_dir" \
    taskset -c "$bench_cpu" "$output_dir/g301_alpha_benchmark" \
    native "$samples" >"$output_dir/raw_native.csv"

env OPENSSL_ia32cap="$disabled_caps" OPENSSL_MODULES="$provider_dir" \
    taskset -c "$bench_cpu" "$output_dir/g301_alpha_benchmark" \
    aes_accel_masked "$samples" >"$output_dir/raw_aes_accel_masked.csv"

python3 "$script_dir/analyze_alpha_results.py" \
    "$output_dir/raw_native.csv" "$output_dir/raw_aes_accel_masked.csv" \
    --summary "$output_dir/summary.csv" \
    --comparisons "$output_dir/comparisons.csv" \
    --validation "$output_dir/VALIDATION.txt"

(cd "$output_dir" && find . -maxdepth 1 -type f ! -name SHA256SUMS.txt \
    -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS.txt)
echo "$output_dir"
