#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export CCACHE_DISABLE=1

if [[ $# -ne 5 ]]; then
    echo "usage: $0 OPENSSL_PREFIX BASELINE_SOURCE CANDIDATE_SOURCE EXPECTED_MAJOR OUTPUT_DIR" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/../scripts/common.sh"
prefix=$(realpath "$1")
baseline_source=$(realpath "$2")
candidate_source=$(realpath "$3")
expected_major=$4
output_dir=$5
pairs=${G301_ABBA_PAIRS:-8}
samples=${G301_ABBA_SAMPLES:-8}
bench_cpu=${G301_BENCH_CPU:-2}
disabled_caps='~0x200000200000000:~0x60000000000:~0x0:~0x0:~0x0'
cc_bin=${CC:-$(command -v gcc || command -v cc)}

if [[ -e "$output_dir" ]]; then
    echo "output path already exists: $output_dir" >&2
    exit 1
fi
if (( pairs < 8 || samples < 8 || samples % 4 != 0 )); then
    echo "need at least 8 pairs and a sample count divisible by 4" >&2
    exit 1
fi
for source_dir in "$baseline_source" "$candidate_source"; do
    test -f "$source_dir/SOURCE_MANIFEST.sha256"
done
libdir=$(g301_find_openssl_libdir "$prefix")
test -x "$prefix/bin/openssl"
g301_check_openssl_major "$prefix/bin/openssl" "$libdir" "$expected_major"
openssl_version=$(LD_LIBRARY_PATH="$libdir" "$prefix/bin/openssl" version \
    | awk '{print $2}')

mkdir -p "$output_dir/raw" "$output_dir/modules" "$output_dir/source"
output_dir=$(realpath "$output_dir")
build_work=$(mktemp -d "${TMPDIR:-/tmp}/g301-abba-build.XXXXXX")
trap 'rm -rf "$build_work"' EXIT

copy_source_snapshot()
{
    local source_root=$1 destination=$2 list_file=$3 path

    (cd "$source_root" && sha256sum --quiet -c SOURCE_MANIFEST.sha256)
    {
        printf '%s\n' './SOURCE_MANIFEST.sha256'
        awk '{ print $2 }' "$source_root/SOURCE_MANIFEST.sha256"
    } >"$list_file"
    while IFS= read -r path; do
        case "$path" in
            ./*) ;;
            *)
                echo "unsafe source-manifest path: $path" >&2
                exit 1
                ;;
        esac
        if [[ "$path" == *'/../'* || "$path" == '../'* \
            || -L "$source_root/$path" || ! -f "$source_root/$path" ]]; then
            echo "unsafe or missing source-manifest entry: $path" >&2
            exit 1
        fi
    done <"$list_file"
    mkdir -p "$destination"
    (cd "$source_root" && tar -cf - -T "$list_file") \
        | (cd "$destination" && tar -xf -)
    (cd "$destination" && sha256sum --quiet -c SOURCE_MANIFEST.sha256)
}

copy_source_snapshot "$baseline_source" "$output_dir/source/baseline" \
    "$build_work/baseline-files.txt"
copy_source_snapshot "$candidate_source" "$output_dir/source/candidate" \
    "$build_work/candidate-files.txt"

build_module()
{
    local variant=$1 source_root="$output_dir/source/$1"
    local build_root="$build_work/$1" module_dir="$output_dir/modules/$1"

    cmake -S "$source_root" -B "$build_root" \
        -DBUILD_TESTING=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER="$cc_bin" \
        -DOPENSSL_ROOT_DIR="$prefix" \
        -DOPENSSL_USE_STATIC_LIBS=FALSE
    cmake --build "$build_root" --parallel --target g301
    mkdir -p "$module_dir"
    cp "$build_root/g301.so" "$module_dir/g301.so"
    "$script_dir/../scripts/check-provider-surface.sh" \
        "$module_dir/g301.so" "$prefix" "$expected_major"
}

build_module baseline
build_module candidate

baseline_dir="$output_dir/modules/baseline"
candidate_dir="$output_dir/modules/candidate"
binary="$output_dir/g301_alpha_benchmark"

"$cc_bin" -std=c11 -O3 -DNDEBUG \
    -Wall -Wextra -Wpedantic -Werror -Wcast-qual -Wconversion \
    -Wformat=2 -Wshadow -Wstrict-prototypes -Wundef \
    -fstack-protector-strong -I"$prefix/include" \
    "$script_dir/g301_alpha_benchmark.c" -o "$binary" \
    -L"$libdir" -Wl,-rpath,"$libdir" -lcrypto

binary_libcrypto=$(ldd "$binary" | awk '$1 ~ /^libcrypto\.so/ {print $3; exit}')
baseline_libcrypto=$(ldd "$baseline_dir/g301.so" | awk '$1 ~ /^libcrypto\.so/ {print $3; exit}')
candidate_libcrypto=$(ldd "$candidate_dir/g301.so" | awk '$1 ~ /^libcrypto\.so/ {print $3; exit}')
if [[ -z "$binary_libcrypto" || -z "$baseline_libcrypto" \
    || -z "$candidate_libcrypto" \
    || "$(realpath "$binary_libcrypto")" != "$(realpath "$baseline_libcrypto")" \
    || "$(realpath "$binary_libcrypto")" != "$(realpath "$candidate_libcrypto")" ]]; then
    echo "binary and modules resolve to different libcrypto objects" >&2
    exit 1
fi

file_hash()
{
    sha256sum "$1" | awk '{ print $1 }'
}

baseline_module_hash=$(file_hash "$baseline_dir/g301.so")
candidate_module_hash=$(file_hash "$candidate_dir/g301.so")
baseline_manifest_hash=$(file_hash \
    "$output_dir/source/baseline/SOURCE_MANIFEST.sha256")
candidate_manifest_hash=$(file_hash \
    "$output_dir/source/candidate/SOURCE_MANIFEST.sha256")
libcrypto_hash=$(file_hash "$binary_libcrypto")
benchmark_hash=$(file_hash "$binary")
compiler_hash=$(file_hash "$cc_bin")

printf '%s\n' \
    'cmake -S source/baseline -B build/baseline -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=<CC> -DOPENSSL_ROOT_DIR=<OPENSSL_PREFIX> -DOPENSSL_USE_STATIC_LIBS=FALSE' \
    'cmake --build build/baseline --parallel --target g301' \
    'cmake -S source/candidate -B build/candidate -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=<CC> -DOPENSSL_ROOT_DIR=<OPENSSL_PREFIX> -DOPENSSL_USE_STATIC_LIBS=FALSE' \
    'cmake --build build/candidate --parallel --target g301' \
    '<CC> -std=c11 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -Wcast-qual -Wconversion -Wformat=2 -Wshadow -Wstrict-prototypes -Wundef -fstack-protector-strong -I<OPENSSL_PREFIX>/include benchmarks/g301_alpha_benchmark.c -o g301_alpha_benchmark -L<OPENSSL_LIBDIR> -Wl,-rpath,<OPENSSL_LIBDIR> -lcrypto' \
    >"$output_dir/BUILD_COMMANDS.txt"

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    lane pair slot variant cpu_mode sequence csv \
    baseline_module_sha256 candidate_module_sha256 \
    baseline_source_manifest_sha256 candidate_source_manifest_sha256 \
    libcrypto_sha256 benchmark_sha256 compiler_sha256 >"$output_dir/RUNS.tsv"

run_one()
{
    local pair=$1 slot=$2 variant=$3 cpu_mode=$4 sequence=$5
    local module_dir output_relative output

    module_dir="$output_dir/modules/$variant"
    output_relative="raw/${cpu_mode}_pair$(printf '%02d' "$pair")_slot${slot}_${variant}.csv"
    output="$output_dir/$output_relative"
    if [[ "$cpu_mode" == native ]]; then
        env -u OPENSSL_ia32cap OPENSSL_MODULES="$module_dir" \
            LD_LIBRARY_PATH="$libdir" taskset -c "$bench_cpu" \
            "$binary" "$cpu_mode" "$samples" >"$output"
    else
        env OPENSSL_ia32cap="$disabled_caps" OPENSSL_MODULES="$module_dir" \
            LD_LIBRARY_PATH="$libdir" taskset -c "$bench_cpu" \
            "$binary" "$cpu_mode" "$samples" >"$output"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$openssl_version" "$pair" "$slot" "$variant" "$cpu_mode" \
        "$sequence" "$output_relative" "$baseline_module_hash" \
        "$candidate_module_hash" "$baseline_manifest_hash" \
        "$candidate_manifest_hash" "$libcrypto_hash" "$benchmark_hash" \
        "$compiler_hash" \
        >>"$output_dir/RUNS.tsv"
}

for cpu_mode in native aes_accel_masked; do
    for ((pair = 0; pair < pairs; pair++)); do
        if (( pair % 2 == 0 )); then
            order=(baseline candidate candidate baseline)
            sequence=ABBA
        else
            order=(candidate baseline baseline candidate)
            sequence=BAAB
        fi
        for slot in 0 1 2 3; do
            run_one "$pair" "$slot" "${order[$slot]}" "$cpu_mode" "$sequence"
        done
    done
done

{
    echo "openssl_abi_major=$expected_major"
    echo "openssl_version=$openssl_version"
    echo "pairs=$pairs"
    echo "samples_per_process=$samples"
    echo "cpu=$bench_cpu"
    echo "sequence=ABBA/BAAB alternating"
    echo "baseline_module_sha256=$baseline_module_hash"
    echo "candidate_module_sha256=$candidate_module_hash"
    echo "baseline_source_manifest_sha256=$baseline_manifest_hash"
    echo "candidate_source_manifest_sha256=$candidate_manifest_hash"
    echo "libcrypto_sha256=$libcrypto_hash"
    echo "benchmark_sha256=$benchmark_hash"
    echo "compiler_sha256=$compiler_hash"
    "$cc_bin" --version | sed -n '1p'
    cmake --version | sed -n '1p'
    uname -a
    lscpu
} >"$output_dir/ENVIRONMENT.txt"

analysis_status=0
python3 "$script_dir/analyze_candidate_abba.py" \
    "$output_dir/RUNS.tsv" "$output_dir" || analysis_status=$?
(cd "$output_dir" && find . -type f ! -name SHA256SUMS.txt -print0 \
    | sort -z | xargs -0 sha256sum >SHA256SUMS.txt)
echo "$output_dir"
exit "$analysis_status"
