#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 OPENSSL_ABI3_PREFIX OPENSSL_ABI4_PREFIX FRESH_WORK_DIR" >&2
    exit 2
fi

prefix_35=$1
prefix_40=$2
work_dir=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -e "$work_dir" ]; then
    echo "work directory must not exist: $work_dir" >&2
    exit 2
fi
mkdir -p "$work_dir"

"$script_dir/run-provider-lane.sh" \
    "$prefix_35" "$work_dir/openssl-abi3" 3
"$script_dir/run-provider-lane.sh" \
    "$prefix_40" "$work_dir/openssl-abi4" 4

echo "G301 ABI 3/4 dual-lane matrix: PASS"
