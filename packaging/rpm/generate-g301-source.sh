#!/bin/sh
set -eu

commit=07da4c847e8d0fbd287159809ff1b21d21996239
expected=18f24b523cd300344f5e19752d06651f66d28c0b780a7f8c484dad02c1d2d75b
repository=${1:?usage: generate-g301-source.sh G301_GIT_CHECKOUT [OUTPUT]}
output=${2:-g301-openssl-provider-${commit}.tar.gz}

test "$(git -C "$repository" rev-parse "${commit}^{commit}")" = "$commit"
git -C "$repository" archive --format=tar \
    --prefix="g301-openssl-provider-${commit}/" \
    "$commit" outer-tls | gzip -n >"$output"
test "$(sha256sum "$output" | awk '{ print $1 }')" = "$expected"
