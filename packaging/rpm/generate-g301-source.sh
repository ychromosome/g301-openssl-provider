#!/bin/sh
set -eu

commit=267a171c9570b4a1f819879a4c881862a25188eb
expected=5504a698ae69128ae5984f74cb2ac1c169fe38be860037edc8657b6aaa80894f
repository=${1:?usage: generate-g301-source.sh G301_GIT_CHECKOUT [OUTPUT]}
output=${2:-g301-openssl-provider-${commit}.tar.gz}

test "$(git -C "$repository" rev-parse "${commit}^{commit}")" = "$commit"
git -C "$repository" archive --format=tar \
    --prefix="g301-openssl-provider-${commit}/" \
    "$commit" outer-tls | gzip -n >"$output"
test "$(sha256sum "$output" | awk '{ print $1 }')" = "$expected"
