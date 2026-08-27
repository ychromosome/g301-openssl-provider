#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ROOT"
export CCACHE_DISABLE=1

date --utc --iso-8601=seconds
uname -a
lscpu
rustc -Vv
cargo -V
openssl version -a
sha256sum Cargo.lock

printf '%s\n' 'Indicative OpenSSL hardware ceiling; not a G301-overhead baseline:'
openssl speed -seconds 3 -evp aes-256-gcm -aead
printf '%s\n' 'Paired in-process EVP and G301 Criterion measurements:'
cargo bench --locked --bench core --features test-vectors -- --noplot
