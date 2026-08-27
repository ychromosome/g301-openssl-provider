#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$ROOT"
export CCACHE_DISABLE=1

cargo fmt --all -- --check
cargo check --locked
cargo clippy --locked -- -D warnings
cargo clippy --locked --all-targets --features test-vectors -- -D warnings
cargo test --locked --features test-vectors
cargo test --locked --release --features test-vectors
cargo bench --locked --bench core --features test-vectors -- --test
