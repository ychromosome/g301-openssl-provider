# Local consolidation test report — 2026-08-14

Status: local behavior evidence only. Not a security audit, independent review,
release qualification, or production approval.

## Environment

- Fedora x86_64
- Rust `1.97.1` / Cargo `1.97.1`
- GCC `15.3.1`
- CMake `3.31.11`
- system OpenSSL `3.5.7`
- private OpenSSL `4.1.0-dev`, installed under
  `/tmp/openssl-provider-suite-prefix`, based on pinned upstream commit
  `20da449b76daf8c93fd38cfbfac2a6776217a8f8` plus the uncommitted local generic
  provider-suite patch

All builds were out of tree. No system installation, activation, remote, push,
or network action was performed.

## Inner-thread core

From `/home/martin/Dokumente/ED301/G301`:

```text
cargo fmt --all -- --check                                      PASS
cargo check --locked --offline --workspace --all-targets
  --features test-vectors                                       PASS
cargo clippy --locked --offline --workspace --all-targets
  --features test-vectors -- -D warnings                        PASS
cargo test --locked --offline --workspace
  --features test-vectors                                       PASS (30/30)
cargo test --locked --offline --workspace --release
  --features test-vectors                                       PASS (30/30)
inner-threads/scripts/check-core.sh                             PASS
```

Each test run comprised 12 unit tests, 9 negative tests, 7 session tests, and
2 compile-fail documentation tests. The unit coverage explicitly verifies that
all five channels in both directions occupy all ten indices exactly once and
derive pairwise distinct keys and nonce bases. Session coverage exercises all
four data channels bidirectionally plus authenticated Guard commits. The full
script also completed its Criterion `--test` smoke lane for derivation and all
paired seal/open payload cases.

## Outer provider against system OpenSSL

Build directory: `/tmp/g301-consolidated-outer-system`.

```text
strict GCC configure/build                                      PASS
ctest --output-on-failure                                       PASS (5/5)
```

The five lanes were EVP integration, state machine, dispatch surface,
manifest reconstruction, and TLS capability descriptor inspection. System
OpenSSL does not consume the provider-defined suite for native negotiation.

## Outer provider against the private patched fork

Build directory: `/tmp/g301-consolidated-outer-private`.

```text
strict GCC configure/build with G301_ENABLE_PRIVATE_TLS_E2E=ON  PASS
ctest --output-on-failure                                       PASS (6/6)
```

The additional private-fork E2E lane passed exact G301 suite negotiation,
bidirectional records, exporter, KeyUpdate, provider-absence failure, and the
other assertions encoded in `tests/test_private_tls_e2e.c`.

This private-prefix run is a compatibility checkpoint. The OpenSSL worktree is
still under active uncommitted review, so the root OpenSSL task must reinstall
the final reviewed fork and rerun this E2E before sealing its final evidence.

## Open integration gate

No combined outer-to-inner test was fabricated. The imported inner core still
fetches AES-256-GCM from the process-global OpenSSL context. The TLS exporter
adapter remains NOT STARTED until it can preserve the TLS connection's private
library context and property query with reviewed lifetime and exactly-once
semantics.
