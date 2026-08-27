<!-- SPDX-License-Identifier: Apache-2.0 -->

# Open decisions and gates

Date: 2026-08-25

## Settled for the experimental V1 candidate

- construction: AES-256-GCM over `manifest || caller_AAD`;
- exact 32-byte manifest and 16-byte tag;
- OpenSSL default-provider delegation through a child library context;
- one EVP cipher identity, no ordinary AES alias;
- six-field experimental TLS descriptor;
- no private provider usage-limit field;
- no cipher-owned RNG, record counter, nonce, KeyUpdate, or TLS framing;
- no QUIC, kTLS, TLS 1.2 legacy surface, pipeline, one-shot, or `dupctx`.

## Open gates

1. Build and review the separate minimal OpenSSL provider-ciphersuite patch.
2. Add generic libssl record-usage enforcement with built-in-suite regression
   tests; do not hide it in G301 metadata.
3. Run a fresh TLS 1.3 matrix: both directions, KeyUpdate, failure without the
   provider, built-in suite non-regression, resumption policy, and offload
   exclusion.
4. Measure wrapper overhead now that the standalone assurance matrix is green.
5. Obtain independent security and performance reviews of a sealed source and
   evidence bundle.
6. Freeze a public name and registered code point only after external review.

Completed on 2026-08-25: dual-lane EVP/lifecycle/fault/sanitizer/analyzer/
Valgrind matrix; 4,096-case-per-lane independent Mbed TLS differential oracle;
RFC 9846 single-key applicability arithmetic. Details and limits are recorded
in `ASSURANCE_STATUS.md`.

The reserved `inner-threads` layer is not one of these gates and remains out of
scope.
