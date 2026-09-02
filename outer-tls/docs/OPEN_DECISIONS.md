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
- provider-owned cipher-context record counter; no cipher-owned RNG, nonce,
  KeyUpdate, or TLS framing;
- no QUIC, kTLS, TLS 1.2 legacy surface, pipeline, one-shot, or `dupctx`.

## Open gates

1. Obtain upstream review of the separate provider-ciphersuite patch.
2. Repeat the ABI 3/4 assurance lanes on current security patch releases.
3. Obtain independent review of the combined native TLS lane.
4. Freeze a public name and registered code point only after external review.
5. Decide whether libssl metadata will enforce a limit across cipher-context
   reconstruction with an unchanged write key.

Completed on 2026-08-25: dual-lane EVP/lifecycle/fault/sanitizer/analyzer/
Valgrind matrix; 4,096-case-per-lane independent Mbed TLS differential oracle;
RFC 9846 single-key applicability arithmetic. Details and limits are recorded
in `ASSURANCE_STATUS.md`.

Completed on 2026-08-31: experimental native TLS negotiation against the
separate fork, including exact suite selection, both record directions,
exporter agreement, KeyUpdate, built-in non-regression and absent-provider
rejection.

Completed on 2026-09-01: provider-enforced cipher-context usage limit with
accelerated TLS tests in both directions and across KeyUpdate.

The reserved `inner-threads` layer is not one of these gates and remains out of
scope.
