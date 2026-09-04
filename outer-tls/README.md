<!-- SPDX-License-Identifier: Apache-2.0 -->

# G301 outer OpenSSL provider

Experimental provider for `G301-AES-256-GCM-V1`. Not for production.

The operation is exactly AES-256-GCM with the fixed 32-byte G301 manifest
prepended to caller AAD. AES-256-GCM is fetched from OpenSSL's default provider
through a child library context; no AES, GCM, hash, KDF, or RNG is implemented
here.

The provider also advertises one experimental TLS 1.3 descriptor:

- name and AEAD: `G301-AES-256-GCM-V1`;
- private code point: `0xff30`;
- handshake digest: `SHA2-384`;
- tag length: 16 bytes;
- security bits: 256.

The descriptor has exactly six fields and no private usage-limit metadata.
The provider refuses encryption after 23,680,450 records under one
uninterrupted key installation in a cipher context. Installing a different key
starts a new counter; returning to an earlier key starts another. The supported
libssl path uses one uninterrupted context per write-key epoch. libssl owns
sequence numbers, nonces, KeyUpdate, framing, alerts, and connection close.

Unmodified OpenSSL can load and exercise the EVP cipher and inspect the
descriptor, but cannot negotiate it as a TLS suite. The separate
provider-ciphersuite fork now supplies a passing experimental native TLS lane.
The working identifiers are not IANA registrations.

The compatibility target is OpenSSL ABI major 3 and ABI major 4. The recorded
standalone evidence used OpenSSL 3.5.7 and 4.0.1. The matrix includes
an independent Mbed TLS oracle, lifecycle/concurrency cases,
ASan/UBSan, GCC/Clang analysis, Valgrind, and binary-surface checks. These are
implementation checks, not a production or constant-time proof. See
`docs/ASSURANCE_STATUS.md` and `docs/CONSTANT_TIME_BOUNDARY.md`.

The last standalone pass measured roughly 0.12-0.15 microseconds of fixed
wrapper/API cost per record. A rereview retained those figures only as
historical evidence because the old acceptance package did not fully bind
source to binary and used two non-conservative confidence gates. The corrected
runner requires fresh independent ABI 3 and ABI 4 results. See
`docs/PERFORMANCE_STATUS.md`.

See `docs/G301_DRAFT.md` for the byte contract, `docs/THREAT_MODEL.md` for the
claim boundary, and `BUILDING.md` for local commands. The reserved
`../inner-threads/` component is out of scope.
