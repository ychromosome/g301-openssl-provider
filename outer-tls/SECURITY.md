<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security boundary

G301 is an experimental profile-binding wrapper, not a new cipher primitive.
Its only incremental property is fail-closed detection of a one-sided manifest
or dispatch mismatch. The manifest adds no entropy, key bits, cryptographic
strength, replay state, roles, channels, or protection against nonce reuse.

Non-negotiable rules:

1. AES-256-GCM comes only from a maintained OpenSSL provider. No local AES,
   GCM, GHASH, hash, KDF, or RNG implementation is permitted.
2. Encryption and decryption use exactly
   `AES-256-GCM(K, N, manifest || AAD, input)` with a 32-byte key, 12-byte IV,
   and untruncated 16-byte tag.
3. The manifest is injected exactly once before all caller AAD and payload.
   Any inner failure poisons the current operation until a complete successful
   reinitialization.
4. Unauthenticated decryption output is provisional. A caller may act on it
   only after successful final tag verification.
5. Key/nonce uniqueness, TLS directions and epochs, record counting,
   KeyUpdate, and connection termination belong to libssl. The provider
   advertises no private usage-limit parameter.
6. The outer name never aliases `AES-256-GCM` or
   `TLS_AES_256_GCM_SHA384`. The wrapper advertises `fips=no`; use of an
   OpenSSL primitive does not make the wrapper FIPS validated.
7. TLS 1.2 legacy controls, multiblock, pipeline, QUIC, kTLS, one-shot cipher,
   and context duplication are outside the current dispatch surface and must
   fail or remain unavailable.
8. Provider `size_t` lengths are checked before the classic EVP `int` bridge.
   Tag retrieval copies exactly 16 bytes only after a successful private inner
   fetch reports exactly 16 bytes.
9. The working name and code point are private test identifiers. No
   production, standards, interoperability, audit, or security claim follows
   from passing tests.

The detailed assets, attacker model, non-claims, and gates are in
`docs/THREAT_MODEL.md` and `docs/OPEN_DECISIONS.md`.
