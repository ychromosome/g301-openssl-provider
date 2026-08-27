# Working rules for the consolidated G301 repository

These rules apply to this repository and all descendants.

## Status and claims

- The repository is experimental, not security-audited, not release ready,
  not a standard, not FIPS validated, and not approved for production.
- A successful local test proves only the tested behavior on the recorded
  environment. It is not a security proof or an independent audit.
- `G301-AES-256-GCM-V1` and code point `0xff30` are private Alpha/Beta working
  identifiers. A public name and code point are not frozen.

## Cryptographic boundaries

- Do not implement AES, GCM, SHA-384, HKDF, or random generation locally.
- The values 301, 99, 372, 175, and 947 are public domain identifiers, never
  entropy, secrets, or independent security strength.
- Preserve domain separation, canonical framing, nonce uniqueness, strict
  input limits, fail-closed behavior, and key erasure.
- `outer-tls/` contains only the provider AEAD and its TLS capability metadata.
- `inner-threads/` contains the separate post-handshake session layer with
  five channels in two directions. Do not fold it into the TLS AEAD.
- A TLS adapter may initialize the inner layer only after a completed native
  G301 TLS 1.3 handshake, from one exactly-once 48-byte TLS exporter. It must
  retain the connection's private OpenSSL library context and property query.
  No adapter may fetch cryptography through the process-global default context.

## Licensing boundary

- `outer-tls/` is Apache-2.0.
- `inner-threads/` is provisionally all rights reserved under
  `LicenseRef-G301-Inner-Reserved` pending legal review.
- There is no repository-wide default license. Do not move or copy files across
  the boundary without preserving and reviewing their file-level license.
- Do not add narrative manuscripts, plot, characters, world-building, or other
  lore text to this technical repository.

## External actions

No remote, publication, push, pull request, issue, message, system OpenSSL
installation, provider activation, or global crypto-policy change without a
separate explicit authorization.

## OpenSSL implementation rules

- Treat the checked-out OpenSSL `CONTRIBUTING.md`, `STYLE.md`,
  `.clang-format`, `test/README.md`, the applicable
  `doc/man7/provider*.pod`, and `doc/man7/ossl-guide-migration.pod` as
  binding inputs.
- Use current Provider dispatches and public `EVP_*` APIs, Core allocator
  and error upcalls, terminated `OSSL_PARAM` arrays, and explicit ownership
  across C/Rust FFI.
- Distinguish operational errors from valid negative results.  Preserve
  constant-time secret handling and cleanse secret storage on every exit.
