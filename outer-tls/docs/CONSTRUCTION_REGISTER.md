<!-- SPDX-License-Identifier: Apache-2.0 -->

# Construction register

Date: 2026-08-25

| Component | Source | Build/buy decision | Local code |
|---|---|---|---|
| AES-256-GCM | NIST SP 800-38D; OpenSSL default provider | BUY | fetched as `AES-256-GCM`, `provider=default` |
| Provider cipher contract | OpenSSL `provider-cipher(7)` | USE STANDARD API | dispatch and state adapter only |
| Provider child context | OpenSSL `OSSL_LIB_CTX_new_child()` | USE STANDARD API | one child context per provider instance |
| TLS record key/IV/AAD | RFC 9846 Sections 5.2-5.4 | DELEGATE TO LIBSSL | none |
| TLS handshake digest | RFC 9846 suite model | USE SHA2-384 | descriptor metadata only |
| Fixed AAD prefix | G301 experimental profile | EIGENBAU | immutable 32-byte constant, injected once |
| Manifest encoding | G301 experimental profile | EIGENBAU | fixed-width table, no runtime parser |
| TLS descriptor | OpenSSL #23093 design candidate | EXPERIMENTAL GLUE | six metadata fields; no record policy |
| Random generation | OpenSSL/libssl owner | NOT USED BY CIPHER | none |
| Record usage limit | RFC 9846 Section 5.5 | PARTIAL | cipher-context counter; 23,680,450 encrypted records; fresh same-key contexts are not linked |

The two local construction choices exist only to bind the fixed public profile
to each AEAD invocation and to expose that operation through EVP. Neither
reimplements a primitive. Their acceptance gates are byte-exact differential
tests against ordinary AES-256-GCM with `M || A`, state-machine fault tests,
dual OpenSSL lanes, sanitizer/Valgrind runs, and independent review.

Primary references:

- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://www.rfc-editor.org/rfc/rfc9846
- https://docs.openssl.org/3.5/man7/provider-cipher/
- https://docs.openssl.org/3.5/man3/OSSL_LIB_CTX/
