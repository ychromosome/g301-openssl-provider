<!-- SPDX-License-Identifier: Apache-2.0 -->

# Primary sources

- NIST SP 800-38D: AES-GCM construction and limits.
- RFC 5116: AEAD interface terminology.
- RFC 8446 and RFC 9846: TLS 1.3 record processing and key-use limits.
- OpenSSL `provider-cipher(7)`: provider cipher dispatch contract.
- OpenSSL `OSSL_PARAM(3)`: parameter typing and size semantics.
- OpenSSL `OSSL_LIB_CTX(3)`: provider child library contexts.
- OpenSSL `life_cycle-cipher(7)`: cipher context lifecycle.

G301 reuses OpenSSL's maintained AES-256-GCM implementation. These sources do
not standardize G301, its private name, manifest, or private-use code point.
