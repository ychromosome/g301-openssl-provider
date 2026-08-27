<!-- SPDX-License-Identifier: Apache-2.0 -->

# Test-vector provenance

The two frozen KATs in `tests/test_integration.c` use:

```text
AES-256-GCM(K, N, manifest || caller_AAD, plaintext)
```

They were generated independently with Python `cryptography` 46.0.7 backed by
OpenSSL 3.5.7 and with libgcrypt 1.11.1. The provider matrix additionally
recomputes the same construction with Mbed TLS; it does not learn expected
bytes from G301 output.

For each KAT, the zero-manifest and double-manifest tags are frozen negative
controls. The ciphertext body remains equal because GCM AAD changes only the
authentication computation. Reusing the public KAT key/nonce is test-only and
is forbidden in operation.

The authoritative byte values are kept beside the executable assertions in
`tests/test_integration.c`. Any change requires independent regeneration and a
new profile version; observed provider output is never an oracle.
