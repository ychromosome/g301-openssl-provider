<!-- SPDX-License-Identifier: Apache-2.0 -->

# G301-AES-256-GCM-V1 experimental byte contract

Status: experimental implementation contract; not a standard or deployment
profile.

## Construction

Let `M` be the fixed manifest below. G301 is defined by:

```text
Encrypt(K, N, A, P) = AES-256-GCM.Encrypt(K, N, M || A, P)
Decrypt(K, N, A, C) = AES-256-GCM.Decrypt(K, N, M || A, C)
```

The underlying operation is AES-256-GCM as specified by NIST SP 800-38D. The
provider delegates it to OpenSSL's default provider through the documented
provider CIPHER and EVP interfaces. The manifest is implicit, fixed, and not
sent on the wire.

| Parameter | Value |
|---|---:|
| Key | 32 bytes |
| IV/nonce | 12 bytes |
| Tag | 16 bytes, no truncation |
| Manifest | 32 bytes |
| Ciphertext expansion | 16 bytes |
| TLS handshake digest | SHA2-384 |

## Manifest

| Offset | Length | Value |
|---:|---:|---|
| 0 | 15 | ASCII `G301-TLS13-AEAD` |
| 15 | 1 | version `0x01` |
| 16 | 1 | DATA-entry count `0x04` |
| 17 | 3 | type `0x01`, `u16be(301)` |
| 20 | 3 | type `0x01`, `u16be(99)` |
| 23 | 3 | type `0x01`, `u16be(372)` |
| 26 | 3 | type `0x01`, `u16be(175)` |
| 29 | 3 | type `0x02`, `u16be(947)` |

The count at offset 16 covers only the four consecutive type-`0x01` DATA
entries. V1 then requires exactly one uncounted type-`0x02` CONTROL trailer,
`u16be(947)`, at offset 29. It is a fixed encoding, not a generic TLV stream.

```text
hex:
473330312d544c5331332d41454144010401012d0100630101740100af0203b3

SHA-256:
08ab7ab17f4731f9bc744c3e9e6eebc5eb20a8feddd6654b9d8c139a11165c4c
```

The values are public identifiers. They are not secrets, entropy, independent
keys, or independent cryptographic domains. V1 is a fixed encoding, not an
extensible parser format.

## EVP state contract

The outer context has four record phases:

```text
NO_RECORD -> MANIFEST_PENDING -> ACTIVE -> FINALIZED
```

A successful key/IV initialization enters `MANIFEST_PENDING`. The first
non-empty AAD or payload update, or final on an otherwise empty record, injects
`M` once and enters `ACTIVE`. AAD after payload is rejected. Final can run once.
Decryption final requires a fresh exact 16-byte tag for the current record.
Inner operational failures poison the context until complete reinitialization.

## Experimental TLS descriptor

Capability name: `TLS-CIPHERSUITE-V1`. The descriptor contains exactly:

| Field | Value |
|---|---|
| name | `G301-AES-256-GCM-V1` |
| code point | `0xff30` |
| AEAD name | `G301-AES-256-GCM-V1` |
| digest name | `SHA2-384` |
| tag length | `16` |
| security bits | `256` |

The descriptor is a candidate for the separate OpenSSL provider-ciphersuite
work. It is not part of upstream OpenSSL and the code point is private-use.
There is no per-suite record counter or usage-limit field.

For TLS 1.3, RFC 9846 owns the record header AAD, nonce construction, traffic
keys, directions, epochs, KeyUpdate, and key-usage limit. G301 changes only the
AEAD AAD from `A` to `M || A`; it does not change ciphertext or tag lengths.

## Claim boundary

If one endpoint injects the specified `M` and the peer omits, duplicates, or
changes it under the same apparent suite identity, authentication fails except
with the ordinary AES-GCM forgery probability. This is the sole incremental
claim. Bilateral misuse, endpoint compromise, nonce reuse, and application
policy are not addressed.
