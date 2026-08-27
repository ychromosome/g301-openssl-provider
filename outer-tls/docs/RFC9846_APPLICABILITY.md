<!-- SPDX-License-Identifier: Apache-2.0 -->

# RFC 9846 AES-GCM usage applicability

Status: arithmetic gate completed for the proposed conservative `2^24`
generic libssl cap; final TLS integration remains blocked on implementation
and review of that generic enforcement.

RFC 9846 Section 5.5 requires KeyUpdate or connection close before the
applicable AEAD usage limit. It states that up to `2^24.5` full-size AES-GCM
records retain an approximate `2^-57` authenticated-encryption margin.

G301 adds 32 fixed AAD bytes but does not change key, nonce, plaintext, tag, or
record sizes. At maximum TLS 1.3 plaintext size:

```text
TLSInnerPlaintext bytes                     = 16385
plaintext GHASH blocks                      = ceil(16385 / 16) = 1025
ordinary TLS record-header AAD bytes        = 5
ordinary AAD GHASH blocks                   = ceil(5 / 16) = 1
G301 manifest || TLS AAD bytes              = 32 + 5 = 37
G301 AAD GHASH blocks                       = ceil(37 / 16) = 3
ordinary L / L+1                            = 1026 / 1027
G301 L / L+1                                = 1028 / 1029
```

Under the cited AES-GCM single-key bound, equal advantage scales the maximum
record count by `1027/1029`. Applying that ratio to `2^24.5` gives about
`23,680,450` full-size G301 records, about 46,116 fewer than the RFC's rounded
AES-GCM figure. Equivalently, using the unadjusted `2^24.5` count changes the
bound by only about `0.005614` bits; this is recorded for precision rather than
treated as a new guarantee.

The project therefore selects no G301-private descriptor field. Its proposed
generic libssl enforcement cap is at most `2^24 = 16,777,216` protected
records per sending traffic key and epoch. This is below both the RFC's
approximate value and the size-adjusted G301 value. At that cap, the extra two
AAD blocks cost about `0.005614` bits while the conservative integer cap keeps
about one full bit of record-count slack relative to `2^24.5`; the slack
therefore dominates the AAD adjustment.

This is a single-key, maximum-record-size comparison. It is not a fleet,
multi-user, multi-connection, or total-deployment failure bound. Read and
write directions and every traffic-key epoch are distinct scopes. The provider
does not count records or schedule KeyUpdate; the generic libssl record layer
must enforce the cap and test retry, KeyUpdate, close, and built-in suites.

Primary source: RFC 9846 Section 5.5. The exact analytical model must remain
identified in review evidence; this document does not turn an Internet-Draft
formula into a new standard claim.
