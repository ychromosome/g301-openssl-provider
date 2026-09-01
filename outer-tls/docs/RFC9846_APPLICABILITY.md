<!-- SPDX-License-Identifier: Apache-2.0 -->

# AES-GCM usage-limit applicability

RFC 9846 Section 5.5 states that up to `2^24.5` full-size AES-GCM records
retain an approximate `2^-57` authenticated-encryption margin and requires a
KeyUpdate or connection close before the applicable limit.

G301 adds 32 fixed AAD bytes but changes neither key, nonce, plaintext nor tag
length. At maximum TLS 1.3 plaintext size:

```text
TLSInnerPlaintext bytes               = 16385
ordinary plaintext GHASH blocks       = ceil(16385 / 16) = 1025
ordinary TLS header AAD blocks        = ceil(5 / 16) = 1
G301 manifest || TLS AAD blocks       = ceil((32 + 5) / 16) = 3
ordinary L / L+1                      = 1026 / 1027
G301 L / L+1                          = 1028 / 1029
```

Scaling the cited bound by `1027/1029` gives approximately 23,680,450
full-size records, about 0.005614 bits below the unadjusted value. This is a
single-key, maximum-record-size comparison, not a fleet-wide failure bound.
Directions and traffic-key epochs are separate scopes.

The active six-field capability declares no usage-limit parameter. An earlier
generic `2^24` libssl cap was evaluated but is not part of the current fork.
The final record-usage policy remains an integration gate; this arithmetic
does not claim that the current TLS lane enforces the derived threshold.
