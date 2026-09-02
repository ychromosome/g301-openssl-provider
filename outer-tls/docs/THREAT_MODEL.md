<!-- SPDX-License-Identifier: Apache-2.0 -->

# Threat model

## Protected assets

- confidentiality and integrity of records under the ordinary AES-256-GCM
  assumptions;
- fail-closed detection of a one-sided G301 manifest/dispatch mismatch.

## Trust boundaries

- libssl owns negotiation, traffic keys, nonces, sequence numbers, epochs,
  record framing, KeyUpdate, alerts, and connection close;
- OpenSSL's default provider owns AES-256-GCM and tag verification;
- the G301 provider owns exact manifest injection, its local EVP state, and
  the encrypted-record budget for each write key;
- the application owns peer authentication, authorization, replay-sensitive
  semantics, and any post-handshake protocol.

## Attacker model

A network attacker may observe, replay, delay, drop, reorder, and modify
traffic. Callers may supply malformed lengths, parameters, operation order,
tags, and lifecycle sequences. Provider loads, contexts, and operations may be
concurrent. Allocation and delegated EVP operations may fail.

Endpoint compromise, malicious local provider replacement, a broken AES
implementation, key exfiltration, and repeated `(key, nonce)` pairs are outside
the construction's protection.

## Security argument

For fixed public `M`, G301 is ordinary AES-256-GCM over AAD `M || A`. The
boundary is unambiguous because `M` is exactly 32 bytes. If peers disagree on
`M` while all other inputs match, their GHASH inputs differ and tag validation
fails with the ordinary forgery probability. This does not add strength to
AES-GCM or protect against both peers making the same mistake.

## Required controls

- exact key, IV, and tag lengths;
- exactly-once manifest injection before caller AAD and payload;
- no AAD after payload;
- no tag release before successful encryption final;
- no successful decryption final without a fresh current-record tag;
- no encryption after 23,680,450 records in one provider cipher context;
- checked length conversion and output bounds;
- fail-closed propagation of delegated failures;
- child-library-context fetch restricted to `provider=default`;
- no alias to ordinary AES-GCM and no FIPS claim;
- no QUIC/kTLS or legacy TLS bypass for the experimental operation.

## Non-claims

Passing the current matrix is not a proof, independent audit, standardization,
interoperability result, or production approval. The working name and code
point are not registrations.
