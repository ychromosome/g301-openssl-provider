# G301 v0.1 inner threads

Status: **EXPERIMENTAL CORE / LOCAL TEST TARGET / ADAPTER GATED / NOT
SECURITY-AUDITED / NOT FOR PRODUCTION.**

This separately licensed subtree preserves the technical v0.1 inner layer:

| Channel | Public ID | Directions |
|---|---:|---|
| Menora | 301 | client-to-server, server-to-client |
| Chanukkia | 99 | client-to-server, server-to-client |
| Jom Kippur | 372 | client-to-server, server-to-client |
| Tzafah | 175 | client-to-server, server-to-client |
| Guard | 947 | client-to-server, server-to-client |

The key schedule derives ten independent contexts. Each owns a 256-bit AES-GCM
key, 96-bit nonce base, sequence number, and usage accounting. Guard commits
bind both peers to the same exporter and canonical application context before
data is accepted.

The Q2/QUIC transport, READY gate, record type `0x83`, admission engine, and
other retired paths from the source experiment are deliberately absent.

The normal API has no public raw-exporter constructor. Deterministic material
is available only under the `test-vectors` Cargo feature. A production adapter
is blocked until all crypto fetches can be injected from the TLS connection's
private OpenSSL library context; see `../integration/README.md`.

License: `LicenseRef-G301-Inner-Reserved`; all rights reserved pending legal
review. See `LICENSE` and the repository-level `../LICENSE_SCOPE.md`.
