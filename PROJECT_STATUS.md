# Project status

Date: 2026-08-26

| Component | State |
|---|---|
| Outer EVP provider | BUILDS; ABI 3/4 matrix PASS (tested on 3.5.7 and 4.0.1) |
| Fixed manifest and KAT bytes | FROZEN for the experimental V1 profile |
| Minimal six-field TLS descriptor | IMPLEMENTED; descriptor inspection PASS |
| Private per-suite `2^24` field | REMOVED from the active design and source |
| Native TLS use | BLOCKED on separate minimal libssl patch and generic RFC 9846 enforcement |
| Independent AES-GCM oracle | PASS: 4,096 deterministic cases per lane, positive and negative |
| Lifecycle and concurrency | PASS: 100 fresh load/unload cycles, dual libctx, shared-key threads |
| Sanitizers and analyzers | PASS on both lanes; LSan replaced by separate Valgrind leak lane |
| Valgrind | PASS on both lanes; no errors or definite/indirect/possible leaks |
| Provider binary surface | PASS: one export, one manifest, exact-lane libcrypto binding |
| Historical broad-fork TLS smoke | NOT APPLICABLE: obsolete seven-field descriptor/API build |
| Performance baseline | COMPLETE on both lanes; fixed wrapper cost about 0.15-0.20 microseconds |
| First optimization spike | REJECTED: lane/direction-dependent, no stable gain |
| Independent external review | Prior reviews repaired; fresh rereview requested |
| Inner post-handshake layer | OUT OF SCOPE; unchanged |
| Production/release approval | NOT GRANTED |

The active target is intentionally narrow: one provider CIPHER operation and
one experimental TLS descriptor. The OpenSSL patch, generic record-usage
enforcement, public identifiers, and the reserved inner layer are separate
workstreams.

See `outer-tls/docs/ASSURANCE_STATUS.md` for the executed matrix and its claim
limits.
