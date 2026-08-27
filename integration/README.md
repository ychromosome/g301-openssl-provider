# Outer TLS to inner threads — integration gate

Status: **DESIGN CONTRACT / ADAPTER NOT STARTED.**

The layers remain separate. `outer-tls/` participates in TLS 1.3 through the
generic provider-suite interface in the pinned private OpenSSL fork.
`inner-threads/` starts only after that handshake is complete.

## Required adapter contract

The future adapter must fail closed unless all of these are true:

1. both peers completed TLS 1.3 with exact Alpha/Beta suite name
   `G301-AES-256-GCM-V1` and private code point `0xff30`;
2. the connection is a full, non-resumed handshake with no PSK, ticket-based
   resumption, or 0-RTT state;
3. neither QUIC nor kTLS owns the record path;
4. the adapter has the same private `OSSL_LIB_CTX` and property query that own
   the SSL context and provider suite;
5. the canonical application context is nonempty and at most 255 bytes;
6. `SSL_export_keying_material` (or its verified equivalent) is called exactly
   once, after Finished, for 48 bytes with label
   `EXPERIMENTAL-G301-ORLOGTHATTR-AEAD-v1` and the canonical context hash;
7. the 48 bytes move into a non-cloneable, zeroizing capability and are
   consumed into exactly one endpoint-role-bound inner session;
8. Guard 947 commits are exchanged and authenticated before any of the four
   data channels becomes active.

The adapter must not expose raw exporter bytes to ordinary callers, cache
them, recreate sessions from them, or call `Cipher::fetch(None, ...)` through
the process-global default context.

## Why the gate is open

The imported inner core deliberately retains the reviewed v0.1 derivation and
record behavior, but its AES-256-GCM fetch is process-global. Refactoring that
fetch into an injected private-context crypto backend changes a security-
critical lifetime boundary. It requires its own design, implementation review,
negative tests, and a combined native TLS E2E lane. This consolidation does
not hide that missing work behind a convenience adapter.
