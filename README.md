# G301

Experimental local workspace for two deliberately separate components:

- `outer-tls/`: Apache-2.0 OpenSSL provider for the G301 fixed-manifest
  AES-256-GCM profile;
- `inner-threads/`: reserved, non-public post-handshake work that is not part
  of the cipher and is not included in the current build effort.

The active work is confined to `outer-tls/`. It delegates AES-256-GCM to the
OpenSSL default provider and authenticates one fixed 32-byte manifest before
the caller-supplied AAD. It does not implement AES, GCM, TLS framing, nonce
generation, KeyUpdate, or application policy.

Current state:

- the EVP provider builds and passes the expanded functional and lifecycle
  matrix for OpenSSL ABI major 3 and ABI major 4; the recorded standalone
  evidence used 3.5.7 and 4.0.1;
- 4,096 deterministic cases per lane agree with an independent Mbed TLS
  AES-GCM oracle, including tag and one-sided-manifest rejection;
- ASan/UBSan, GCC and Clang analyzers, Valgrind, export/binding checks, and
  repeated load/unload checks pass on both lanes within the stated limits;
- the provider advertises the six-field minimal experimental TLS suite
  descriptor;
- an experimental native TLS lane against the separate provider-ciphersuite
  fork negotiates `0xff30`, exchanges data in both directions, agrees on an
  exporter, survives KeyUpdate and rejects an absent provider;
- the working name `G301-AES-256-GCM-V1` and code point `0xff30` are private
  experimental identifiers, not registrations;
- no production, security-audit, interoperability, FIPS, or standards claim
  is made.

Start with `outer-tls/README.md` and `outer-tls/docs/G301_DRAFT.md`.
Licensing is path-scoped; see `LICENSE_SCOPE.md`. There is no repository-wide
default license.
