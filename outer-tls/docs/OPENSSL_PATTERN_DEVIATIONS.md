<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenSSL pattern deviations

Date: 2026-08-25

| Pattern | G301 decision | Reason |
|---|---|---|
| Built-in AES-GCM operation | Wrap default-provider AES-256-GCM through public EVP | G301 adds one fixed AAD prefix; no primitive fork |
| Ordinary AES name/aliases | Use only `G301-AES-256-GCM-V1` | Prevent silent substitution and recursive fetch |
| Provider `dupctx` | Not advertised | Optional interface; no proven current TLS consumer; copying mutable inner state would add audit surface |
| One-shot/pipeline cipher calls | Not advertised | Current record path needs the streaming encrypt/decrypt contract only |
| TLS 1.2 AEAD, MAC, encrypt-then-MAC, and multiblock controls | Explicitly rejected | V1 is TLS 1.3-only and must not enter legacy/offload paths |
| QUIC and kTLS | Excluded | Neither path can consume the experimental provider operation with the required semantics |
| GCM tag truncation | Rejected | V1 fixes a 16-byte tag |
| Per-suite usage-limit metadata | Omitted | RFC 9846 enforcement belongs to generic libssl, not a provider descriptor |
| TLS suite registration | Private `0xff30` test identity only | No IANA allocation or upstream interface exists yet |

Every deviation is a scope reduction or an explicit profile distinction. A
future consumer requirement must reopen and test the corresponding contract;
it must not be enabled silently.
