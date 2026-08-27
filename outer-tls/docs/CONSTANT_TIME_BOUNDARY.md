<!-- SPDX-License-Identifier: Apache-2.0 -->

# Constant-time boundary

G301 contains no local AES, GHASH, finite-field, hash, KDF, or secret-indexed
table implementation. The wrapper forwards key, nonce, AAD, payload, and tag
operations to `AES-256-GCM` fetched from the selected OpenSSL default provider.

Local branches depend on public API state, direction, lengths, parameter
names, allocation outcomes, and delegated success or failure. The fixed
manifest is public. A branch-taint campaign over this adapter would therefore
not prove the constant-time behavior of AES-GCM; that property belongs to the
exact OpenSSL primitive binary, CPU dispatch, compiler, and platform.

The local codegen gate is narrower:

- no locally implemented primitive may appear;
- the module must bind to the requested lane's `libcrypto`;
- the manifest must appear exactly once;
- the only dynamic export is `OSSL_provider_init`;
- secret buffers and context storage are cleared on owned teardown paths;
- failures must not bypass final tag verification or release a fresh tag.

Passing these checks is a boundary and composition argument, not a general
constant-time proof. Any future local primitive or secret-dependent policy
would invalidate this conclusion and require a new taint/codegen campaign.
