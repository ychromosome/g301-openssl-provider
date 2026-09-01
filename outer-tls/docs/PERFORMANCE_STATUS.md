<!-- SPDX-License-Identifier: Apache-2.0 -->

# Performance status

Date: 2026-09-01

The standalone EVP benchmark uses reused contexts and measures IV reset, AAD,
payload, final, and tag get/set. Four paths isolate ordinary AES-GCM, the
32-byte manifest, a second AAD call, and the G301 wrapper. Each run uses a
balanced 4x4 Latin square, paired samples, and 10,000-resample bootstrap
intervals. It is not a TLS or production benchmark.

## Final native baseline

Values were measured on one AMD Ryzen 9 5950X host. OpenSSL 3.5.7 and 4.0.1
are exact evidence points for the ABI 3 and ABI 4 targets.

| OpenSSL | Direction | Payload | G301 ns/record | Total delta | Wrapper/API delta |
|---|---|---:|---:|---:|---:|
| 3.5.7 | Encrypt | 1 | 215.664 | +135.102 ns / +168.29% | +124.220 ns |
| 3.5.7 | Encrypt | 16 | 218.533 | +133.387 ns / +157.38% | +122.238 ns |
| 3.5.7 | Encrypt | 1,024 | 395.920 | +131.866 ns / +49.95% | +119.040 ns |
| 3.5.7 | Encrypt | 16,385 | 2,966.013 | +149.119 ns / +5.29% | +132.098 ns |
| 3.5.7 | Decrypt | 1 | 230.306 | +141.892 ns / +160.61% | +126.290 ns |
| 3.5.7 | Decrypt | 16 | 234.656 | +135.921 ns / +137.80% | +124.672 ns |
| 3.5.7 | Decrypt | 1,024 | 415.928 | +146.869 ns / +54.68% | +135.032 ns |
| 3.5.7 | Decrypt | 16,385 | 3,027.768 | +160.251 ns / +5.59% | +141.396 ns |
| 4.0.1 | Encrypt | 1 | 226.821 | +147.036 ns / +184.63% | +137.089 ns |
| 4.0.1 | Encrypt | 16 | 228.866 | +142.771 ns / +166.24% | +130.365 ns |
| 4.0.1 | Encrypt | 1,024 | 405.043 | +137.177 ns / +51.04% | +125.748 ns |
| 4.0.1 | Encrypt | 16,385 | 2,977.054 | +143.699 ns / +5.07% | +130.204 ns |
| 4.0.1 | Decrypt | 1 | 231.514 | +143.355 ns / +162.17% | +132.409 ns |
| 4.0.1 | Decrypt | 16 | 237.240 | +142.299 ns / +150.41% | +131.241 ns |
| 4.0.1 | Decrypt | 1,024 | 417.611 | +150.063 ns / +56.10% | +136.234 ns |
| 4.0.1 | Decrypt | 16,385 | 3,046.614 | +161.744 ns / +5.63% | +148.027 ns |

## Decisions

- C1, passing `NULL` instead of an empty parameter list, was rejected because
  it failed the cross-lane gate and regressed ABI 4 encryption.
- A later security fix replaced repeated external parameter-list searches with
  one local traversal. The recorded point estimates were 42.948 ns on 3.5.7
  and 42.871 ns on 4.0.1. A hostile rereview found the source-to-binary chain
  and two confidence-bound gates insufficient, so these figures are historical
  evidence, not an accepted performance claim.
- AAD fusion, direct provider dispatch, and local AES/GHASH remain rejected.

## Write-key usage counter

An eight-pair ABBA/BAAB run on OpenSSL 3.5.7 measured median fixed wrapper
cost increases of 18.154 ns pooled, 23.172 ns for encryption, and 13.653 ns
for decryption. At 16,385 bytes the native-path medians increased by 1.190%
for encryption and 1.233% for decryption. The counter is a security gate, not
a performance candidate; its measured cost is retained as a regression
baseline.

The corrected candidate runner builds both modules from verified, bundled
source snapshots and gates on adverse confidence limits. A fresh run on ABI 3
and ABI 4 is still required before restoring an acceptance claim.

The remaining fixed cost comes primarily from composing a provider-backed EVP
wrapper over another provider-backed EVP cipher. Further specialization is
deferred until a real workload establishes a requirement.
