<!-- SPDX-License-Identifier: Apache-2.0 -->

# G301 Alpha EVP microbenchmark

This benchmark measures the standalone Alpha/Beta EVP provider. It is not a
TLS benchmark, a security proof, or a production-readiness claim.

For 1, 16, 1024, and 16385-byte payloads it measures reused-context record
operations: IV reset, AAD, payload, final, and tag get/set. Four paths separate
the costs:

- `default_a`: AES-256-GCM with one five-byte caller-AAD call;
- `default_ma_prebuilt`: AES-256-GCM with one prebuilt 37-byte `M || A` call;
- `default_split_ma`: AES-256-GCM with separate 32-byte `M` and five-byte `A`
  calls;
- `g301_a`: G301 with five-byte caller AAD; the provider injects `M`.

The paired differences isolate total profile, manifest bytes, split AAD calls,
and wrapper/API cost. A balanced 4x4 Latin square rotates path order. Before
timing and after every paired sample, ciphertext, tags, plaintext, record
indices, and rolling checksums are checked across the appropriate paths.

Run with a separately built `g301.so` directory:

```sh
G301_BENCH_CPU=2 G301_BENCH_SAMPLES=48 \
    benchmarks/run_alpha_benchmark.sh PROVIDER_MODULE_DIR FRESH_OUTPUT
```

Set `OPENSSL_PREFIX` for an exact non-system OpenSSL lane. The runner rejects
different `libcrypto` resolution for the benchmark and provider. It writes raw
CSV, summary statistics, paired 10,000-resample bootstrap confidence intervals,
validation evidence, environment details, binary/source hashes, and checksums.

For an acceptance candidate, `run_candidate_abba.sh` takes exact baseline and
candidate source trees, verifies both source manifests, builds both modules,
and bundles their source snapshots with the measured binaries:

```sh
benchmarks/run_candidate_abba.sh OPENSSL_PREFIX \
    BASELINE_SOURCE CANDIDATE_SOURCE 3 FRESH_OUTPUT
```

Use `4` for ABI major 4. Each lane must pass independently. The runner rejects
absolute paths in its run table and uses the adverse 95% confidence bound for
both benefit and regression gates. `CC` may select the compiler.

`run_alpha_benchmark.sh` is a standalone diagnostic. Its output alone is not a
baseline/candidate acceptance package.

The masked run disables AES-NI, PCLMULQDQ, VAES, and VPCLMULQDQ through
OpenSSL's `OPENSSL_ia32cap` interface. It does not claim to disable every CPU
acceleration or stabilize clock frequency.
