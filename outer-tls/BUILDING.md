<!-- SPDX-License-Identifier: Apache-2.0 -->

# Building the G301 Alpha/Beta outer provider

Status: experimental. These commands do not install or activate a system
provider and do not grant a security, release, or production claim.

## Standalone EVP and descriptor tests

Requirements: C11 compiler, CMake 3.20 or newer, OpenSSL development files,
and pthreads. Mbed TLS development files are optional and used only by the
independent test oracle.

```sh
CCACHE_DISABLE=1 cmake -S . -B /tmp/g301-outer-system \
    -DBUILD_TESTING=ON \
    -DG301_ENABLE_MBEDTLS_ORACLE=ON \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER=/usr/bin/gcc
CCACHE_DISABLE=1 cmake --build /tmp/g301-outer-system --parallel
CCACHE_DISABLE=1 ctest --test-dir /tmp/g301-outer-system \
    --output-on-failure
```

The provider module is `/tmp/g301-outer-system/g301.so`. Upstream OpenSSL can
exercise the EVP provider and inspect its capability, but it does not natively
negotiate the provider-defined TLS suite.

## Reproducible lane scripts

The scripts require OpenSSL ABI major 3 or 4 and fresh work directories.
Exact patch releases are recorded as evidence, not treated as the support
boundary:

```sh
scripts/run-provider-lane.sh OPENSSL_ABI3_PREFIX FRESH_WORK_DIR 3
scripts/check-dual-lane.sh OPENSSL_ABI3_PREFIX \
    OPENSSL_ABI4_PREFIX FRESH_WORK_DIR
scripts/run-assurance-lane.sh OPENSSL_ABI3_PREFIX 3 FRESH_WORK_DIR
```

`run-provider-lane.sh` enables the Mbed TLS oracle, runs CTest, checks that the
module exports only `OSSL_provider_init`, binds to the requested lane, has
RELRO/NOW and a non-executable stack, and embeds the manifest once.

`run-assurance-lane.sh` adds ASan/UBSan, GCC `-fanalyzer`, Clang
`scan-build`, and Valgrind. LeakSanitizer is disabled only because it cannot
operate under the ptrace-constrained review environment; Valgrind is the
separate leak gate. This is an environment limitation, not a source waiver.

## Optional compatible-patch TLS E2E

Point CMake only at a prefix implementing the current six-field candidate API:

```sh
CCACHE_DISABLE=1 cmake -S . -B /tmp/g301-outer-private \
    -DBUILD_TESTING=ON \
    -DG301_ENABLE_PRIVATE_TLS_E2E=ON \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER=/usr/bin/gcc \
    -DOPENSSL_ROOT_DIR=/tmp/openssl-provider-suite-prefix \
    -DOPENSSL_USE_STATIC_LIBS=FALSE
CCACHE_DISABLE=1 cmake --build /tmp/g301-outer-private --parallel
LD_LIBRARY_PATH=/tmp/openssl-provider-suite-prefix/lib64 \
OPENSSL_MODULES=/tmp/g301-outer-private \
ctest --test-dir /tmp/g301-outer-private --output-on-failure
```

The E2E target is expected to verify exact G301 suite negotiation, private code
point `0xff30`, bidirectional application records, a 64-byte TLS exporter,
KeyUpdate followed by traffic, and fail-closed behavior when the provider is
absent. It does not exercise the separately licensed inner-thread layer.

The historical broad fork that required a seventh per-suite write-limit field
is intentionally incompatible with the current descriptor and is not a valid
normative lane. Do not add that field back merely to make an old binary pass.
