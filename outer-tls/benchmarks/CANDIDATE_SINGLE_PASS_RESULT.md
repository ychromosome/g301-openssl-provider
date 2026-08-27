<!-- SPDX-License-Identifier: Apache-2.0 -->

# Single-pass parameter-policy result

Candidate: replace repeated external parameter-list searches with one local
traversal while preserving the same forbidden-name inventory.

Eight counterbalanced ABBA/BAAB pairs per lane were measured on 2026-08-26.

| OpenSSL | Native pooled fixed-wrapper gain | 95% CI | Result |
|---|---:|---:|---|
| 3.5.7 | 42.948 ns / 25.67% | 42.002 to 45.141 ns | historical result |
| 4.0.1 | 42.871 ns / 24.08% | 41.234 to 45.750 ns | historical result |

The 2026-08-26 rereview found the original acceptance gate and provenance
insufficient. The point estimates remain historical evidence, but acceptance
is withdrawn until both lanes are rebuilt from exact bundled source snapshots
and pass the adverse-confidence-bound gates.
