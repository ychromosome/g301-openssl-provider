<!-- SPDX-License-Identifier: Apache-2.0 -->

# C1 result

Candidate: pass `NULL` instead of an empty `OSSL_PARAM` list to the inner
cipher during record reinitialization.

Eight counterbalanced ABBA/BAAB pairs per lane were measured on 2026-08-26.

| OpenSSL | Native pooled fixed-wrapper change | 95% CI | Result |
|---|---:|---:|---|
| 3.5.7 | 8.693 ns / 5.86% faster | 6.292 to 10.093 ns | pass |
| 4.0.1 | 1.297 ns / 0.82% faster | 0.779 to 3.688 ns | fail |

OpenSSL 4.0.1 native encryption also regressed by 4.116 ns, with a 95% CI of
1.364 to 4.909 ns regression. The cross-lane acceptance gate therefore failed.
The production candidate was not adopted. A later, separate parameter-scan
simplification is recorded in `CANDIDATE_SINGLE_PASS_RESULT.md`.
