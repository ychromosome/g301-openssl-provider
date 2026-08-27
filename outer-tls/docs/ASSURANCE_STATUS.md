<!-- SPDX-License-Identifier: Apache-2.0 -->

# Assurance status

Date: 2026-08-26

This file records freshly executed checks for the current standalone provider.
Historical PASS logs are not promoted to this status.

| Gate | OpenSSL 3.5.7 | OpenSSL 4.0.1 |
|---|---:|---:|
| Strict release build and CTest | PASS, 8/8 | PASS, 8/8 |
| Independent Mbed TLS 3.6.7 oracle | PASS, 4,096 cases | PASS, 4,096 cases |
| Tampered-tag rejection | PASS | PASS |
| One-sided-manifest rejection | PASS | PASS |
| Fresh load/use/unload cycles | PASS, 100 | PASS, 100 |
| Two isolated library contexts | PASS | PASS |
| Shared-key threaded use | PASS | PASS |
| ASan/UBSan runtime | PASS, 8/8 | PASS, 8/8 |
| GCC `-fanalyzer` | PASS | PASS |
| Clang `scan-build` | PASS, no bugs found | PASS, no bugs found |
| Valgrind | PASS, 0 errors/leaks in checked classes | PASS, 0 errors/leaks in checked classes |
| Binary surface and lane binding | PASS | PASS |
| Targeted direct-allocation failure sweep | PASS, 5/5 controlled | PASS, 5/5 controlled |

Compatibility is defined for OpenSSL ABI major 3 and ABI major 4. The exact
3.5.7 and 4.0.1 releases in the table identify these runs only.

The oracle compares G301 encryption and decryption with Mbed TLS AES-256-GCM
over `manifest || caller_AAD` across boundary-sized AAD and payload inputs. It
also proves that a tag from ordinary AES-GCM over caller AAD alone is rejected.
Expectations come from NIST SP 800-38D and the frozen G301 byte contract, not
from observed provider output.

The sanitizer lane disables LeakSanitizer because the review environment
prevents its ptrace operation. Valgrind is the independent leak lane. The
allocation sweep targets the provider's five direct allocations; it does not
claim exhaustive failure injection inside OpenSSL.

TLS negotiation is not established by this matrix. The historical broad fork
uses an obsolete seven-field descriptor and an older generated API surface;
it is not a substitute for the separate six-field minimal patch. Native TLS,
generic RFC 9846 record-use enforcement, resumption, and built-in-suite
non-regression remain open gates.

No production, standardization, FIPS, interoperability, constant-time, or
independent-audit claim follows from this status.
