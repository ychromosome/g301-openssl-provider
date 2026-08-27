# License scope — no repository-wide default

Copyright 2026 Martin Wolf and contributors.

This repository intentionally contains separately scoped material. A license
in one subtree does not apply to another subtree.

| Path | Provisional status |
|---|---|
| `outer-tls/**` | Apache License 2.0 (`Apache-2.0`), subject to each file's notices |
| `inner-threads/**` | `LicenseRef-G301-Inner-Reserved`; all rights reserved pending legal review |
| `LICENSES/Apache-2.0.txt` | Reference copy of Apache License 2.0 |
| root and `integration/**` | All rights reserved unless a file expressly states otherwise |

The inner-thread scope is an internal working designation, not an open-source
license grant. It is deliberately pending the planned law-office review. Do
not publish, redistribute, relicense, or move inner-thread material into the
Apache-licensed subtree without an explicit rights decision.

Third-party dependencies retain their own licenses. See each build manifest
and `outer-tls/THIRD_PARTY_NOTICES.md`.
