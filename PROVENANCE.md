# Provenance and evidence boundary

The local workspace was consolidated on 2026-08-14 from:

- outer source: `/home/martin/Dokumente/ED301/G301-TLS13-AEAD`;
- inner source: `/home/martin/Dokumente/ED301/G301-AEAD`.

Those directories were not Git repositories at consolidation time. The file
`ORIGIN_SHA256SUMS` is therefore a historical snapshot manifest, not a live
verification command. Some donor files changed after the snapshot, so a check
against today's donor directories is expected to fail. It must not be used as
current-source evidence.

The former root `SHA256SUMS` likewise describes an intermediate consolidation
state and is historical only. The active outer-provider source manifest is
`outer-tls/SOURCE_MANIFEST.sha256`; it binds the completed 2026-08-25 source,
test, script, license, and documentation set and intentionally excludes itself.

Current work is restricted to `outer-tls/`. The `inner-threads/` subtree is a
separate reserved component, is not copied into outer-provider deliverables,
and remains unchanged. Generated builds, logs, benchmarks, and review bundles
are evidence artifacts rather than source inputs and do not belong in a
minimal public source archive.

Future source changes invalidate that manifest and require regeneration after
the corresponding gates pass. `.git/`, build directories, `target/`, evidence
outputs, and the manifest file itself remain excluded.
