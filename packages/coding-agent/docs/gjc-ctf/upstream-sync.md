# Upstream synchronization

`gjc-ctf` has no generic upstream-sync command or automatic skill updater. It does provide one narrow acquisition API for the reviewed LA CTF archive pin; every other source remains unsupported.

## Content-addressed inputs

The implemented acquisition and any future sync/review must preserve:

- the benchmark `sourceCommit`;
- each challenge `sourceRevision` and `sourceSha256`;
- each corpus permission reference and artifact digest;
- backend/image/tool versions and backend policy digest;
- the trusted oracle id, entry digest, and registry digest;
- immutable safety-policy digest and calibration id/limits digest; and
- effective skill id/version/content, loader, build, and workspace-override digests.

A source revision or URL is a locator, not proof of content. A sync is acceptable only after the fetched bytes, permission evidence, and all digests are recorded and validated against a new manifest/lock lineage.
## Selected source

The selected corpus is a **local plumbing corpus, not scored evidence**: three archived LA CTF 2026 challenges from [`uclaacm/lactf-archive`](https://github.com/uclaacm/lactf-archive) at pinned source commit `3379d4a7b36680764a34e7dc817cc3c94c244764`:
- `2026/misc/endians` (`lactf-2026-misc-endians`)
- `2026/rev/ooo` (`lactf-2026-rev-ooo`)
- `2026/rev/flag-finder` (`lactf-2026-rev-flag-finder`)

This pin identifies source bytes for review; archive metadata and placeholder flags are not independent oracle evidence, and live challenge endpoints are not probed without explicit authorization.

## Skill and generated assets

The CTF skill is generated/embedded from the competition-owned source and checked by the identity loader. Do not edit the embedded artifact, loader digest, or build digest independently to make a lock pass. A legitimate skill update changes the source content, regenerates the packaged artifact, resolves a new effective content digest, and creates a new manifest/benchmark lock. Existing runs keep their old identity.

The compiled distribution embeds the CTF entry point, dashboard archive, and skill. Rebuilding those assets does not constitute an upstream benchmark sync and does not create benchmark evidence.

## Implemented pinned acquisition

`acquireLactfCorpus(source, cacheRoot)` accepts only a source equal to `LACTF_2026_CORPUS_SOURCES`, clones/fetches through exact Git argv with hooks disabled and an isolated home, checks out the immutable commit, and verifies HEAD and remote identity. `buildCorpusProvenance` hashes the reviewed visible files, and `materializeCorpusEntry` copies only those allowlisted regular files into a confined destination.

The three current source entries intentionally exclude `challenge.yaml`, archive flags, and solve scripts. Symlink escapes, a changed commit, changed repository URL, missing files, or digest mismatch fail closed. All entries remain `scored: false`; transport success does not supply permission, runtime, calibration, or oracle evidence.

Adding or updating a source requires a reviewed source-code change plus new manifest/lock lineage. Never rewrite an existing lock or accept challenge-provided fetch/install commands.

## Current operational guidance

There is no generic shell sync command. An owning TypeScript integration may call the narrow acquisition API and retain its provenance result; `gjc-ctf status --json` and the dashboard only inspect already registered state. Real scored benchmark execution remains unavailable without all authorities described above.
