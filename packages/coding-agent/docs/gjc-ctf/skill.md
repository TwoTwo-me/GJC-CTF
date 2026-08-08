# CTF skill, lock identity, and promotion

The CTF skill is competition-owned and content-addressed; it is not a canonical GJC workflow default. It can produce a local candidate, never an independently verified solve by itself.

## Embedded and effective identity

The generated loader embeds `src/ctf/skills/ctf.md` with identity `ctf` version `1.1.0`. The effective identity records `id`, semantic version, `contentDigest`, `loaderDigest`, `buildDigest`, nullable `workspaceOverrideDigest`, source (`embedded` or `workspace-override`), and resolution time.

The canonical workspace override is `<competition-root>/.gjc-ctf/skills/overrides/ctf/SKILL.md`. When that file is absent and no explicit override path is supplied, the backward-compatible path is `<competition-root>/skills/ctf/SKILL.md`. Both remain inside the competition root. Absolute paths, `..`, unreadable content, wrong `ctf`/`1.1.0` front matter, loader/build identity changes, and digest mismatches are refused.

A manifest skill reference binds id/version/effective digest. A benchmark lock additionally binds `effectiveId`, `effectiveVersion`, `contentDigest`, `loaderDigest`, `buildDigest`, and nullable `workspaceOverrideDigest`. A changed effective skill requires a new manifest and benchmark lock; do not overwrite a digest to make a stale lock appear current.
## Competition-local generated installation

A fresh `gjc-ctf init` publishes the validated generated artifact before it creates the manifest at `<competition-root>/.gjc-ctf/skills/artifacts/ctf/1.1.0/<installed-effective-digest>/artifact.json`. On Linux, publication traverses from a retained physical root descriptor, creates and syncs fixed directory components with `mkdirat`, writes and syncs an anonymous `O_TMPFILE` inode, and links it into the retained final parent without replacement. Existing leaves are opened with `openat(O_NOFOLLOW)` and read once from that exact descriptor. Symlinks, non-regular leaves, unsafe components, conflicting bytes, and unavailable anonymous-inode publication are refused; there is no pathname-check or named-temporary fallback. Platforms without the descriptor-relative primitive fail closed rather than silently using the embedded identity.

Before publishing the generated artifact, init durably records the complete intended revision-1 manifest in canonical `.gjc-ctf-init.json` bytes. If the process stops after that receipt but before the manifest is committed, repeating init accepts only that exact current-generated-skill receipt, re-establishes artifact and initial-event-head durability, and commits the same competition identity; malformed, non-canonical, custom, or unrelated non-empty roots remain refused. The installer then re-loads the artifact and binds its installed effective digest into the manifest. This installed identity intentionally differs from the embedded fallback because its source and workspace-override digest are bound. Repeating a completed init is byte-idempotent. A later init restores a missing artifact only when the existing manifest already binds that exact generated installed identity and the current binary has exact matching bytes; skill-less, embedded, and custom manifests are never migrated. Outside init, the embedded fallback remains read-only and writes nothing.

This immutable generated namespace is separate from the canonical and legacy editable override paths. `ctf` remains competition-owned and is never globally or user-installed. GJC exposes exactly four public canonical workflow skills; `ctf` is not one of them.

## Candidate execution boundary

The tool-free production `AgentSession` adapter and local candidate backend consume only digest-bound materialized allowlisted files. They have no challenge-visible tools, network, credentials, hidden metadata, archive flags, or official solve scripts. Candidate/unknown/failure attempts are retained, but a candidate becomes a solve only when an independent trusted signed oracle validates the locked run.

The LA CTF campaign pin is `3379d4a7b36680764a34e7dc817cc3c94c244764`. Its six challenges are split into two tiers: misc/reverse first, then crypto/pwn/web. Tier expansion requires independently signed verification of every eligible active-tier challenge. The hard solver-work stop is `2026-08-09T00:00:00Z` (`2026-08-09 09:00 KST`). The current digest-sealed result is 4 candidates, 2 failures, and 0 independently verified solves; candidate values are not disclosed. The harness does not solve every challenge.

## Signed training and frozen-holdout promotion

`generateSkillCandidate`, `evaluateSkillCandidate`, and `SkillPromotionStore` implement the programmatic optimization path. A candidate is derived from an immutable parent and may change skill content only. The evaluator accepts trusted Ed25519-signed reports for both training and a committed frozen holdout, requires exact benchmark-lock lineage, minimum samples, bounded unknowns, and confidence-interval improvement. Promotion recomputes those conditions internally and records prepared/committed/aborted promotion or rollback receipts.

A failed or unknown candidate remains diagnosable but cannot become active. The active optimizer pointer cannot silently rewrite a locked benchmark skill: export/install the promoted artifact through the rooted identity loader, then create a new manifest and lock. The optimizer neither creates external permission nor supplies an oracle or calibration.

## Safety and limitations

Archive flags, official solves, solution scripts, hidden metadata, candidate contents, and dashboard output are prohibited as promotion or benchmark evidence. The pinned archive does not authorize contact with remote hosts. This repository contains no external permission record, trusted independent oracle report, or calibrated real-corpus result; missing evidence remains unavailable rather than a successful promotion or solve.
