# Benchmark contract, tiers, and version statistics

The LA CTF harness is a local, unscored plumbing corpus, not proof that every challenge is solved. Its pinned source is [`uclaacm/lactf-archive`](https://github.com/uclaacm/lactf-archive) commit `3379d4a7b36680764a34e7dc817cc3c94c244764`.

## Corpus and promotion gate

The immutable six-challenge corpus is ordered into two tiers:

1. Tier 1: `lactf-2026-misc-endians`, `lactf-2026-rev-ooo`, and `lactf-2026-rev-flag-finder`.
2. Tier 2: `lactf-2026-crypto-not-so-lazy-trigrams`, `lactf-2026-pwn-tic-tac-no`, and `lactf-2026-web-single-trust`.

Tier 1 starts active. Tier 2 may be promoted only when an independently signed report verifies every eligible active-tier challenge. A model or analyzer candidate cannot satisfy that rule. The solver-work deadline is fixed at `2026-08-09T00:00:00Z` (`2026-08-09 09:00 KST`).

The prior expanded-v2 campaign digest `3a834bd5cbb0a988e8c948ea454255d22ec3d3851b8617a64f6c1d920376e557` and its derived observations are invalidated by `artifacts/ctf/lactf-expanded-v2-invalidation.json`: the crypto materialization allowlist exposed the unnecessary plaintext source `pt.txt`. The corrected allowlist contains only `chall.py` and `ct.txt`; a fresh campaign and provenance receipt are required before publishing new candidate/failure statistics.
The Tier 1 diagnostic artifact `artifacts/ctf/lactf-tier1-local-evidence-v1.json` contains three source-bound local-checker passes signed by an ephemeral local authority. It omits candidate values and explicitly sets `scored: false` and `tierExpansionAuthorized: false`; these observations cannot satisfy the independent benchmark-oracle promotion gate.

Archive flags, official solves, archive solution scripts, hidden metadata, and candidate contents are excluded from evidence. The archive does not authorize remote-host access. No external permission record, trusted independent oracle, or calibration artifact is bundled, so the real-corpus benchmark remains unavailable and no score is published.

## Manifest, lock, and run records

A benchmark manifest (`ctf-benchmark-1`) binds the benchmark id, corpus and source provenance, eligibility and holdout policy, objective, fixed budget, five unique repeat seeds, model policy, effective skill identity, backend/oracle/safety/calibration/operational-limit digests, and report root. Its digest covers the complete manifest except the digest field.

A `ctf-benchmark-lock-1` repeats the immutable execution identity: manifest/corpus/eligibility/holdout/budget digests, source commit, objective, model, skill, backend, oracle, safety, calibration, operational limits, five seeds, and its lock digest. A mismatch is `benchmark_lock_mismatch`; a changed skill is a different run. Fixture, placeholder, and `todo` source references are rejected as provenance.

A `ctf-metrics-1` report retains all five records per locked challenge. A run record binds its run/challenge/repeat identity, deterministic seed, validated outcome, wall and first-valid time, intervention/token/tool/cost data, code commit, lock, effective skill, model/backend, calibration, category, and optional start time. A pass requires `validatedSolve: true` and an oracle-accepted result. Oracle failure, unsafe preflight, stale claim, missing provenance, or incomplete evidence is not a pass.

`runDeterministicFixtureBenchmark` is an implemented five-repeat fixture API. It is non-scored and cannot substitute for a locked, authorized, independently verified run. `gjc-ctf solve --mode benchmark` remains unavailable without injected backend, permission, preflight, calibration, lock, and oracle authorities.

## Versioned machine-readable statistics

`benchmarks/gjc-ctf/version-stats.ts` provides the machine-readable report/comparison workflow:

1. `computeVersionStats` accepts the full `BenchmarkReportRequest` authority bundle plus `identity`; it internally calls `evaluateBenchmarkReport` before aggregation and returns either `{ status: "ready", stats }` or `{ status: "unavailable", reason }`. A raw `MetricsReportV1` or structural signed proof is not an accepted input.
2. `validateVersionStats` and `parseVersionStats` verify the schema and self-sealing digests of a ready statistics artifact; they are integrity parsers, not benchmark authorization.
3. `versionStatsJson` emits canonical machine-readable JSON after that integrity check.
4. `compareVersionStats` accepts two complete version-statistics authority requests and authorizes both through `computeVersionStats` before returning comparable identity digests, solved-to-unsolved challenge regressions, and candidate-minus-baseline deltas. Raw self-sealed statistics objects cannot produce a production comparison. Different `corpusDigest`, `calibrationDigest`, or `benchmarkLockDigest` values produce an explicitly incomparable result.

Every report binds exactly these dimensions: `harnessDigest`, `effectiveSkillDigest`, `modelFingerprint`, `backendFingerprint`, `toolchainDigest`, `corpusDigest`, `calibrationDigest`, and `benchmarkLockDigest`. In this contract, `harnessDigest` is the authorized signed preflight-report digest and `toolchainDigest` is the authorized signed runtime-evidence digest; the remaining dimensions are checked against the validated manifest, lock, calibration, and run identities.

Statistics retain the eligible denominator; independently verified solve count and rate; pass@1 and pass@3; first-valid latency; p50/p95 runtime; input/output/cache token and tool totals; known cost and unknown-cost count; timeout/crash/leak/invalid/unknown/failure counts; category aggregates; per-challenge status; and confidence/holdout status. Comparable results include candidate-minus-baseline deltas for solve count/rate, pass@1/pass@3, first-valid and p50/p95 latency, token/tool/cost totals, and outcome counts, plus confidence/holdout transitions. A delta whose operand is unknown remains unknown. Unknown cost stays unknown rather than becoming zero. Unknown, failed, invalid, timed-out, crashed, leaked, and unvalidated outcomes remain visible and never become passes.

The API is programmatic; it is not a `gjc-ctf` CLI command. It must not be fed archive flags, official solves, solution scripts, candidate contents, or dashboard output.

## Skill optimization boundary

`generateSkillCandidate` and `evaluateSkillCandidate` retain diagnostic evaluations, while production promotion uses a digest-sealed `SkillOptimizationRoundStore` round. The round commits the ordered cohort, incumbent and benchmark lineage, finite continuation budget, and canonical Ed25519 training/holdout authority registry before selection. It permits exactly one signed training selection and one independently signed redacted holdout gate; only a passed gate for the selected candidate can reach the module-confined promotion capability. Failed or unavailable rounds cannot promote, and absent holdout authority closes zero-look as unavailable. Public artifacts are digest/status/count only. A promoted skill must be resolved through the normal identity loader and receive a new manifest/lock; it cannot silently rewrite a locked benchmark.
