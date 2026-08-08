# Metrics and version comparison

Metrics are derived only from immutable run provenance and independently verified oracle outcomes. This harness does not turn a candidate into a pass.

## Current campaign

The pinned LA CTF source is `uclaacm/lactf-archive` commit `3379d4a7b36680764a34e7dc817cc3c94c244764`, with six challenges in two tiers. The active first tier is the three misc/reverse challenges; crypto, pwn, and web remain in tier 2 until every eligible active-tier challenge independently verifies.

The prior campaign digest `3a834bd5cbb0a988e8c948ea454255d22ec3d3851b8617a64f6c1d920376e557`, `artifacts/ctf/lactf-expanded-v2-version-observation.json`, and the deadline comparison derived from it are invalidated by `artifacts/ctf/lactf-expanded-v2-invalidation.json`. The old crypto materialization included the unnecessary plaintext source `pt.txt`; its candidate/failure counts are retained only as audit history and cannot support benchmark, comparison, solver-quality, or tier-promotion claims. The corrected allowlist contains only `chall.py` and `ct.txt`, and current real-corpus statistics remain unavailable until a fresh provenance-bound campaign is run.
The current operational receipt is `artifacts/ctf/ctf-harness-v3-evidence.json`. It records 281 passing focused tests, zero focused failures, standalone `gjc`/`gjc-ctf` hashes, compiled bootstrap/init/status smoke, and zero CTF type diagnostics. The package-wide typecheck remains explicitly failed by unrelated pre-existing provider/ACP/browser/LSP/docs-rs diagnostics, so the receipt does not claim a green aggregate typecheck. `artifacts/ctf/lactf-version-observation-v2.json` records the invalid expanded-v2 baseline, diagnostic-only Tier 1 evidence, and the current verified-harness/unscored version without inventing solve-rate statistics.

## Validated metric rules

- `firstValidTimeMs` includes only an oracle-accepted result with `validatedSolve: true`.
- Eligible denominators exclude holdout entries and are bound to the calibration digest.
- Reports retain run, challenge, oracle, calibration, preflight, policy, and lock digests.
- Unknown, failed, invalid, timeout, crash, leak, and unvalidated samples remain visible; none is converted to a pass.
- Cost is known cents with a source or unknown with a reason and source. Unknown cost is never zero.
- `passAtK(totalRuns, successfulRuns, k)` uses the independent-repeat estimator `1 - C(total-successful, k) / C(total, k)` and preserves zero-pass and under-sampled cases. `nearestRank` provides p50/p95 for non-empty samples; otherwise the percentile is `null`.

## Machine-readable version statistics

The programmatic API in `benchmarks/gjc-ctf/version-stats.ts` builds and compares digest-sealed reports. `computeVersionStats` accepts the complete `BenchmarkReportRequest` authority bundle plus `identity`, internally invokes `evaluateBenchmarkReport`, and returns `{ status: "ready", stats }` or `{ status: "unavailable", reason }`. It does not accept a raw `MetricsReportV1` or a structural signed proof. `validateVersionStats` and `parseVersionStats` verify artifact integrity only; they do not authorize a benchmark result. `versionStatsJson` serializes an integrity-validated artifact. `compareVersionStats` accepts two full authority requests and authorizes both before comparing them; raw self-sealed statistics cannot produce a production comparison.

Each report identity contains `harnessDigest`, `effectiveSkillDigest`, `modelFingerprint`, `backendFingerprint`, `toolchainDigest`, `corpusDigest`, `calibrationDigest`, and `benchmarkLockDigest`. `harnessDigest` is the signed preflight-report digest and `toolchainDigest` is the signed runtime-evidence digest; all other fields are checked against the authorized manifest, lock, calibration, and runs. The report includes eligible denominator, verified solves/rate, pass@1/pass@3, first-valid latency, p50/p95 runtime, input/output/cache token and tool totals, known cost and unknown-cost count, outcome/category aggregates, per-challenge status, and confidence/holdout status. A comparable result includes candidate-minus-baseline deltas for solve count/rate, pass@1/pass@3, first-valid, p50/p95, tokens, tools, cost, and outcomes, as well as confidence/holdout transitions. Any delta with an unknown operand remains unknown. Comparison is explicitly incomparable if corpus, calibration, or benchmark-lock digest differs.

This is an API workflow, not an invented CLI command. It requires validated, locked evidence; archive flags, official solves, solution scripts, hidden metadata, candidate contents, and dashboard output are prohibited inputs.

No authorized external permission, independent signed oracle, or calibrated real-corpus run is available in this repository. Archive metadata is not oracle evidence, and no remote host may be contacted without authorization. Consequently, metrics may describe local fixture/campaign state but do not constitute a published LA CTF score.
