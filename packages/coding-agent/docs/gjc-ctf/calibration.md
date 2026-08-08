# Calibration

Benchmark calibration is immutable for a selected objective. A calibration records its digest, eligible denominator, numeric thresholds, selected objective, operational limits, and safety-policy reference.

Benchmark preflight rejects missing or mismatched calibration, safety, limits, trusted-oracle, and benchmark-lock digests. Holdout entries are excluded from the eligible denominator. Threshold and fixture selection are implementation-time calibration inputs, not evidence of a live benchmark.

The selected corpus is a **local plumbing corpus, not scored evidence**: three archived LA CTF 2026 challenges from [`uclaacm/lactf-archive`](https://github.com/uclaacm/lactf-archive) at pinned source commit `3379d4a7b36680764a34e7dc817cc3c94c244764`:
- `2026/misc/endians` (`lactf-2026-misc-endians`)
- `2026/rev/ooo` (`lactf-2026-rev-ooo`)
- `2026/rev/flag-finder` (`lactf-2026-rev-flag-finder`)

No corpus permission record, independent trusted oracle report, or published score is bundled in this repository; Gate 5 remains unavailable until those external artifacts are supplied and verified. Archive metadata and placeholder flags do not satisfy oracle evidence, and live endpoints are not probed without explicit authorization.
