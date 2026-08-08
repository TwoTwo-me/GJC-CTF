import * as z from "zod/v4";
import { BenchmarkImplementationIdentitySchema, BenchmarkSeedScheduleSchema, benchmarkRepeatSeed } from "./benchmark";
import { CtfIdSchema, DigestSchema, NonNegativeIntegerSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { OracleTransitionProofSchema } from "./event";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";
export const TerminalGoalProofSchema = z
	.object({
		kind: z.literal("solved"),
		candidateId: CtfIdSchema,
		oracleResultDigest: DigestSchema,
	})
	.strict();
export type TerminalGoalProof = z.infer<typeof TerminalGoalProofSchema>;

export const SignedOracleProofSchema = z
	.object({
		verified: z.literal(true),
		result: z.record(z.string(), z.unknown()),
		entry: z.record(z.string(), z.unknown()),
		key: z.record(z.string(), z.unknown()),
		registryDigest: DigestSchema,
	})
	.strict();
export type SignedOracleProof = z.infer<typeof SignedOracleProofSchema>;
export type SignedEvidenceProof = z.infer<typeof OracleTransitionProofSchema>;

export const MetricCostSchema = z.union([
	z
		.object({ status: z.literal("known"), cents: z.number().finite().nonnegative(), source: z.string().min(1) })
		.strict(),
	z.object({ status: z.literal("unknown"), reason: z.string().min(1), source: z.string().min(1) }).strict(),
]);
export type MetricCost = z.infer<typeof MetricCostSchema>;

export const MetricOutcomeSchema = z.enum(["pass", "fail", "timeout", "crash", "leak", "invalid", "unknown"]);
export type MetricOutcome = z.infer<typeof MetricOutcomeSchema>;

const MetricOracleProofContextSchema = z
	.object({
		eventType: z.enum(["node", "edge"]),
		challengeId: CtfIdSchema,
		before: z.unknown().optional(),
		after: z.unknown(),
	})
	.strict();

export const MetricRunRecordSchema = z
	.object({
		runId: CtfIdSchema,
		challengeId: CtfIdSchema,
		repeatIndex: z.number().int().min(0).max(4),
		seed: z.string().regex(/^sha256:[a-f0-9]{64}$/),
		validatedSolve: z.boolean(),
		terminalGoalProof: TerminalGoalProofSchema.optional(),
		signedOracleProof: SignedOracleProofSchema.optional(),
		/** Digest of the signed sandbox preflight report bound to this run. */
		preflightReportDigest: DigestSchema.optional(),
		/** Digest of the signed runtime attestation bound to this run. */
		runtimeEvidenceDigest: DigestSchema.optional(),
		/** Canonical evidence digests covered by the signed proofs. */
		evidenceRefs: z.array(DigestSchema).min(1).optional(),
		/** Signed authority over the sandbox preflight report. */
		preflightProof: OracleTransitionProofSchema.optional(),
		/** Signed authority over runtime/oracle evidence. */
		runtimeProof: OracleTransitionProofSchema.optional(),
		/** Backward-compatible generic signed transition proof. */
		oracleProof: OracleTransitionProofSchema.optional(),
		/** Signed transition context used to verify benchmark preflight/runtime evidence. */
		oracleProofContext: MetricOracleProofContextSchema.optional(),
		outcome: MetricOutcomeSchema,
		wallTimeMs: PositiveIntegerSchema,
		firstValidTimeMs: PositiveIntegerSchema.nullable(),
		manualInterventionCount: NonNegativeIntegerSchema,
		inputTokens: NonNegativeIntegerSchema,
		outputTokens: NonNegativeIntegerSchema,
		cacheTokens: NonNegativeIntegerSchema,
		toolCalls: NonNegativeIntegerSchema,
		cost: MetricCostSchema,
		codeCommit: z.string().min(1),
		benchmarkLockDigest: DigestSchema,
		effectiveSkillDigest: DigestSchema,
		modelFingerprint: DigestSchema,
		backendFingerprint: DigestSchema,
		calibrationDigest: DigestSchema,
		category: z.string().min(1),
		startedAt: TimestampSchema.optional(),
	})
	.strict();
export type MetricRunRecord = z.infer<typeof MetricRunRecordSchema>;

export const CategoryAggregateSchema = z
	.object({
		category: z.string().min(1),
		numerator: NonNegativeIntegerSchema,
		denominator: PositiveIntegerSchema,
		excludedCount: NonNegativeIntegerSchema,
		unknownCount: NonNegativeIntegerSchema,
	})
	.strict();
export type CategoryAggregate = z.infer<typeof CategoryAggregateSchema>;

export const MetricsReportV1Schema = z
	.object({
		metricsSchemaVersion: z.literal(CTF_SCHEMA_VERSIONS.metrics),
		benchmarkId: CtfIdSchema,
		benchmarkLockDigest: DigestSchema,
		/** Optional for legacy metric summaries; benchmark publication requires it. */
		implementationIdentity: BenchmarkImplementationIdentitySchema.optional(),
		/** Optional for legacy metric summaries; benchmark publication requires it. */
		calibrationDigest: DigestSchema.optional(),
		/** Optional for legacy metric summaries; benchmark publication requires it. */
		eligibleChallengeIds: z.array(CtfIdSchema).min(1).optional(),
		createdAt: TimestampSchema,
		repeatCount: z.literal(5),
		/** Canonical challenge/repeat seed schedule. */
		seedSchedule: BenchmarkSeedScheduleSchema.optional(),
		/** Legacy alias for a single-challenge schedule. */
		seeds: z
			.array(z.string().regex(/^sha256:[a-f0-9]{64}$/))
			.length(5)
			.optional(),
		runs: z.array(MetricRunRecordSchema),
		passAt1: z.number().finite().min(0).max(1),
		passAt3: z.number().finite().min(0).max(1),
		categoryAggregates: z.array(CategoryAggregateSchema),
		p50WallTimeMs: PositiveIntegerSchema.nullable(),
		p95WallTimeMs: PositiveIntegerSchema.nullable(),
		manualInterventionCount: NonNegativeIntegerSchema,
		unknownCount: NonNegativeIntegerSchema,
		/** Calibration target/floor and the achieved eligible pass count. */
		targetPassCount: NonNegativeIntegerSchema.optional(),
		floorPassCount: NonNegativeIntegerSchema.optional(),
		achievedPassCount: NonNegativeIntegerSchema.optional(),
		fingerprint: DigestSchema,
	})
	.strict();
export type MetricsReportV1 = z.infer<typeof MetricsReportV1Schema>;

/** Backward-compatible alias for the canonical benchmark repeat seed function. */
export const repeatSeed = benchmarkRepeatSeed;

function choose(n: number, k: number): number {
	if (k < 0 || k > n) return 0;
	let result = 1;
	for (let i = 1; i <= k; i++) result = (result * (n - k + i)) / i;
	return result;
}

/** pass@k over independent repeats, retaining zero-pass and under-sampled behavior. */
export function passAtK(totalRuns: number, successfulRuns: number, k: number): number {
	if (
		!Number.isInteger(totalRuns) ||
		!Number.isInteger(successfulRuns) ||
		!Number.isInteger(k) ||
		totalRuns < 0 ||
		successfulRuns < 0 ||
		successfulRuns > totalRuns ||
		k <= 0
	) {
		throw new RangeError("invalid pass@k inputs");
	}
	if (totalRuns === 0 || k > totalRuns) return 0;
	return 1 - choose(totalRuns - successfulRuns, k) / choose(totalRuns, k);
}

/** Nearest-rank percentile (p is in [0,1]); empty samples have no percentile. */
export function nearestRank(samples: readonly number[], p: number): number | null {
	if (samples.length === 0) return null;
	if (!Number.isFinite(p) || p < 0 || p > 1) throw new RangeError("percentile must be between 0 and 1");
	const sorted = [...samples].sort((a, b) => a - b);
	const rank = Math.max(1, Math.ceil(p * sorted.length));
	return sorted[rank - 1];
}

export function metricsFingerprint(value: Omit<MetricsReportV1, "fingerprint">): Digest {
	return canonicalDigest(value);
}

export function validateMetricsReport(value: unknown): MetricsReportV1 {
	const parsed = MetricsReportV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_manifest", "metrics report is invalid", { details: { issues: parsed.error.issues } });
	const report = parsed.data;
	assertKnownMajor(report.metricsSchemaVersion, "metrics");
	if (report.seeds !== undefined && new Set(report.seeds).size !== report.seeds.length)
		throw new CtfError("invalid_manifest", "metrics report seeds must be unique");
	if (report.runs.some(run => run.benchmarkLockDigest !== report.benchmarkLockDigest))
		throw new CtfError("benchmark_lock_mismatch", "metrics runs use different benchmark locks");
	for (const run of report.runs) {
		if (!run.validatedSolve) continue;
		if (run.terminalGoalProof === undefined || run.signedOracleProof === undefined) {
			throw new CtfError(
				"oracle_integrity_error",
				`validated solve ${run.runId} is missing terminal-goal or signed-oracle proof`,
			);
		}
		const result = run.signedOracleProof.result;
		if (
			typeof result !== "object" ||
			result === null ||
			Array.isArray(result) ||
			canonicalDigest(result) !== run.terminalGoalProof.oracleResultDigest ||
			(result as Record<string, unknown>).runId !== run.runId ||
			(result as Record<string, unknown>).challengeId !== run.challengeId ||
			(result as Record<string, unknown>).verdict !== "pass" ||
			run.terminalGoalProof.candidateId.length === 0
		) {
			throw new CtfError("oracle_integrity_error", `validated solve ${run.runId} proof identity is invalid`);
		}
	}
	const challengeIds = report.eligibleChallengeIds ?? [...new Set(report.runs.map(run => run.challengeId))];
	if (report.seedSchedule !== undefined) {
		const scheduleIds = Object.keys(report.seedSchedule);
		if (
			scheduleIds.length !== challengeIds.length ||
			challengeIds.some(challengeId => !scheduleIds.includes(challengeId)) ||
			challengeIds.some(challengeId =>
				report.seedSchedule?.[challengeId].some(
					(seed, index) => seed !== benchmarkRepeatSeed(report.benchmarkId, challengeId, index),
				),
			)
		) {
			throw new CtfError("benchmark_lock_mismatch", "metrics report seed schedule is not deterministic");
		}
		if (
			report.seeds !== undefined &&
			(challengeIds.length !== 1 ||
				report.seeds.some((seed, index) => seed !== report.seedSchedule?.[challengeIds[0]][index]))
		) {
			throw new CtfError("benchmark_lock_mismatch", "metrics report seeds alias is ambiguous or detached");
		}
		for (const run of report.runs) {
			const schedule = report.seedSchedule[run.challengeId];
			if (schedule === undefined || run.seed !== schedule[run.repeatIndex]) {
				throw new CtfError(
					"benchmark_lock_mismatch",
					`metrics run ${run.runId} seed is not bound to the canonical schedule`,
				);
			}
		}
	} else if (report.seeds !== undefined) {
		for (const run of report.runs) {
			if (run.seed !== report.seeds[run.repeatIndex]) {
				throw new CtfError(
					"benchmark_lock_mismatch",
					`metrics run ${run.runId} seed does not match repeat ${run.repeatIndex}`,
				);
			}
		}
	}
	if (report.eligibleChallengeIds !== undefined) {
		if (new Set(report.eligibleChallengeIds).size !== report.eligibleChallengeIds.length) {
			throw new CtfError("invalid_manifest", "metrics report eligible challenge IDs must be unique");
		}
		const eligible = new Set(report.eligibleChallengeIds);
		if (report.runs.some(run => !eligible.has(run.challengeId))) {
			throw new CtfError("benchmark_lock_mismatch", "metrics run challenge is outside the eligible denominator");
		}
	}
	if ((report.calibrationDigest === undefined) !== (report.eligibleChallengeIds === undefined)) {
		throw new CtfError("invalid_manifest", "metrics report lineage fields must be provided together");
	}
	if (
		report.calibrationDigest !== undefined &&
		report.runs.some(run => run.calibrationDigest !== report.calibrationDigest)
	) {
		throw new CtfError("uncalibrated_limits", "metrics runs use a different calibration lineage");
	}
	if (report.eligibleChallengeIds !== undefined) {
		const aggregateDenominator = report.categoryAggregates.reduce((sum, aggregate) => sum + aggregate.denominator, 0);
		if (
			aggregateDenominator !== report.eligibleChallengeIds.length ||
			report.categoryAggregates.some(
				aggregate => aggregate.numerator + aggregate.excludedCount + aggregate.unknownCount > aggregate.denominator,
			)
		) {
			throw new CtfError("invalid_manifest", "metrics report category denominator is invalid");
		}
	}
	const { fingerprint, ...unsignedReport } = report;
	if (!digestsEqual(metricsFingerprint(unsignedReport), fingerprint)) {
		throw new CtfError("digest_mismatch", "metrics report fingerprint mismatch");
	}
	return report;
}
export const MetricsSchema = MetricsReportV1Schema;
export const parseMetricsReport = validateMetricsReport;
