import * as path from "node:path";
import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, NonNegativeIntegerSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, canonicalJson, type Digest, digestsEqual, sha256Hex } from "./digest";
import { CtfError } from "./errors";
import { SandboxExecutionClassSchema } from "./sandbox";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

const BenchmarkSeedSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const BenchmarkSeedTupleSchema = z.tuple([
	BenchmarkSeedSchema,
	BenchmarkSeedSchema,
	BenchmarkSeedSchema,
	BenchmarkSeedSchema,
	BenchmarkSeedSchema,
]);
export const BenchmarkSeedScheduleSchema = z.record(CtfIdSchema, BenchmarkSeedTupleSchema);
export type BenchmarkSeedTuple = [string, string, string, string, string];
export type BenchmarkSeedSchedule = Record<string, BenchmarkSeedTuple>;

export const BenchmarkCorpusEntrySchema = z
	.object({
		challengeId: CtfIdSchema,
		category: z.string().min(1),
		sourceRef: z.string().min(1),
		sourceRevision: z.string().min(1),
		sourceSha256: DigestSchema,
		permissionRef: z.string().min(1),
		artifactDigests: z.array(DigestSchema).min(1),
		executionClass: SandboxExecutionClassSchema,
		backendDigest: DigestSchema,
		solverVisibleAllowlist: z.array(z.string().min(1)),
		oracleId: CtfIdSchema,
		oracleDigest: DigestSchema,
	})
	.strict();
export type BenchmarkCorpusEntry = z.infer<typeof BenchmarkCorpusEntrySchema>;

function isUnsafeRelativePath(value: string): boolean {
	return (
		value.includes("\0") ||
		path.posix.isAbsolute(value) ||
		path.win32.isAbsolute(value) ||
		/^[A-Za-z]:/.test(value) ||
		value.split(/[\\/]+/).includes("..")
	);
}

function isPlaceholderMetadata(value: string): boolean {
	return /^(fixture|placeholder|todo)(:|$)/i.test(value.trim());
}

export const BenchmarkObjectiveSchema = z.enum(["competition-solve-first", "benchmark-fixed-budget"]);
export type BenchmarkObjective = z.infer<typeof BenchmarkObjectiveSchema>;

export const BenchmarkBudgetSchema = z
	.object({
		wallMs: PositiveIntegerSchema,
		inputTokens: NonNegativeIntegerSchema,
		outputTokens: NonNegativeIntegerSchema,
		toolCalls: NonNegativeIntegerSchema,
		costCents: NonNegativeIntegerSchema,
	})
	.strict();
export type BenchmarkBudget = z.infer<typeof BenchmarkBudgetSchema>;

export const SkillLockIdentitySchema = z
	.object({
		effectiveId: CtfIdSchema,
		effectiveVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
		contentDigest: DigestSchema,
		loaderDigest: DigestSchema,
		buildDigest: DigestSchema,
		workspaceOverrideDigest: DigestSchema.nullable(),
	})
	.strict();
export type SkillLockIdentity = z.infer<typeof SkillLockIdentitySchema>;

export const BenchmarkManifestV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.benchmark),
		benchmarkId: CtfIdSchema,
		createdAt: TimestampSchema,
		sourceCommit: z.string().min(1),
		corpus: z.array(BenchmarkCorpusEntrySchema).min(1),
		holdoutChallengeIds: z.array(CtfIdSchema),
		eligibilityPolicyVersion: z.string().min(1),
		objective: BenchmarkObjectiveSchema,
		budget: BenchmarkBudgetSchema,
		repeatCount: z.literal(5),
		/** Canonical challenge/repeat seed schedule. */
		seedSchedule: BenchmarkSeedScheduleSchema.optional(),
		/** Legacy alias for a single-challenge schedule. */
		seeds: z.array(BenchmarkSeedSchema).length(5).optional(),
		modelPolicyId: CtfIdSchema,
		modelConfigDigest: DigestSchema,
		skill: SkillLockIdentitySchema,
		backendPolicyDigest: DigestSchema,
		oracleRegistryDigest: DigestSchema,
		safetyPolicyDigest: DigestSchema,
		calibrationId: CtfIdSchema,
		operationalLimitsDigest: DigestSchema,
		reportRoot: z.string().min(1),
		manifestDigest: DigestSchema,
	})
	.strict();
export type BenchmarkManifestV1 = z.infer<typeof BenchmarkManifestV1Schema>;

export const BenchmarkLockV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.benchmarkLock),
		benchmarkId: CtfIdSchema,
		benchmarkManifestDigest: DigestSchema,
		corpusDigest: DigestSchema,
		eligibilityDigest: DigestSchema,
		holdoutDigest: DigestSchema,
		objective: BenchmarkObjectiveSchema,
		budgetDigest: DigestSchema,
		sourceCommit: z.string().min(1),
		modelPolicyId: CtfIdSchema,
		modelConfigDigest: DigestSchema,
		skill: SkillLockIdentitySchema,
		backendPolicyDigest: DigestSchema,
		oracleRegistryDigest: DigestSchema,
		safetyPolicyDigest: DigestSchema,
		calibrationId: CtfIdSchema,
		operationalLimitsDigest: DigestSchema,
		repeatCount: z.literal(5),
		/** Canonical challenge/repeat seed schedule. */
		seedSchedule: BenchmarkSeedScheduleSchema.optional(),
		/** Legacy alias for a single-challenge schedule. */
		seeds: z.array(BenchmarkSeedSchema).length(5).optional(),
		lockDigest: DigestSchema,
	})
	.strict();
export type BenchmarkLockV1 = z.infer<typeof BenchmarkLockV1Schema>;

export function benchmarkManifestDigest(
	manifest: BenchmarkManifestV1 | Omit<BenchmarkManifestV1, "manifestDigest">,
): Digest {
	return canonicalDigest(manifest, ["manifestDigest"]);
}
export function benchmarkCorpusDigest(manifest: Pick<BenchmarkManifestV1, "corpus">): Digest {
	return canonicalDigest(manifest.corpus);
}
export function benchmarkEligibilityDigest(
	manifest: Pick<BenchmarkManifestV1, "corpus" | "eligibilityPolicyVersion">,
): Digest {
	return canonicalDigest({ corpus: manifest.corpus, eligibilityPolicyVersion: manifest.eligibilityPolicyVersion });
}
export function benchmarkHoldoutDigest(manifest: Pick<BenchmarkManifestV1, "holdoutChallengeIds">): Digest {
	return canonicalDigest(manifest.holdoutChallengeIds);
}
export function benchmarkBudgetDigest(manifest: Pick<BenchmarkManifestV1, "budget">): Digest {
	return canonicalDigest(manifest.budget);
}
export function benchmarkLockDigest(lock: BenchmarkLockV1 | Omit<BenchmarkLockV1, "lockDigest">): Digest {
	return canonicalDigest(lock, ["lockDigest"]);
}

/** Deterministic repeat seed bound to immutable benchmark/challenge/repeat identity. */
export function benchmarkRepeatSeed(benchmarkId: string, challengeId: string, repeatIndex: number): `sha256:${string}` {
	if (!Number.isInteger(repeatIndex) || repeatIndex < 0 || repeatIndex >= 5)
		throw new RangeError("repeat index must be between 0 and 4");
	return `sha256:${sha256Hex(canonicalJson([benchmarkId, challengeId, repeatIndex]))}`;
}

export function benchmarkSeedSchedule(benchmarkId: string, challengeIds: readonly string[]): BenchmarkSeedSchedule {
	const unique = new Set(challengeIds);
	if (unique.size !== challengeIds.length || challengeIds.some(id => !CtfIdSchema.safeParse(id).success)) {
		throw new RangeError("benchmark challenge IDs must be unique and valid");
	}
	const schedule = {} as BenchmarkSeedSchedule;
	for (const challengeId of challengeIds) {
		schedule[challengeId] = [0, 1, 2, 3, 4].map(index =>
			benchmarkRepeatSeed(benchmarkId, challengeId, index),
		) as BenchmarkSeedTuple;
	}
	return schedule;
}

function seedScheduleMatches(
	schedule: BenchmarkSeedSchedule,
	benchmarkId: string,
	challengeIds: readonly string[],
): boolean {
	const expected = benchmarkSeedSchedule(benchmarkId, challengeIds);
	const actualIds = Object.keys(schedule);
	return (
		actualIds.length === challengeIds.length &&
		challengeIds.every(
			challengeId =>
				actualIds.includes(challengeId) &&
				schedule[challengeId].every((seed, index) => seed === expected[challengeId][index]),
		)
	);
}

function seedAliasMatches(
	seeds: readonly string[] | undefined,
	schedule: BenchmarkSeedSchedule | undefined,
	challengeIds: readonly string[],
): boolean {
	if (seeds === undefined) return true;
	if (challengeIds.length !== 1) return false;
	const challengeSchedule = schedule?.[challengeIds[0]];
	return challengeSchedule !== undefined && seeds.every((seed, index) => seed === challengeSchedule[index]);
}

export function validateBenchmarkManifest(value: unknown): BenchmarkManifestV1 {
	const parsed = BenchmarkManifestV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("benchmark_provenance_missing", "benchmark manifest is invalid", {
			details: { issues: parsed.error.issues },
		});
	const manifest = parsed.data;
	assertKnownMajor(manifest.schemaVersion, "benchmark");
	const ids = new Set<string>();
	for (const entry of manifest.corpus) {
		if (ids.has(entry.challengeId))
			throw new CtfError("benchmark_provenance_missing", `duplicate benchmark challenge: ${entry.challengeId}`);
		ids.add(entry.challengeId);
		if (isPlaceholderMetadata(entry.sourceRef) || isPlaceholderMetadata(entry.sourceRevision)) {
			throw new CtfError("benchmark_provenance_missing", `placeholder source provenance for ${entry.challengeId}`);
		}
		if (isPlaceholderMetadata(entry.permissionRef)) {
			throw new CtfError(
				"benchmark_provenance_missing",
				`placeholder permission provenance for ${entry.challengeId}`,
			);
		}
		for (const visiblePath of entry.solverVisibleAllowlist) {
			if (isUnsafeRelativePath(visiblePath)) {
				throw new CtfError(
					"benchmark_provenance_missing",
					`solver-visible path escapes the benchmark clean room for ${entry.challengeId}: ${visiblePath}`,
				);
			}
		}
	}
	if (manifest.seeds !== undefined && new Set(manifest.seeds).size !== manifest.seeds.length)
		throw new CtfError("invalid_manifest", "benchmark seeds must be unique");
	const challengeIds = manifest.corpus.map(entry => entry.challengeId);
	if (
		manifest.seedSchedule !== undefined &&
		(!seedScheduleMatches(manifest.seedSchedule, manifest.benchmarkId, challengeIds) ||
			!seedAliasMatches(manifest.seeds, manifest.seedSchedule, challengeIds))
	) {
		throw new CtfError(
			"benchmark_lock_mismatch",
			"benchmark seed schedule is not bound to the benchmark/challenge identity",
		);
	}
	if (manifest.seedSchedule === undefined && manifest.seeds !== undefined && challengeIds.length !== 1) {
		throw new CtfError("benchmark_lock_mismatch", "legacy benchmark seeds are ambiguous for multiple challenges");
	}
	if (!digestsEqual(benchmarkManifestDigest(manifest), manifest.manifestDigest))
		throw new CtfError("digest_mismatch", "benchmark manifest digest mismatch");
	return manifest;
}

export function validateBenchmarkLock(value: unknown): BenchmarkLockV1 {
	const parsed = BenchmarkLockV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("benchmark_lock_mismatch", "benchmark lock is invalid", {
			details: { issues: parsed.error.issues },
		});
	const lock = parsed.data;
	assertKnownMajor(lock.schemaVersion, "benchmarkLock");
	if (lock.seeds !== undefined && new Set(lock.seeds).size !== lock.seeds.length)
		throw new CtfError("benchmark_lock_mismatch", "benchmark lock seeds must be unique");
	if (lock.seedSchedule !== undefined) {
		for (const [challengeId, seeds] of Object.entries(lock.seedSchedule)) {
			const expected = [0, 1, 2, 3, 4].map(index => benchmarkRepeatSeed(lock.benchmarkId, challengeId, index));
			if (seeds.some((seed, index) => seed !== expected[index])) {
				throw new CtfError("benchmark_lock_mismatch", "benchmark lock seed schedule is not deterministic");
			}
		}
	}
	if (!digestsEqual(benchmarkLockDigest(lock), lock.lockDigest))
		throw new CtfError("digest_mismatch", "benchmark lock digest mismatch");
	return lock;
}

export function assertBenchmarkLockMatchesManifest(lock: BenchmarkLockV1, manifest: BenchmarkManifestV1): void {
	validateBenchmarkManifest(manifest);
	validateBenchmarkLock(lock);
	const checks: [boolean, string][] = [
		[lock.benchmarkId === manifest.benchmarkId, "benchmark ID"],
		[digestsEqual(lock.benchmarkManifestDigest, manifest.manifestDigest), "manifest digest"],
		[lock.repeatCount === manifest.repeatCount, "repeat count"],
		[
			(manifest.seedSchedule === undefined && lock.seedSchedule === undefined) ||
				(manifest.seedSchedule !== undefined &&
					lock.seedSchedule !== undefined &&
					canonicalDigest(lock.seedSchedule) === canonicalDigest(manifest.seedSchedule)),
			"seed schedule",
		],
		[
			(manifest.seeds === undefined && lock.seeds === undefined) ||
				(manifest.seeds !== undefined &&
					lock.seeds?.every((seed, index) => seed === manifest.seeds?.[index]) === true),
			"seeds",
		],
		[digestsEqual(lock.corpusDigest, benchmarkCorpusDigest(manifest)), "corpus digest"],
		[digestsEqual(lock.eligibilityDigest, benchmarkEligibilityDigest(manifest)), "eligibility digest"],
		[digestsEqual(lock.holdoutDigest, benchmarkHoldoutDigest(manifest)), "holdout digest"],
		[lock.objective === manifest.objective, "objective"],
		[digestsEqual(lock.budgetDigest, benchmarkBudgetDigest(manifest)), "budget digest"],
		[lock.sourceCommit === manifest.sourceCommit, "source commit"],
		[lock.modelPolicyId === manifest.modelPolicyId, "model policy"],
		[digestsEqual(lock.modelConfigDigest, manifest.modelConfigDigest), "model config"],
		[canonicalDigest(lock.skill) === canonicalDigest(manifest.skill), "effective skill identity"],
		[digestsEqual(lock.backendPolicyDigest, manifest.backendPolicyDigest), "backend policy"],
		[digestsEqual(lock.oracleRegistryDigest, manifest.oracleRegistryDigest), "oracle registry"],
		[digestsEqual(lock.safetyPolicyDigest, manifest.safetyPolicyDigest), "safety policy"],
		[lock.calibrationId === manifest.calibrationId, "calibration"],
		[digestsEqual(lock.operationalLimitsDigest, manifest.operationalLimitsDigest), "operational limits"],
	];
	const mismatch = checks.find(([ok]) => !ok);
	if (mismatch) throw new CtfError("benchmark_lock_mismatch", `benchmark lock ${mismatch[1]} does not match manifest`);
}

export function targetPassCount(eligibleCount: number): number {
	if (!Number.isInteger(eligibleCount) || eligibleCount < 0)
		throw new RangeError("eligible count must be non-negative");
	return eligibleCount >= 2 ? Math.max(2, Math.ceil(eligibleCount / 2)) : 0;
}
export const BenchmarkManifestSchema = BenchmarkManifestV1Schema;
export const BenchmarkLockSchema = BenchmarkLockV1Schema;
export const parseBenchmarkManifest = validateBenchmarkManifest;
export const parseBenchmarkLock = validateBenchmarkLock;
