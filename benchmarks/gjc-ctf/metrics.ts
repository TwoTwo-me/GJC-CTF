import { canonicalDigest, canonicalJson, digestsEqual, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import {
	assertBenchmarkLockMatchesManifest,
	SkillLockIdentitySchema,
	validateBenchmarkLock,
	validateBenchmarkManifest,
	type BenchmarkLockV1,
	type BenchmarkManifestV1,
	type BenchmarkSeedSchedule,
	type SkillLockIdentity,
} from "../../packages/coding-agent/src/ctf/contracts/benchmark";
import {
	benchmarkEligibleChallengeIds,
	benchmarkEligibleDenominator,
	verifyBenchmarkOracleTransitionProof,
	type BenchmarkOracleProofContext,
} from "./manifest";
import {
	nearestRank,
	metricsFingerprint,
	passAtK,
	MetricRunRecordSchema,
	validateMetricsReport,
	type MetricOutcome,
	type MetricRunRecord,
	type MetricsReportV1,
	type SignedOracleProof,
	type TerminalGoalProof,
} from "../../packages/coding-agent/src/ctf/contracts/metrics";
import {
	validateOracleTransitionProof,
	type OracleTransitionProof,
} from "../../packages/coding-agent/src/ctf/contracts/event";
import {
	validateBenchmarkCalibration,
	type BenchmarkCalibrationPolicy,
} from "../../packages/coding-agent/src/ctf/runtime/policy";
import {
	validateEffectiveSkill,
} from "../../packages/coding-agent/src/ctf/contracts/skill";
import {
	validateOperationalLimits,
	validateSafetyMaxima,
	type OperationalLimitsV1,
	type SafetyMaximaV1,
} from "../../packages/coding-agent/src/ctf/contracts/sandbox";
import {
	validateTrustedOracleRegistry,
	verifyTrustedOracleResult,
	type TrustedOracleRegistry,
} from "../../packages/coding-agent/src/ctf/runtime/oracle";
import { oracleResultDigest, oracleEntryDigest, type OracleResultV1 } from "../../packages/coding-agent/src/ctf/contracts/oracle";
export type { MetricRunRecord };

export type MetricValue<T> =
	| Readonly<{ status: "known"; value: T }>
	| Readonly<{ status: "unknown"; reason: string }>;
export type MetricDenominator = Readonly<{
	eligibleDenominator: number;
	eligibleChallengeIds?: readonly string[];
}>;

export type MetricSummaryCalibration = Readonly<{
	calibration: BenchmarkCalibrationPolicy;
	eligibleDenominator?: number;
}>;

export type BenchmarkResult =
	| Readonly<{
		status: "ready";
		benchmarkLock: BenchmarkLockV1;
		calibration: BenchmarkCalibrationPolicy;
		summary: DeterministicMetricSummary;
	}>
	| Readonly<{
		status: "unavailable";
		reason: string;
	}>;

export type BenchmarkReportResult =
	| Readonly<{ status: "ready"; report: MetricsReportV1 }>
	| Readonly<{ status: "unavailable"; reason: string }>;

export type DeterministicMetricSummary = Readonly<{
	passAt1: MetricValue<number>;
	passAt3: MetricValue<number>;
	p50WallTimeMs: MetricValue<number>;
	p95WallTimeMs: MetricValue<number>;
	totalRuns: number;
	failureRuns: number;
	unknownRuns: number;
	failureOutcomes: Readonly<Record<string, number>>;
	unknownReasons: readonly string[];
	costCents: MetricValue<number>;
	firstValidTimeMs: MetricValue<number>;
	manualInterventionCount: MetricValue<number>;
	inputTokens: MetricValue<number>;
	outputTokens: MetricValue<number>;
	cacheTokens: MetricValue<number>;
	toolCalls: MetricValue<number>;
	eligibleDenominator: number;
	calibrationDigest: Digest;
	thresholds: Readonly<Record<string, number>>;
	targetPassCount: number;
	floorPassCount: number;
	achievedPassCount: number;
}>;

export type MetricFixtureRun = Readonly<{
	runId: string;
	challengeId: string;
	repeatIndex: number;
	seed: `sha256:${string}`;
	outcome: MetricOutcome;
	validatedSolve: boolean;
	wallTimeMs: number;
}>;

export type MetricFixture = Readonly<{
	schemaVersion: "gjc-ctf-metric-fixture-1";
	fixtureId: string;
	benchmarkLockDigest: Digest;
	runs: readonly MetricFixtureRun[];
	fixtureDigest: Digest;
}>;

function unknown<T>(reason: string): MetricValue<T> {
	return { status: "unknown", reason };
}

function known<T>(value: T): MetricValue<T> {
	return { status: "known", value };
}
function rejectMetric(code: "benchmark_provenance_missing" | "benchmark_lock_mismatch" | "uncalibrated_limits" | "invalid_manifest" | "oracle_integrity_error", message: string): never {
	throw new CtfError(code, message);
}
function calibrationTargetFloor(
	calibration: BenchmarkCalibrationPolicy,
	denominator: number,
): { targetPassCount: number; floorPassCount: number } {
	const target = calibration.thresholds.targetPassCount;
	const floor = calibration.thresholds.floorPassCount;
	if (
		!Number.isSafeInteger(target) ||
		!Number.isSafeInteger(floor) ||
		target < 0 ||
		floor < 0 ||
		target > denominator ||
		floor > denominator ||
		floor > target
	) {
		rejectMetric("uncalibrated_limits", "benchmark calibration must bind valid targetPassCount and floorPassCount");
	}
	return { targetPassCount: target, floorPassCount: floor };
}

type BenchmarkMetricAuthority = Readonly<{
	manifest: BenchmarkManifestV1;
	seedSchedule: BenchmarkSeedSchedule;
	lock: BenchmarkLockV1;
	eligibleChallengeIds: readonly string[];
	categories: ReadonlyMap<string, string>;
	skill: SkillLockIdentity;
	effectiveSkillDigest: Digest;
	limits: OperationalLimitsV1;
	safety: SafetyMaximaV1;
	oracle: TrustedOracleRegistry;
	scored: boolean;
	oraclePins: ReadonlyMap<string, Readonly<{ oracleId: string; oracleDigest: Digest }>>;
}>;

type MetricInputValidation = Readonly<{
	denominator: number;
	calibration: BenchmarkCalibrationPolicy;
	challengeIds?: readonly string[];
	authority?: BenchmarkMetricAuthority;
	targetPassCount: number;
	floorPassCount: number;
}>;

function concreteBenchmarkAuthorities(
	options: Record<string, unknown>,
	manifest: BenchmarkManifestV1,
): Pick<BenchmarkMetricAuthority, "skill" | "limits" | "safety" | "oracle"> & { effectiveSkillDigest: Digest } {
	const rawSkill = options.effectiveSkill ?? options.skill;
	if (rawSkill === undefined) {
		rejectMetric("benchmark_provenance_missing", "scored benchmark runs require concrete effective skill identity");
	}
	const lockSkill = SkillLockIdentitySchema.safeParse(rawSkill);
	let skill: SkillLockIdentity;
	let effectiveSkillDigest: Digest;
	if (lockSkill.success) {
		skill = lockSkill.data;
		effectiveSkillDigest = canonicalDigest(skill);
	} else {
		try {
			const effective = validateEffectiveSkill(rawSkill);
			skill = {
				effectiveId: effective.id,
				effectiveVersion: effective.version,
				contentDigest: effective.contentDigest,
				loaderDigest: effective.loaderDigest,
				buildDigest: effective.buildDigest,
				workspaceOverrideDigest: effective.workspaceOverrideDigest,
			};
			effectiveSkillDigest = canonicalDigest(effective);
		} catch {
			rejectMetric("benchmark_provenance_missing", "effective skill identity is invalid");
		}
	}
	if (canonicalDigest(skill) !== canonicalDigest(manifest.skill)) {
		rejectMetric("benchmark_lock_mismatch", "effective skill identity does not match the benchmark manifest");
	}

	const rawSafety = options.safetyMaxima ?? options.safety;
	const rawLimits = options.operationalLimits ?? options.limits;
	if (rawSafety === undefined || rawLimits === undefined) {
		rejectMetric("uncalibrated_limits", "scored benchmark runs require concrete safety maxima and operational limits");
	}
	const safety = validateSafetyMaxima(rawSafety);
	const limits = validateOperationalLimits(rawLimits, safety);
	if (limits.selectedFor !== "benchmark" || limits.calibrationId !== manifest.calibrationId) {
		rejectMetric("uncalibrated_limits", "operational limits are not benchmark-calibrated");
	}
	if (limits.limitsDigest !== manifest.operationalLimitsDigest || safety.policyDigest !== manifest.safetyPolicyDigest) {
		rejectMetric("uncalibrated_limits", "concrete limits or safety maxima do not match the benchmark manifest");
	}

	const rawOracle = options.oracle;
	const registryInput = rawOracle && typeof rawOracle === "object" && !Array.isArray(rawOracle)
		? ((rawOracle as Record<string, unknown>).trustedRegistry ?? (rawOracle as Record<string, unknown>).oracleRegistry ?? (rawOracle as Record<string, unknown>).registry ?? rawOracle)
		: rawOracle;
	if (registryInput === undefined) {
		rejectMetric("benchmark_provenance_missing", "scored benchmark runs require a trusted oracle registry");
	}
	const oracle = validateTrustedOracleRegistry(registryInput);
	if (oracle.registry.registryDigest !== manifest.oracleRegistryDigest) {
		rejectMetric("benchmark_lock_mismatch", "trusted oracle registry does not match the benchmark manifest");
	}
	return { skill, limits, safety, oracle, effectiveSkillDigest };
}
function benchmarkMetricAuthority(options: Record<string, unknown> | undefined): BenchmarkMetricAuthority | undefined {
	const rawManifest = options?.manifest;
	const rawLock = options?.lock;
	if (rawManifest === undefined && rawLock === undefined) return undefined;
	if (rawManifest === undefined || rawLock === undefined) {
		rejectMetric("benchmark_provenance_missing", "metric benchmark manifest and lock are required together");
	}
	const manifest = validateBenchmarkManifest(rawManifest);
	const lock = validateBenchmarkLock(rawLock);
	assertBenchmarkLockMatchesManifest(lock, manifest);
	if (manifest.seedSchedule === undefined || lock.seedSchedule === undefined) {
		rejectMetric("benchmark_lock_mismatch", "scored benchmark runs require a canonical challenge seed schedule");
	}
	const eligibleChallengeIds = manifest.corpus
		.filter(entry => !manifest.holdoutChallengeIds.includes(entry.challengeId))
		.map(entry => entry.challengeId);
	const eligibleSet = new Set(eligibleChallengeIds);
	const categories = new Map(
		manifest.corpus
			.filter(entry => eligibleSet.has(entry.challengeId))
			.map(entry => [entry.challengeId, entry.category] as const),
	);
	if (categories.size !== eligibleChallengeIds.length) {
		rejectMetric("benchmark_provenance_missing", "metric benchmark eligible challenge categories are incomplete");
	}
	const concrete = concreteBenchmarkAuthorities(options ?? {}, manifest);
	const oraclePins = new Map(
		manifest.corpus
			.filter(entry => eligibleSet.has(entry.challengeId))
			.map(entry => [entry.challengeId, { oracleId: entry.oracleId, oracleDigest: entry.oracleDigest as Digest }] as const),
	);
	return {
		manifest,
		seedSchedule: manifest.seedSchedule,
		lock,
		eligibleChallengeIds,
		categories,
		oraclePins,
		scored: manifest.corpus
			.filter(entry => !manifest.holdoutChallengeIds.includes(entry.challengeId))
			.every(entry => entry.executionClass === "verified-local/rootless-podman-network-off"),
		...concrete,
	};
}

function sameOrderedIds(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((id, index) => id === right[index]);
}
function sameSeedSchedule(left: unknown, right: BenchmarkSeedSchedule | undefined): boolean {
	return right !== undefined && left !== undefined && canonicalDigest(left) === canonicalDigest(right);
}

type MetricRunWithTransitionContext = MetricRunRecord & Readonly<{
	oracleProofContext?: unknown;
	transitionContext?: unknown;
	signedTransitionContext?: unknown;
}>;

const METRIC_RUN_TRANSITION_CONTEXT_ALIASES = [
	"oracleProofContext",
	"transitionContext",
	"signedTransitionContext",
] as const;

function metricRunTransitionContext(run: MetricRunRecord): BenchmarkOracleProofContext | undefined {
	const value = run as unknown as Record<string, unknown>;
	const candidates = METRIC_RUN_TRANSITION_CONTEXT_ALIASES
		.map(alias => value[alias])
		.filter(candidate => candidate !== undefined);
	if (candidates.length === 0) return undefined;
	const first = candidates[0];
	if (candidates.slice(1).some(candidate => canonicalDigest(candidate) !== canonicalDigest(first))) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} has conflicting signed transition contexts`);
	}
	return first as BenchmarkOracleProofContext;
}

function metricRunSchemaValue(run: MetricRunRecord): unknown {
	const value = run as unknown as Record<string, unknown>;
	if (!METRIC_RUN_TRANSITION_CONTEXT_ALIASES.some(alias => alias in value)) return run;
	const {
		oracleProofContext: _oracleProofContext,
		transitionContext: _transitionContext,
		signedTransitionContext: _signedTransitionContext,
		...schemaValue
	} = value as MetricRunWithTransitionContext;
	return schemaValue;
}
function validateValidatedSolve(run: MetricRunRecord, authority: BenchmarkMetricAuthority): void {
	if (!run.validatedSolve) return;
	const terminal = run.terminalGoalProof as TerminalGoalProof | undefined;
	const signed = run.signedOracleProof as SignedOracleProof | undefined;
	if (terminal === undefined || signed === undefined) {
		throw new CtfError("oracle_integrity_error", `validated solve ${run.runId} is missing terminal-goal or signed-oracle proof`);
	}
	const result = signed.result as unknown as OracleResultV1;
	if (signed.registryDigest !== authority.oracle.registry.registryDigest) {
		rejectMetric("benchmark_lock_mismatch", `validated solve ${run.runId} oracle registry lineage is invalid`);
	}
	let digest: Digest;
	try {
		digest = oracleResultDigest(result);
		verifyTrustedOracleResult(authority.oracle, result, {
			runId: run.runId,
			challengeId: run.challengeId,
			nonce: result.nonce,
			candidateDigest: result.candidateDigest as Digest,
			inputDigest: result.inputDigest as Digest,
		});
	} catch (error) {
		if (error instanceof CtfError) throw error;
		rejectMetric("oracle_integrity_error", `validated solve ${run.runId} signed oracle proof is invalid`);
	}
	if (digest !== terminal.oracleResultDigest || result.runId !== run.runId || result.challengeId !== run.challengeId || result.verdict !== "pass") {
		rejectMetric("oracle_integrity_error", `validated solve ${run.runId} proof identity is invalid`);
	}
}
function validateSignedRunEvidence(run: MetricRunRecord, authority: BenchmarkMetricAuthority): void {
	if (
		!run.preflightReportDigest ||
		!run.runtimeEvidenceDigest ||
		!Array.isArray(run.evidenceRefs) ||
		!run.evidenceRefs.includes(run.preflightReportDigest) ||
		!run.evidenceRefs.includes(run.runtimeEvidenceDigest)
	) {
		rejectMetric("benchmark_provenance_missing", `metric run ${run.runId} is missing signed preflight/runtime evidence`);
	}
	let preflightProof: OracleTransitionProof;
	let runtimeProof: OracleTransitionProof;
	try {
		preflightProof = validateOracleTransitionProof(
			run.preflightProof ??
			(run.oracleProof?.authority === "preflight" ? run.oracleProof : undefined),
		);
		runtimeProof = validateOracleTransitionProof(
			run.runtimeProof ??
			(run.oracleProof?.authority === "oracle" ? run.oracleProof : undefined),
		);
	} catch {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} signed preflight/runtime evidence is invalid`);
	}
	const transitionContext = metricRunTransitionContext(run);
	if (transitionContext === undefined) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} requires an explicit signed transition context`);
	}
	if (transitionContext.challengeId !== run.challengeId) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} transition context is detached from its challenge`);
	}
	const evidenceDigest = canonicalDigest(run.evidenceRefs);
	if (
		preflightProof.authority !== "preflight" ||
		preflightProof.preflightReportDigest !== run.preflightReportDigest ||
		runtimeProof.authority !== "oracle" ||
		runtimeProof.oracleResultDigest !== run.runtimeEvidenceDigest ||
		preflightProof.registryDigest !== authority.oracle.registry.registryDigest ||
		runtimeProof.registryDigest !== authority.oracle.registry.registryDigest ||
		preflightProof.evidenceDigest !== evidenceDigest ||
		runtimeProof.evidenceDigest !== evidenceDigest
	) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} signed evidence is detached from the benchmark authority`);
	}
	const keyIds = new Set(authority.oracle.keys.map(key => key.keyId));
	if (!keyIds.has(preflightProof.signerKeyId) || !keyIds.has(runtimeProof.signerKeyId)) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} signed evidence uses an untrusted signer`);
	}
	const signed = run.signedOracleProof;
	if (signed === undefined) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} is missing signed oracle evidence`);
	}
	const result = signed.result as unknown as OracleResultV1;
	const pin = authority.oraclePins.get(run.challengeId);
	if (pin === undefined || result.oracleId !== pin.oracleId) {
		rejectMetric("benchmark_lock_mismatch", `metric run ${run.runId} oracle identity is not pinned to the challenge`);
	}
	const entry = authority.oracle.registry.entries.find(candidate => candidate.oracleId === result.oracleId);
	if (entry === undefined || oracleEntryDigest(entry) !== pin.oracleDigest || signed.registryDigest !== authority.oracle.registry.registryDigest) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} oracle evidence is detached from the challenge pin`);
	}
	if (
		!digestsEqual(preflightProof.oracleEntryDigest, pin.oracleDigest) ||
		!digestsEqual(runtimeProof.oracleEntryDigest, pin.oracleDigest) ||
		preflightProof.signerKeyId !== entry.signerKeyId ||
		runtimeProof.signerKeyId !== entry.publicKeyId
	) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} signed evidence authority is detached from the challenge pin`);
	}
	const resultDigest = oracleResultDigest(result);
	if (
		!digestsEqual(runtimeProof.oracleResultDigest, resultDigest) ||
		!digestsEqual(runtimeProof.oracleResultDigest, run.runtimeEvidenceDigest)
	) {
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} oracle result digest is detached from signed evidence`);
	}
	try {
		verifyTrustedOracleResult(authority.oracle, result, {
			runId: run.runId,
			challengeId: run.challengeId,
			nonce: result.nonce,
			candidateDigest: result.candidateDigest as Digest,
			inputDigest: result.inputDigest as Digest,
		});
	} catch (error) {
		if (error instanceof CtfError) throw error;
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} signed oracle evidence is invalid`);
	}
	try {
		verifyBenchmarkOracleTransitionProof(
			preflightProof,
			transitionContext,
			run.evidenceRefs as unknown as readonly Digest[],
			authority.manifest,
			authority.oracle,
		);
		verifyBenchmarkOracleTransitionProof(
			runtimeProof,
			transitionContext,
			run.evidenceRefs as unknown as readonly Digest[],
			authority.manifest,
			authority.oracle,
		);
	} catch (error) {
		if (error instanceof CtfError) throw error;
		rejectMetric("oracle_integrity_error", `metric run ${run.runId} signed transition evidence is invalid`);
	}
}

function validateMetricInputs(
	input: unknown,
	explicitCalibration?: unknown,
): MetricInputValidation {
	const options = input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : undefined;
	const authority = options !== undefined &&
		(options.effectiveSkill !== undefined ||
			options.skill !== undefined ||
			options.operationalLimits !== undefined ||
			options.limits !== undefined ||
			options.oracle !== undefined)
		? benchmarkMetricAuthority(options)
		: undefined;
	const calibrationInput = options?.calibration ?? explicitCalibration;
	const calibration = validateBenchmarkCalibration(calibrationInput, { requireBenchmark: true });
	if (authority !== undefined) {
		if (calibration.calibrationId !== authority.manifest.calibrationId || calibration.operationalLimitsDigest !== authority.manifest.operationalLimitsDigest) {
			rejectMetric("uncalibrated_limits", "metric calibration does not match the benchmark manifest");
		}
		if (options?.objective !== undefined && options.objective !== authority.manifest.objective) {
			rejectMetric("benchmark_lock_mismatch", "metric objective does not match the benchmark manifest");
		}
	}
	const expectedDenominator = authority === undefined || !authority.scored ? undefined : benchmarkEligibleDenominator(authority.manifest);
	const denominatorInput = options?.eligibleDenominator ?? (typeof input === "number" ? input : undefined);
	if (
		typeof denominatorInput !== "number" ||
		!Number.isSafeInteger(denominatorInput) ||
		denominatorInput <= 0 ||
		denominatorInput !== calibration.eligibleDenominator ||
		(expectedDenominator !== undefined && denominatorInput !== expectedDenominator)
	) {
		rejectMetric("benchmark_provenance_missing", "metric eligible denominator is missing or does not match calibration");
	}
	const targetFloor = authority === undefined || !authority.scored
		? { targetPassCount: 0, floorPassCount: 0 }
		: calibrationTargetFloor(calibration, denominatorInput);
	const rawIds = options?.eligibleChallengeIds;
	if (rawIds !== undefined && (!Array.isArray(rawIds) || rawIds.length !== denominatorInput || new Set(rawIds).size !== rawIds.length || !rawIds.every(id => typeof id === "string" && id.length > 0))) {
		rejectMetric("benchmark_provenance_missing", "metric eligible challenge denominator identity is invalid");
	}
	if (authority !== undefined && (!Array.isArray(rawIds) || !sameOrderedIds(rawIds as string[], authority.eligibleChallengeIds))) {
		rejectMetric("benchmark_lock_mismatch", "metric eligible challenge identity does not match the benchmark manifest");
	}
	return {
		denominator: denominatorInput,
		calibration,
		...(rawIds === undefined ? {} : { challengeIds: rawIds as string[] }),
		...(authority === undefined ? {} : { authority }),
		...targetFloor,
	};
}

function validateMetricRun(
	run: MetricRunRecord,
	authority?: BenchmarkMetricAuthority,
	calibration?: BenchmarkCalibrationPolicy,
	requireScoredEvidence = false,
): void {
	if (!MetricRunRecordSchema.safeParse(metricRunSchemaValue(run)).success) rejectMetric("invalid_manifest", `metric run is invalid: ${String((run as { runId?: unknown })?.runId ?? "<unknown>")}`);
	assertRunShape(run);
	if (requireScoredEvidence && (authority === undefined || !authority.scored))
		rejectMetric(
			"benchmark_provenance_missing",
			`metric run ${run.runId} cannot be scored without an independently verified local execution authority`,
		);
	if (authority !== undefined) {
		if (run.benchmarkLockDigest !== authority.lock.lockDigest || run.codeCommit !== authority.manifest.sourceCommit) {
			rejectMetric("benchmark_lock_mismatch", `metric run ${run.runId} is detached from the benchmark lock`);
		}
		const expectedSeed = authority.seedSchedule[run.challengeId]?.[run.repeatIndex];
		if (run.seed !== expectedSeed) {
			rejectMetric("benchmark_lock_mismatch", `metric run ${run.runId} seed does not match the canonical challenge/repeat schedule`);
		}
		if (run.category !== authority.categories.get(run.challengeId)) {
			rejectMetric("benchmark_lock_mismatch", `metric run ${run.runId} category does not match the benchmark manifest`);
		}
		if (calibration !== undefined && run.calibrationDigest !== calibration.calibrationDigest) {
			rejectMetric("uncalibrated_limits", `metric run ${run.runId} calibration lineage is invalid`);
		}
		if (run.effectiveSkillDigest !== authority.effectiveSkillDigest) {
			rejectMetric("benchmark_lock_mismatch", `metric run ${run.runId} effective skill identity is invalid`);
		}
		if (authority.scored || requireScoredEvidence) validateSignedRunEvidence(run, authority);
		validateValidatedSolve(run, authority);
		if (run.outcome === "pass" && !run.validatedSolve) {
			rejectMetric("oracle_integrity_error", `metric run ${run.runId} pass outcome lacks validated solve evidence`);
		}
		if (run.validatedSolve && run.outcome !== "pass") {
			rejectMetric("oracle_integrity_error", `metric run ${run.runId} validated solve has a non-pass outcome`);
		}
		if (run.outcome === "timeout" && run.wallTimeMs < authority.limits.wallMs) {
			rejectMetric("invalid_manifest", `metric run ${run.runId} timeout is below the calibrated wall limit`);
		}
	}
}

function assertRunShape(run: MetricRunRecord): void {
	if (!Number.isInteger(run.repeatIndex) || run.repeatIndex < 0 || run.repeatIndex > 4 || !Number.isInteger(run.wallTimeMs) || run.wallTimeMs <= 0) {
		throw new CtfError("invalid_manifest", `metric run is invalid: ${run.runId}`);
	}
}

/** pass@k for one challenge; unknown outcomes remain unknown rather than failures. */
export function metricPassAtK(runs: readonly MetricRunRecord[], k: number): MetricValue<number> {
	if (!Number.isInteger(k) || k <= 0) throw new RangeError("k must be a positive integer");
	if (runs.length === 0) return unknown("no runs");
	for (const run of runs) assertRunShape(run);
	if (runs.some(run => run.outcome === "unknown")) return unknown("one or more runs have unknown outcome");
	const successes = runs.filter(run => run.outcome === "pass" && run.validatedSolve).length;
	return known(passAtK(runs.length, successes, k));
}

function challengeGroups(runs: readonly MetricRunRecord[]): Map<string, MetricRunRecord[]> {
	const grouped = new Map<string, MetricRunRecord[]>();
	for (const run of runs) {
		const current = grouped.get(run.challengeId);
		if (current) current.push(run);
		else grouped.set(run.challengeId, [run]);
	}
	return grouped;
}
function sumKnown(runs: readonly MetricRunRecord[], field: "manualInterventionCount" | "inputTokens" | "outputTokens" | "cacheTokens" | "toolCalls"): MetricValue<number> {
	return known(runs.reduce((sum, run) => sum + run[field], 0));
}

function costTotal(runs: readonly MetricRunRecord[]): MetricValue<number> {
	if (runs.length === 0) return unknown("no runs");
	const unknownCost = runs.find(run => run.cost.status === "unknown");
	if (unknownCost && unknownCost.cost.status === "unknown") return unknown(`cost is unknown: ${unknownCost.cost.reason}`);
	return known(runs.reduce((sum, run) => sum + (run.cost.status === "known" ? run.cost.cents : 0), 0));
}

function firstValidTime(runs: readonly MetricRunRecord[]): MetricValue<number> {
	const values = runs
		.filter(run => run.outcome === "pass" && run.validatedSolve && run.firstValidTimeMs !== null)
		.map(run => run.firstValidTimeMs as number);
	return values.length === 0 ? unknown("no valid solve time observed") : known(nearestRank(values, 0.5) as number);
}


/**
 * Compute deterministic, evidence-scoped metrics.  A benchmark aggregate is
 * the arithmetic mean of per-challenge pass@k values; no empty challenge is
 * silently treated as a pass.
 */
export function summarizeMetricRuns(
	runs: readonly MetricRunRecord[],
	input?: unknown,
	explicitCalibration?: BenchmarkCalibrationPolicy,
): DeterministicMetricSummary {
	const metricInput = validateMetricInputs(input, explicitCalibration);
	for (const run of runs) validateMetricRun(run, metricInput.authority, metricInput.calibration);
	const groups = challengeGroups(runs);
	if (metricInput.challengeIds && [...groups.keys()].some((challengeId: string) => !metricInput.challengeIds?.includes(challengeId))) {
		rejectMetric("invalid_manifest", "metric run challenge is outside the eligible denominator");
	}
	if (!metricInput.challengeIds && groups.size > metricInput.denominator) {
		rejectMetric("benchmark_provenance_missing", "metric runs exceed the eligible denominator");
	}
	const denominatorCovered = metricInput.challengeIds
		? groups.size === metricInput.challengeIds.length && metricInput.challengeIds.every(challengeId => groups.has(challengeId))
		: groups.size === metricInput.denominator;
	const perChallenge1: number[] = [];
	const perChallenge3: number[] = [];
	const unknownReasons: string[] = denominatorCovered ? [] : ["eligible denominator is not fully observed"];
	for (const [challengeId, group] of groups) {
		const one = metricPassAtK(group, 1);
		const three = metricPassAtK(group, 3);
		if (one.status === "known") perChallenge1.push(one.value);
		else unknownReasons.push(`${challengeId}: ${one.reason}`);
		if (three.status === "known") perChallenge3.push(three.value);
		else if (!unknownReasons.includes(`${challengeId}: ${three.reason}`)) unknownReasons.push(`${challengeId}: ${three.reason}`);
	}
	const failures = runs.filter(run => run.outcome !== "pass" && run.outcome !== "unknown");
	const unknownRuns = runs.filter(run => run.outcome === "unknown");
	const failureOutcomes: Record<string, number> = {};
	for (const run of failures) failureOutcomes[run.outcome] = (failureOutcomes[run.outcome] ?? 0) + 1;
	const wallLimit = metricInput.authority?.limits.wallMs
		?? (typeof metricInput.calibration.thresholds.wallMs === "number" && metricInput.calibration.thresholds.wallMs > 0 ? metricInput.calibration.thresholds.wallMs : undefined);
	const wallTimes = runs
		.filter(run => run.outcome !== "unknown")
		.map(run => run.outcome === "timeout" && wallLimit !== undefined ? Math.min(run.wallTimeMs, wallLimit) : run.wallTimeMs)
		.sort((a, b) => a - b);
	const average = (values: readonly number[]): MetricValue<number> => !denominatorCovered || values.length === 0 ? unknown(!denominatorCovered ? "eligible denominator is not fully observed" : "no fully observed challenge runs") : known(values.reduce((sum, value) => sum + value, 0) / values.length);
	const achievedPassCount = [...groups.values()].filter(group => group.some(run => run.outcome === "pass" && run.validatedSolve)).length;
	return {
		passAt1: average(perChallenge1),
		passAt3: average(perChallenge3),
		p50WallTimeMs: !denominatorCovered || wallTimes.length === 0 ? unknown(!denominatorCovered ? "eligible denominator is not fully observed" : "no observed wall times") : known(nearestRank(wallTimes, 0.5) as number),
		p95WallTimeMs: !denominatorCovered || wallTimes.length === 0 ? unknown(!denominatorCovered ? "eligible denominator is not fully observed" : "no observed wall times") : known(nearestRank(wallTimes, 0.95) as number),
		totalRuns: runs.length,
		failureRuns: failures.length,
		unknownRuns: unknownRuns.length,
		failureOutcomes,
		unknownReasons,
		costCents: costTotal(runs),
		firstValidTimeMs: firstValidTime(runs),
		manualInterventionCount: sumKnown(runs, "manualInterventionCount"),
		inputTokens: sumKnown(runs, "inputTokens"),
		outputTokens: sumKnown(runs, "outputTokens"),
		cacheTokens: sumKnown(runs, "cacheTokens"),
		toolCalls: sumKnown(runs, "toolCalls"),
		eligibleDenominator: metricInput.denominator,
		calibrationDigest: metricInput.calibration.calibrationDigest,
		thresholds: metricInput.calibration.thresholds,
		targetPassCount: metricInput.targetPassCount,
		floorPassCount: metricInput.floorPassCount,
		achievedPassCount,
	};
}
function unavailableReason(error: unknown): string {
	return error instanceof CtfError ? error.message : "benchmark result preflight failed";
}
function isDigestValue(value: unknown): value is Digest {
	return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}
function validateSignedBenchmarkEvidenceForReport(
	value: Record<string, unknown>,
	manifest: BenchmarkManifestV1,
	lock: BenchmarkLockV1,
	oracle: TrustedOracleRegistry,
): void {
	const preflightDigest = value.preflightReportDigest;
	const runtimeDigest = value.runtimeEvidenceDigest;
	if (!isDigestValue(preflightDigest) || !isDigestValue(runtimeDigest)) {
		rejectMetric("benchmark_provenance_missing", "scored benchmark report requires signed preflight/runtime evidence digests");
	}
	const refs = value.evidenceRefs;
	if (
		!Array.isArray(refs) ||
		refs.length < 2 ||
		!refs.every(isDigestValue) ||
		!refs.includes(preflightDigest) ||
		!refs.includes(runtimeDigest)
	) {
		rejectMetric("benchmark_provenance_missing", "scored benchmark report evidence references are incomplete");
	}
	let preflight: OracleTransitionProof;
	let runtime: OracleTransitionProof;
	try {
		preflight = validateOracleTransitionProof(
			value.preflightProof ??
			(typeof value.oracleProof === "object" && value.oracleProof !== null && !Array.isArray(value.oracleProof) &&
			(value.oracleProof as { authority?: unknown }).authority === "preflight"
				? value.oracleProof
				: undefined),
		);
		runtime = validateOracleTransitionProof(
			value.runtimeProof ??
			(typeof value.oracleProof === "object" && value.oracleProof !== null && !Array.isArray(value.oracleProof) &&
			(value.oracleProof as { authority?: unknown }).authority === "oracle"
				? value.oracleProof
				: undefined),
		);
	} catch {
		rejectMetric("oracle_integrity_error", "scored benchmark report signed evidence is invalid");
	}
	const evidenceDigest = canonicalDigest(refs);
	if (
		preflight.authority !== "preflight" ||
		preflight.preflightReportDigest !== preflightDigest ||
		runtime.authority !== "oracle" ||
		runtime.oracleResultDigest !== runtimeDigest ||
		preflight.registryDigest !== manifest.oracleRegistryDigest ||
		runtime.registryDigest !== manifest.oracleRegistryDigest ||
		preflight.evidenceDigest !== evidenceDigest ||
		runtime.evidenceDigest !== evidenceDigest ||
		lock.oracleRegistryDigest !== manifest.oracleRegistryDigest
	) {
		rejectMetric("oracle_integrity_error", "scored benchmark report evidence is detached from the benchmark lock");
	}
	const keyIds = new Set(oracle.keys.map(key => key.keyId));
	if (!keyIds.has(preflight.signerKeyId) || !keyIds.has(runtime.signerKeyId)) {
		rejectMetric("oracle_integrity_error", "scored benchmark report evidence uses an untrusted signer");
	}
	if (value.oracleProofContext === undefined) {
		rejectMetric("oracle_integrity_error", "scored benchmark report requires an explicit transition context");
	}
	try {
		verifyBenchmarkOracleTransitionProof(preflight, value.oracleProofContext, refs as Digest[], manifest, oracle);
		verifyBenchmarkOracleTransitionProof(runtime, value.oracleProofContext, refs as Digest[], manifest, oracle);
	} catch (error) {
		if (error instanceof CtfError) throw error;
		rejectMetric("oracle_integrity_error", "scored benchmark report signature is invalid");
	}
}

/**
 * Inspect a benchmark result without converting missing evidence into a score.
 * A ready result requires a valid immutable manifest/lock lineage,
 * digest-bound calibration, manifest-derived denominator and IDs,
 * known outcomes for every run.
 */
export function evaluateBenchmarkResult(request: unknown): BenchmarkResult {
	try {
		if (!request || typeof request !== "object" || Array.isArray(request)) {
			return { status: "unavailable", reason: "benchmark result request is missing" };
		}
		const value = request as Record<string, unknown>;
		const manifest = validateBenchmarkManifest(value.manifest);
		const lock = validateBenchmarkLock(value.lock);
		assertBenchmarkLockMatchesManifest(lock, manifest);
		const authority = benchmarkMetricAuthority(value);
		if (authority === undefined) return { status: "unavailable", reason: "benchmark result benchmark authority is missing" };
		const calibration = validateBenchmarkCalibration(value.calibration, { requireBenchmark: true });
		if (calibration.calibrationId !== manifest.calibrationId || calibration.operationalLimitsDigest !== manifest.operationalLimitsDigest) {
			return { status: "unavailable", reason: "benchmark result calibration lineage is invalid" };
		}
		if (value.objective !== undefined && value.objective !== manifest.objective) {
			return { status: "unavailable", reason: "benchmark result objective does not match the benchmark manifest" };
		}
		if (
			(value.benchmarkId !== undefined && value.benchmarkId !== manifest.benchmarkId) ||
			(value.benchmarkLockDigest !== undefined && value.benchmarkLockDigest !== lock.lockDigest) ||
			(value.calibrationId !== undefined && value.calibrationId !== manifest.calibrationId) ||
			(value.calibrationDigest !== undefined && value.calibrationDigest !== calibration.calibrationDigest) ||
			!sameSeedSchedule(value.seedSchedule, lock.seedSchedule) ||
			(value.seeds !== undefined &&
				(lock.seeds === undefined ||
					!Array.isArray(value.seeds) ||
					!value.seeds.every((seed: unknown) => typeof seed === "string") ||
					!sameOrderedIds(value.seeds as string[], lock.seeds)))
		) {
			return { status: "unavailable", reason: "benchmark result immutable lineage is invalid" };
		}
		const eligibleDenominator = benchmarkEligibleDenominator(manifest);
		if (value.eligibleDenominator !== eligibleDenominator) {
			return { status: "unavailable", reason: "benchmark result denominator is not derived from the benchmark manifest" };
		}
		const targetFloor = calibrationTargetFloor(calibration, eligibleDenominator);
		if (value.targetPassCount !== targetFloor.targetPassCount || value.floorPassCount !== targetFloor.floorPassCount) {
			return { status: "unavailable", reason: "benchmark result target/floor values are not calibrated" };
		}
		try {
			validateSignedBenchmarkEvidenceForReport(value, manifest, lock, authority.oracle);
		} catch (error) {
			return { status: "unavailable", reason: unavailableReason(error) };
		}
		if (
			!Array.isArray(value.eligibleChallengeIds) ||
			!value.eligibleChallengeIds.every(id => typeof id === "string") ||
			!sameOrderedIds(value.eligibleChallengeIds as string[], authority.eligibleChallengeIds)
		) {
			return { status: "unavailable", reason: "benchmark result eligible challenge identity does not match the benchmark manifest" };
		}
		if (!Array.isArray(value.runs)) return { status: "unavailable", reason: "benchmark result runs are missing" };
		const runs = value.runs as MetricRunRecord[];
		for (const run of runs) {
			try {
				validateMetricRun(run, authority, calibration, true);
			} catch (error) {
				return { status: "unavailable", reason: unavailableReason(error) };
			}
		}
		const summary = summarizeMetricRuns(runs, {
			...value,
			manifest,
			lock,
			eligibleDenominator,
			eligibleChallengeIds: authority.eligibleChallengeIds,
			calibration,
			objective: manifest.objective,
		});
		if (value.achievedPassCount !== summary.achievedPassCount) {
			return { status: "unavailable", reason: "benchmark result achieved pass count is not derived from validated runs" };
		}
		const groups = challengeGroups(runs);
		if (groups.size !== summary.eligibleDenominator || summary.unknownRuns !== 0) {
			return { status: "unavailable", reason: "benchmark result does not cover every eligible repeat with known outcomes" };
		}
		for (const group of groups.values()) {
			const indices = group.map(run => run.repeatIndex);
			if (group.length !== 5 || new Set(indices).size !== 5 || ![0, 1, 2, 3, 4].every(index => indices.includes(index))) {
				return { status: "unavailable", reason: "benchmark result requires five unique repeats per eligible challenge" };
			}
		}
		return Object.freeze({ status: "ready", benchmarkLock: lock, calibration, summary });
	} catch (error) {
		return { status: "unavailable", reason: unavailableReason(error) };
	}
}

/** Throwing form for integrations that need a hard stop before publication. */
export function validateBenchmarkResult(request: unknown): Extract<BenchmarkResult, { status: "ready" }> {
	const result = evaluateBenchmarkResult(request);
	if (result.status !== "ready") rejectMetric("benchmark_provenance_missing", result.reason);
	return result;
}

export type BenchmarkReportRequest = Readonly<{
	report: unknown;
	manifest: unknown;
	lock: unknown;
	calibration: unknown;
	eligibleDenominator: unknown;
	/** The manifest-derived eligible challenge identity; required for publication. */
	eligibleChallengeIds: unknown;
	objective?: unknown;
	effectiveSkill?: unknown;
	skill?: unknown;
	operationalLimits?: unknown;
	limits?: unknown;
	safetyMaxima?: unknown;
	safety?: unknown;
	oracle?: unknown;
	targetPassCount?: unknown;
	floorPassCount?: unknown;
	achievedPassCount?: unknown;
	preflightReportDigest?: unknown;
	runtimeEvidenceDigest?: unknown;
	evidenceRefs?: unknown;
	preflightProof?: unknown;
	runtimeProof?: unknown;
	oracleProof?: unknown;
	/** Signed transition context used to verify benchmark evidence signatures. */
	oracleProofContext?: BenchmarkOracleProofContext;
}>;

/**
 * Validate a report only with its immutable manifest/lock and calibration
 * lineage. Invalid or incomplete reports remain unavailable and never receive
 * synthetic metrics.
 */
export function evaluateBenchmarkReport(request: unknown): BenchmarkReportResult {
	try {
		if (!request || typeof request !== "object" || Array.isArray(request)) {
			return { status: "unavailable", reason: "benchmark report request is missing" };
		}
		const value = request as Record<string, unknown>;
		const manifest = validateBenchmarkManifest(value.manifest);
		const lock = validateBenchmarkLock(value.lock);
		assertBenchmarkLockMatchesManifest(lock, manifest);
		const authority = benchmarkMetricAuthority(value);
		if (authority === undefined) return { status: "unavailable", reason: "benchmark report benchmark authority is missing" };
		const calibration = validateBenchmarkCalibration(value.calibration, { requireBenchmark: true });
		if (
			calibration.calibrationId !== manifest.calibrationId ||
			calibration.operationalLimitsDigest !== manifest.operationalLimitsDigest ||
			lock.calibrationId !== calibration.calibrationId ||
			lock.operationalLimitsDigest !== calibration.operationalLimitsDigest
		) {
			return { status: "unavailable", reason: "benchmark report lock calibration lineage is invalid" };
		}
		if (value.objective !== undefined && value.objective !== manifest.objective) {
			return { status: "unavailable", reason: "benchmark report objective does not match the benchmark manifest" };
		}
		if (
			(value.benchmarkId !== undefined && value.benchmarkId !== manifest.benchmarkId) ||
			(value.benchmarkLockDigest !== undefined && value.benchmarkLockDigest !== lock.lockDigest) ||
			(value.calibrationId !== undefined && value.calibrationId !== manifest.calibrationId) ||
			(value.calibrationDigest !== undefined && value.calibrationDigest !== calibration.calibrationDigest) ||
			!sameSeedSchedule(value.seedSchedule, lock.seedSchedule) ||
			(value.seeds !== undefined &&
				(lock.seeds === undefined ||
					!Array.isArray(value.seeds) ||
					!value.seeds.every((seed: unknown) => typeof seed === "string") ||
					!sameOrderedIds(value.seeds as string[], lock.seeds)))
		) {
			return { status: "unavailable", reason: "benchmark report immutable lineage is invalid" };
		}
		const denominator = benchmarkEligibleDenominator(manifest);
		if (value.eligibleDenominator !== denominator) {
			return { status: "unavailable", reason: "benchmark report denominator is not derived from the benchmark manifest" };
		}
		const targetFloor = calibrationTargetFloor(calibration, denominator);
		if (value.targetPassCount !== targetFloor.targetPassCount || value.floorPassCount !== targetFloor.floorPassCount) {
			return { status: "unavailable", reason: "benchmark report target/floor values are not calibrated" };
		}
		try {
			validateSignedBenchmarkEvidenceForReport(value, manifest, lock, authority.oracle);
		} catch (error) {
			return { status: "unavailable", reason: unavailableReason(error) };
		}
		if (
			!Array.isArray(value.eligibleChallengeIds) ||
			value.eligibleChallengeIds.length !== denominator ||
			!value.eligibleChallengeIds.every(id => typeof id === "string" && id.length > 0) ||
			!sameOrderedIds(value.eligibleChallengeIds as string[], authority.eligibleChallengeIds)
		) {
			return { status: "unavailable", reason: "benchmark report eligible challenge identity does not match the benchmark manifest" };
		}
		const eligibleChallengeIds = authority.eligibleChallengeIds;
		const report = validateMetricsReport(value.report);
		if (
			report.benchmarkId !== lock.benchmarkId ||
			report.benchmarkLockDigest !== lock.lockDigest ||
			report.calibrationDigest !== calibration.calibrationDigest ||
			report.eligibleChallengeIds === undefined ||
			!sameOrderedIds(report.eligibleChallengeIds, eligibleChallengeIds)
		) {
			return { status: "unavailable", reason: "benchmark report immutable lineage is invalid" };
		}
		if (
			!sameSeedSchedule(report.seedSchedule, lock.seedSchedule) ||
			(report.seeds !== undefined &&
				(lock.seeds === undefined || !sameOrderedIds(report.seeds, lock.seeds)))
		) {
			return { status: "unavailable", reason: "benchmark report seeds do not match the immutable lock" };
		}
		const runIdentity = new Set<string>();
		const runIds = new Set<string>();
		for (const run of report.runs) {
			if (runIds.has(run.runId)) return { status: "unavailable", reason: "benchmark report run IDs are duplicated" };
			runIds.add(run.runId);
			try {
				validateMetricRun(run, authority, calibration, true);
			} catch (error) {
				return { status: "unavailable", reason: unavailableReason(error) };
			}
			if (!eligibleChallengeIds.includes(run.challengeId)) {
				return { status: "unavailable", reason: "benchmark report run lineage is invalid" };
			}
			const identity = canonicalJson([run.challengeId, run.repeatIndex]);
			if (runIdentity.has(identity)) return { status: "unavailable", reason: "benchmark report repeats are duplicated" };
			runIdentity.add(identity);
		}
		const groups = challengeGroups(report.runs);
		if (groups.size !== denominator || eligibleChallengeIds.some(challengeId => !groups.has(challengeId))) {
			return { status: "unavailable", reason: "benchmark report does not cover every eligible challenge" };
		}
		for (const group of groups.values()) {
			const indices = group.map(run => run.repeatIndex);
			if (group.length !== 5 || new Set(indices).size !== 5 || ![0, 1, 2, 3, 4].every(index => indices.includes(index))) {
				return { status: "unavailable", reason: "benchmark report requires five unique repeats per eligible challenge" };
			}
		}
		const summary = summarizeMetricRuns(report.runs, {
			...value,
			manifest,
			lock,
			eligibleDenominator: denominator,
			eligibleChallengeIds,
			calibration,
			objective: manifest.objective,
		});
		const knownMetric = (metric: MetricValue<number>): number | null => metric.status === "known" ? metric.value : null;
		if (
			report.passAt1 !== knownMetric(summary.passAt1) ||
			report.passAt3 !== knownMetric(summary.passAt3) ||
			report.p50WallTimeMs !== knownMetric(summary.p50WallTimeMs) ||
			report.p95WallTimeMs !== knownMetric(summary.p95WallTimeMs) ||
			report.manualInterventionCount !== knownMetric(summary.manualInterventionCount) ||
			report.unknownCount !== summary.unknownRuns ||
			report.targetPassCount !== summary.targetPassCount ||
			report.floorPassCount !== summary.floorPassCount ||
			report.achievedPassCount !== summary.achievedPassCount
		) {
			return { status: "unavailable", reason: "benchmark report aggregates are not derived from validated runs" };
		}
		const expectedAggregates = new Map<string, { numerator: number; denominator: number; excludedCount: number; unknownCount: number }>();
		for (const challengeId of eligibleChallengeIds) {
			const category = authority.categories.get(challengeId);
			const group = groups.get(challengeId);
			if (category === undefined || group === undefined) return { status: "unavailable", reason: "benchmark report category lineage is incomplete" };
			const aggregate = expectedAggregates.get(category) ?? { numerator: 0, denominator: 0, excludedCount: 0, unknownCount: 0 };
			aggregate.denominator += 1;
			if (group.some(run => run.outcome === "unknown")) aggregate.unknownCount += 1;
			else if (group.some(run => run.outcome === "pass" && run.validatedSolve)) aggregate.numerator += 1;
			expectedAggregates.set(category, aggregate);
		}
		if (
			report.categoryAggregates.length !== expectedAggregates.size ||
			report.categoryAggregates.some(aggregate => {
				const expected = expectedAggregates.get(aggregate.category);
				return expected === undefined ||
					aggregate.numerator !== expected.numerator ||
					aggregate.denominator !== expected.denominator ||
					aggregate.excludedCount !== expected.excludedCount ||
					aggregate.unknownCount !== expected.unknownCount;
			})
		) {
			return { status: "unavailable", reason: "benchmark report category aggregates are not derived from validated runs" };
		}
		const { fingerprint, ...unsignedReport } = report;
		if (metricsFingerprint(unsignedReport) !== fingerprint) {
			return { status: "unavailable", reason: "benchmark report fingerprint is invalid" };
		}
		const expectedCategoryDenominators = new Map<string, number>();
		for (const challengeId of eligibleChallengeIds) {
			const category = authority.categories.get(challengeId);
			if (category === undefined) return { status: "unavailable", reason: "benchmark report category lineage is incomplete" };
			expectedCategoryDenominators.set(category, (expectedCategoryDenominators.get(category) ?? 0) + 1);
		}
		if (
			report.categoryAggregates.length !== expectedCategoryDenominators.size ||
			new Set(report.categoryAggregates.map(aggregate => aggregate.category)).size !== report.categoryAggregates.length ||
			report.categoryAggregates.some(aggregate => aggregate.denominator !== expectedCategoryDenominators.get(aggregate.category))
		) {
			return { status: "unavailable", reason: "benchmark report category lineage is invalid" };
		}
		const aggregateDenominator = report.categoryAggregates.reduce((sum, aggregate) => sum + aggregate.denominator, 0);
		if (aggregateDenominator !== denominator || report.categoryAggregates.some(aggregate => aggregate.numerator + aggregate.excludedCount + aggregate.unknownCount > aggregate.denominator)) {
			return { status: "unavailable", reason: "benchmark report category denominator is invalid" };
		}
		return Object.freeze({ status: "ready", report });
	} catch (error) {
		return { status: "unavailable", reason: unavailableReason(error) };
	}
}

export function validateBenchmarkReport(request: BenchmarkReportRequest): MetricsReportV1 {
	const result = evaluateBenchmarkReport(request);
	if (result.status !== "ready") rejectMetric("benchmark_provenance_missing", result.reason);
	return result.report;
}

export const buildBenchmarkResult = evaluateBenchmarkResult;
export const buildBenchmarkReport = evaluateBenchmarkReport;

function validateFixtureRun(run: MetricFixtureRun): void {
	const outcomes: MetricOutcome[] = ["pass", "fail", "timeout", "crash", "leak", "invalid", "unknown"];
	if (!outcomes.includes(run.outcome)) throw new CtfError("invalid_manifest", "metric fixture outcome is invalid");
	if (!run.runId || !run.challengeId || !/^sha256:[a-f0-9]{64}$/.test(run.seed) || !Number.isInteger(run.repeatIndex) || run.repeatIndex < 0 || run.repeatIndex > 4 || !Number.isInteger(run.wallTimeMs) || run.wallTimeMs <= 0 || typeof run.validatedSolve !== "boolean") {
		throw new CtfError("invalid_manifest", "metric fixture run is invalid");
	}
}
export type FixtureMetricSummary = Readonly<{
	fixture: MetricFixture;
	passAt1: MetricValue<number>;
	passAt3: MetricValue<number>;
	failureRuns: number;
	unknownRuns: number;
	p50WallTimeMs: MetricValue<number>;
	p95WallTimeMs: MetricValue<number>;
}>;

export function fixturePassAtK(runs: readonly MetricFixtureRun[], k: number): MetricValue<number> {
	if (runs.length === 0) return unknown("no fixture runs");
	if (runs.some(run => run.outcome === "unknown")) return unknown("fixture contains unknown outcomes");
	const successes = runs.filter(run => run.outcome === "pass" && run.validatedSolve).length;
	return known(passAtK(runs.length, successes, k));
}

export function summarizeMetricFixture(value: unknown): FixtureMetricSummary {
	const fixture = validateMetricFixture(value);
	const groups = new Map<string, MetricFixtureRun[]>();
	for (const run of fixture.runs) {
		const group = groups.get(run.challengeId);
		if (group) group.push(run);
		else groups.set(run.challengeId, [run]);
	}
	const passValues = [...groups.values()].map(group => fixturePassAtK(group, 1)).filter((metric): metric is { status: "known"; value: number } => metric.status === "known").map(metric => metric.value);
	const pass3Values = [...groups.values()].map(group => fixturePassAtK(group, 3)).filter((metric): metric is { status: "known"; value: number } => metric.status === "known").map(metric => metric.value);
	const wallTimes = fixture.runs.filter(run => run.outcome !== "unknown").map(run => run.wallTimeMs).sort((a, b) => a - b);
	const average = (values: readonly number[]): MetricValue<number> => values.length === 0 ? unknown("no fully observed fixture challenge") : known(values.reduce((sum, value) => sum + value, 0) / values.length);
	return {
		fixture,
		passAt1: average(passValues),
		passAt3: average(pass3Values),
		failureRuns: fixture.runs.filter(run => run.outcome !== "pass" && run.outcome !== "unknown").length,
		unknownRuns: fixture.runs.filter(run => run.outcome === "unknown").length,
		p50WallTimeMs: wallTimes.length === 0 ? unknown("no observed wall times") : known(nearestRank(wallTimes, 0.5) as number),
		p95WallTimeMs: wallTimes.length === 0 ? unknown("no observed wall times") : known(nearestRank(wallTimes, 0.95) as number),
	};
}

export function metricFixtureDigest(fixture: Omit<MetricFixture, "fixtureDigest"> | MetricFixture): Digest {
	return canonicalDigest(fixture, ["fixtureDigest"]);
}

/** Validate fixture data without executing any challenge artifact. */
export function validateMetricFixture(value: unknown): MetricFixture {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new CtfError("benchmark_provenance_missing", "metric fixture is missing");
	const fixture = value as Partial<MetricFixture>;
	if (fixture.schemaVersion !== "gjc-ctf-metric-fixture-1" || typeof fixture.fixtureId !== "string" || !Array.isArray(fixture.runs) || typeof fixture.benchmarkLockDigest !== "string" || typeof fixture.fixtureDigest !== "string") {
		throw new CtfError("benchmark_provenance_missing", "metric fixture metadata is invalid");
	}
	if (!/^[a-f0-9]{64}$/.test(fixture.benchmarkLockDigest) || !/^[a-f0-9]{64}$/.test(fixture.fixtureDigest)) throw new CtfError("benchmark_provenance_missing", "metric fixture digest is invalid");
	const runIds = new Set<string>();
	for (const run of fixture.runs) {
		validateFixtureRun(run);
		if (runIds.has(run.runId)) throw new CtfError("invalid_manifest", `duplicate metric fixture run: ${run.runId}`);
		runIds.add(run.runId);
	}
	const expected = metricFixtureDigest(fixture as MetricFixture);
	if (expected !== fixture.fixtureDigest) throw new CtfError("digest_mismatch", "metric fixture digest mismatch");
	return { schemaVersion: fixture.schemaVersion, fixtureId: fixture.fixtureId, benchmarkLockDigest: fixture.benchmarkLockDigest, runs: fixture.runs.map(run => ({ ...run })), fixtureDigest: fixture.fixtureDigest };
}

export function fixtureRunsToMetricRecords(runs: readonly MetricRunRecord[]): readonly MetricRunRecord[] {
	for (const run of runs) assertRunShape(run);
	return runs.map(run => ({ ...run }));
}

export const computeMetricSummary = summarizeMetricRuns;
export const deterministicMetrics = summarizeMetricRuns;
export const evaluateBenchmarkMetrics = evaluateBenchmarkResult;
export const validateBenchmarkMetricsReport = validateBenchmarkReport;
