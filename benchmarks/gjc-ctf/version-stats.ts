import * as z from "zod/v4";
import { DigestSchema } from "../../packages/coding-agent/src/ctf/contracts/common";
import { canonicalDigest, canonicalJson, digestsEqual, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import { nearestRank, passAtK, validateMetricsReport, type MetricRunRecord, type MetricsReportV1 } from "../../packages/coding-agent/src/ctf/contracts/metrics";
import { validateBenchmarkLock, validateBenchmarkManifest } from "../../packages/coding-agent/src/ctf/contracts/benchmark";
import { validateBenchmarkCalibration } from "../../packages/coding-agent/src/ctf/runtime/policy";
import { evaluateBenchmarkReport, type BenchmarkReportRequest } from "./metrics";

const UnknownValueSchema = z.object({ status: z.literal("unknown"), reason: z.string().min(1) }).strict();
const KnownValueSchema = <T extends z.ZodType>(value: T) => z.object({ status: z.literal("known"), value }).strict();
export const VersionStatValueSchema = <T extends z.ZodType>(value: T) => z.union([KnownValueSchema(value), UnknownValueSchema]);
export type VersionStatValue<T> = { status: "known"; value: T } | { status: "unknown"; reason: string };

/** Immutable provenance required to identify a benchmark version. */
export const VersionStatsIdentitySchema = z.object({
	harnessDigest: DigestSchema,
	effectiveSkillDigest: DigestSchema,
	modelFingerprint: DigestSchema,
	backendFingerprint: DigestSchema,
	toolchainDigest: DigestSchema,
	corpusDigest: DigestSchema,
	calibrationDigest: DigestSchema,
	benchmarkLockDigest: DigestSchema,
}).strict();
export type VersionStatsIdentity = z.infer<typeof VersionStatsIdentitySchema>;

const ChallengeStatusSchema = z.enum(["solved", "unsolved", "unknown"]);
const CategoryStatsSchema = z.object({
	category: z.string().min(1),
	observedChallengeCount: z.number().int().nonnegative(),
	eligibleDenominator: VersionStatValueSchema(z.number().int().positive()),
	independentlyVerifiedSolveCount: z.number().int().nonnegative(),
	independentlyVerifiedSolveRate: VersionStatValueSchema(z.number().min(0).max(1)),
	passAt1: VersionStatValueSchema(z.number().min(0).max(1)),
	passAt3: VersionStatValueSchema(z.number().min(0).max(1)),
}).strict();
export type CategoryStats = z.infer<typeof CategoryStatsSchema>;

export const VersionStatsV1Schema = z.object({
	schemaVersion: z.literal("gjc-ctf-version-stats-1"),
	identity: VersionStatsIdentitySchema,
	identityDigest: DigestSchema,
	reportFingerprint: DigestSchema,
	eligibleDenominator: z.number().int().positive(),
	independentlyVerifiedSolveCount: z.number().int().nonnegative(),
	independentlyVerifiedSolveRate: VersionStatValueSchema(z.number().min(0).max(1)),
	passAt1: VersionStatValueSchema(z.number().min(0).max(1)),
	passAt3: VersionStatValueSchema(z.number().min(0).max(1)),
	firstValidLatencyMs: VersionStatValueSchema(z.number().int().positive()),
	p50RuntimeMs: VersionStatValueSchema(z.number().int().positive()),
	p95RuntimeMs: VersionStatValueSchema(z.number().int().positive()),
	inputTokens: z.number().int().nonnegative(),
	outputTokens: z.number().int().nonnegative(),
	cacheTokens: z.number().int().nonnegative(),
	toolCalls: z.number().int().nonnegative(),
	knownCostCents: z.number().nonnegative(),
	unknownCostCount: z.number().int().nonnegative(),
	timeoutCount: z.number().int().nonnegative(),
	crashCount: z.number().int().nonnegative(),
	leakCount: z.number().int().nonnegative(),
	invalidCount: z.number().int().nonnegative(),
	unknownCount: z.number().int().nonnegative(),
	failureCount: z.number().int().nonnegative(),
	categoryBreakdown: z.array(CategoryStatsSchema),
	challengeStatus: z.record(z.string().min(1), ChallengeStatusSchema),
	confidenceStatus: z.enum(["complete", "partial", "unknown"]),
	holdoutStatus: z.literal("unknown"),
	fingerprint: DigestSchema,
}).strict();
export type VersionStatsV1 = z.infer<typeof VersionStatsV1Schema>;

type AuthorizedVersionStatsInput = { identity: VersionStatsIdentity; report: MetricsReportV1 };
export type VersionStatsRequest = BenchmarkReportRequest & Readonly<{ identity: unknown }>;
export type VersionStatsResult =
	| Readonly<{ status: "ready"; stats: VersionStatsV1 }>
	| Readonly<{ status: "unavailable"; reason: string }>;

function known<T>(value: T): VersionStatValue<T> { return { status: "known", value }; }
function unknown<T>(reason: string): VersionStatValue<T> { return { status: "unknown", reason }; }
function average(values: readonly number[], reason: string): VersionStatValue<number> {
	return values.length === 0 ? unknown(reason) : known(values.reduce((total, value) => total + value, 0) / values.length);
}
function challengeRuns(report: MetricsReportV1): Map<string, MetricRunRecord[]> {
	const grouped = new Map<string, MetricRunRecord[]>();
	for (const run of report.runs) grouped.set(run.challengeId, [...(grouped.get(run.challengeId) ?? []), run]);
	return grouped;
}
function statusForRuns(runs: readonly MetricRunRecord[] | undefined): "solved" | "unsolved" | "unknown" {
	if (runs === undefined || runs.length === 0 || runs.some(run => run.outcome === "unknown")) return "unknown";
	return runs.some(run => run.outcome === "pass" && run.validatedSolve) ? "solved" : "unsolved";
}
function passForRuns(runs: readonly MetricRunRecord[], k: number): VersionStatValue<number> {
	if (runs.length === 0) return unknown("no runs observed");
	if (runs.some(run => run.outcome === "unknown")) return unknown("one or more outcomes are unknown");
	return known(passAtK(runs.length, runs.filter(run => run.outcome === "pass" && run.validatedSolve).length, k));
}
function assertIdentityMatchesReport(identity: VersionStatsIdentity, report: MetricsReportV1): void {
	if (report.calibrationDigest === undefined || report.eligibleChallengeIds === undefined)
		throw new CtfError("missing_provenance", "version statistics require calibrated eligible metrics reports");
	const mismatch = report.benchmarkLockDigest !== identity.benchmarkLockDigest || report.calibrationDigest !== identity.calibrationDigest || report.runs.some(run => run.effectiveSkillDigest !== identity.effectiveSkillDigest || run.modelFingerprint !== identity.modelFingerprint || run.backendFingerprint !== identity.backendFingerprint || run.benchmarkLockDigest !== identity.benchmarkLockDigest || run.calibrationDigest !== identity.calibrationDigest);
	if (mismatch) throw new CtfError("benchmark_lock_mismatch", "version statistics identity does not match report run identities");
}

/** Canonical digest for a provenance identity. */
export function versionStatsIdentityDigest(identity: VersionStatsIdentity): Digest {
	return canonicalDigest(VersionStatsIdentitySchema.parse(identity));
}
export function versionStatsFingerprint(value: Omit<VersionStatsV1, "fingerprint">): Digest { return canonicalDigest(value); }

/** Recompute statistics only after benchmark-report authorization has verified every run. */
function computeAuthorizedVersionStats(input: AuthorizedVersionStatsInput): VersionStatsV1 {
	const report = validateMetricsReport(input.report);
	const identity = VersionStatsIdentitySchema.parse(input.identity);
	assertIdentityMatchesReport(identity, report);
	const eligible = report.eligibleChallengeIds as readonly string[];
	const groups = challengeRuns(report);
	const challengeStatus = Object.fromEntries(eligible.slice().sort().map(challengeId => [challengeId, statusForRuns(groups.get(challengeId))]));
	const observed = eligible.filter(challengeId => groups.has(challengeId));
	const complete = observed.length === eligible.length && report.runs.every(run => run.outcome !== "unknown");
	const solveCount = Object.values(challengeStatus).filter(status => status === "solved").length;
	const challengePass1 = observed.map(challengeId => passForRuns(groups.get(challengeId)!, 1));
	const challengePass3 = observed.map(challengeId => passForRuns(groups.get(challengeId)!, 3));
	const passAverage = (values: readonly VersionStatValue<number>[], label: string): VersionStatValue<number> => !complete ? unknown("eligible evidence is incomplete") : average(values.filter(value => value.status === "known").map(value => (value as { value: number }).value), `no ${label} evidence`);
	const categories = new Map<string, string[]>();
	for (const challengeId of observed) {
		const category = groups.get(challengeId)![0].category;
		categories.set(category, [...(categories.get(category) ?? []), challengeId]);
	}
	const categoryBreakdown = [...categories.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([category, challengeIds]) => {
		const categoryComplete = complete;
		const statuses = challengeIds.map(challengeId => challengeStatus[challengeId]);
		const one = challengeIds.map(challengeId => passForRuns(groups.get(challengeId)!, 1));
		const three = challengeIds.map(challengeId => passForRuns(groups.get(challengeId)!, 3));
		return { category, observedChallengeCount: challengeIds.length, eligibleDenominator: categoryComplete ? known(challengeIds.length) : unknown("unobserved eligible challenges have no category evidence"), independentlyVerifiedSolveCount: statuses.filter(status => status === "solved").length, independentlyVerifiedSolveRate: categoryComplete ? known(statuses.filter(status => status === "solved").length / challengeIds.length) : unknown("eligible evidence is incomplete"), passAt1: categoryComplete ? average(one.filter(value => value.status === "known").map(value => (value as { value: number }).value), "pass@1") : unknown("eligible evidence is incomplete"), passAt3: categoryComplete ? average(three.filter(value => value.status === "known").map(value => (value as { value: number }).value), "pass@3") : unknown("eligible evidence is incomplete") };
	});
	const knownRuns = report.runs.filter(run => run.outcome !== "unknown");
	const firstValid = report.runs.filter(run => run.outcome === "pass" && run.validatedSolve && run.firstValidTimeMs !== null).map(run => run.firstValidTimeMs as number);
	const result: Omit<VersionStatsV1, "fingerprint"> = {
		schemaVersion: "gjc-ctf-version-stats-1", identity, identityDigest: versionStatsIdentityDigest(identity), reportFingerprint: report.fingerprint,
		eligibleDenominator: eligible.length, independentlyVerifiedSolveCount: solveCount,
		independentlyVerifiedSolveRate: complete ? known(solveCount / eligible.length) : unknown("eligible evidence is incomplete"), passAt1: passAverage(challengePass1, "pass@1"), passAt3: passAverage(challengePass3, "pass@3"),
		firstValidLatencyMs: firstValid.length === 0 ? unknown("no independently verified solve latency") : known(nearestRank(firstValid, 0.5)!),
		p50RuntimeMs: knownRuns.length === 0 ? unknown("no known runtime evidence") : known(nearestRank(knownRuns.map(run => run.wallTimeMs), 0.5)!), p95RuntimeMs: knownRuns.length === 0 ? unknown("no known runtime evidence") : known(nearestRank(knownRuns.map(run => run.wallTimeMs), 0.95)!),
		inputTokens: report.runs.reduce((sum, run) => sum + run.inputTokens, 0), outputTokens: report.runs.reduce((sum, run) => sum + run.outputTokens, 0), cacheTokens: report.runs.reduce((sum, run) => sum + run.cacheTokens, 0), toolCalls: report.runs.reduce((sum, run) => sum + run.toolCalls, 0), knownCostCents: report.runs.reduce((sum, run) => sum + (run.cost.status === "known" ? run.cost.cents : 0), 0), unknownCostCount: report.runs.filter(run => run.cost.status === "unknown").length,
		timeoutCount: report.runs.filter(run => run.outcome === "timeout").length, crashCount: report.runs.filter(run => run.outcome === "crash").length, leakCount: report.runs.filter(run => run.outcome === "leak").length, invalidCount: report.runs.filter(run => run.outcome === "invalid").length, unknownCount: report.runs.filter(run => run.outcome === "unknown").length, failureCount: report.runs.filter(run => run.outcome === "fail").length,
		categoryBreakdown, challengeStatus, confidenceStatus: complete ? "complete" : observed.length === 0 ? "unknown" : "partial", holdoutStatus: "unknown",
	};
	return { ...result, fingerprint: versionStatsFingerprint(result) };
}
function assertProductionIdentity(identity: VersionStatsIdentity, request: Record<string, unknown>, report: MetricsReportV1): void {
	const manifest = validateBenchmarkManifest(request.manifest);
	const lock = validateBenchmarkLock(request.lock);
	const calibration = validateBenchmarkCalibration(request.calibration, { requireBenchmark: true });
	if (
		identity.corpusDigest !== lock.corpusDigest ||
		identity.modelFingerprint !== lock.modelConfigDigest ||
		identity.backendFingerprint !== lock.backendPolicyDigest ||
		identity.calibrationDigest !== calibration.calibrationDigest ||
		identity.benchmarkLockDigest !== lock.lockDigest ||
		identity.harnessDigest !== manifest.skill.loaderDigest ||
		identity.toolchainDigest !== manifest.skill.buildDigest ||
		identity.effectiveSkillDigest !== canonicalDigest(manifest.skill) ||
		report.runs.length === 0 ||
		report.runs.some(run => run.effectiveSkillDigest !== identity.effectiveSkillDigest)
	) {
		throw new CtfError("benchmark_lock_mismatch", "version statistics identity is not bound to authorized benchmark authority");
	}
}
export function computeVersionStats(request: unknown): VersionStatsResult {
	if (!request || typeof request !== "object" || Array.isArray(request)) {
		return { status: "unavailable", reason: "version statistics request is missing" };
	}
	const evaluated = evaluateBenchmarkReport(request);
	if (evaluated.status !== "ready") return evaluated;
	const identity = VersionStatsIdentitySchema.safeParse((request as Record<string, unknown>).identity);
	if (!identity.success) return { status: "unavailable", reason: "version statistics identity is invalid" };
	try {
		assertProductionIdentity(identity.data, request as Record<string, unknown>, evaluated.report);
		return { status: "ready", stats: computeAuthorizedVersionStats({ identity: identity.data, report: evaluated.report }) };
	} catch (error) {
		return { status: "unavailable", reason: error instanceof Error ? error.message : "version statistics computation failed" };
	}
}

/** Parse and verify a self-sealed statistics artifact; this verifies integrity, not benchmark authorization. */
export function validateVersionStats(value: unknown): VersionStatsV1 {
	const parsed = VersionStatsV1Schema.safeParse(value);
	if (!parsed.success) throw new CtfError("invalid_manifest", "version statistics are invalid", { details: { issues: parsed.error.issues } });
	const stats = parsed.data;
	const { fingerprint, ...unsigned } = stats;
	if (!digestsEqual(versionStatsIdentityDigest(stats.identity), stats.identityDigest) || !digestsEqual(versionStatsFingerprint(unsigned), fingerprint)) throw new CtfError("digest_mismatch", "version statistics fingerprint mismatch");
	return stats;
}
export const parseVersionStats = validateVersionStats;
export function versionStatsJson(value: unknown): string { return canonicalJson(validateVersionStats(value)); }
function delta(baseline: number, candidate: number): VersionStatValue<number> {
	return known(candidate - baseline);
}
function metricDelta(baseline: VersionStatValue<number>, candidate: VersionStatValue<number>): VersionStatValue<number> {
	if (baseline.status !== "known" || candidate.status !== "known") {
		return unknown("baseline or candidate metric is unknown");
	}
	return known(candidate.value - baseline.value);
}
export type VersionStatsDeltas = Readonly<{
	independentlyVerifiedSolveCount: VersionStatValue<number>;
	independentlyVerifiedSolveRate: VersionStatValue<number>;
	passAt1: VersionStatValue<number>;
	passAt3: VersionStatValue<number>;
	firstValidLatencyMs: VersionStatValue<number>;
	p50RuntimeMs: VersionStatValue<number>;
	p95RuntimeMs: VersionStatValue<number>;
	inputTokens: VersionStatValue<number>;
	outputTokens: VersionStatValue<number>;
	cacheTokens: VersionStatValue<number>;
	toolCalls: VersionStatValue<number>;
	knownCostCents: VersionStatValue<number>;
	unknownCostCount: VersionStatValue<number>;
	timeoutCount: VersionStatValue<number>;
	crashCount: VersionStatValue<number>;
	leakCount: VersionStatValue<number>;
	invalidCount: VersionStatValue<number>;
	unknownCount: VersionStatValue<number>;
	failureCount: VersionStatValue<number>;
}>;
export type VersionStatusTransitions = Readonly<{
	confidenceStatus: Readonly<{ baseline: VersionStatsV1["confidenceStatus"]; candidate: VersionStatsV1["confidenceStatus"] }>;
	holdoutStatus: Readonly<{ baseline: VersionStatsV1["holdoutStatus"]; candidate: VersionStatsV1["holdoutStatus"] }>;
}>;
function comparisonDeltas(baseline: VersionStatsV1, candidate: VersionStatsV1): VersionStatsDeltas {
	return {
		independentlyVerifiedSolveCount: delta(baseline.independentlyVerifiedSolveCount, candidate.independentlyVerifiedSolveCount),
		independentlyVerifiedSolveRate: metricDelta(baseline.independentlyVerifiedSolveRate, candidate.independentlyVerifiedSolveRate),
		passAt1: metricDelta(baseline.passAt1, candidate.passAt1),
		passAt3: metricDelta(baseline.passAt3, candidate.passAt3),
		firstValidLatencyMs: metricDelta(baseline.firstValidLatencyMs, candidate.firstValidLatencyMs),
		p50RuntimeMs: metricDelta(baseline.p50RuntimeMs, candidate.p50RuntimeMs),
		p95RuntimeMs: metricDelta(baseline.p95RuntimeMs, candidate.p95RuntimeMs),
		inputTokens: delta(baseline.inputTokens, candidate.inputTokens),
		outputTokens: delta(baseline.outputTokens, candidate.outputTokens),
		cacheTokens: delta(baseline.cacheTokens, candidate.cacheTokens),
		toolCalls: delta(baseline.toolCalls, candidate.toolCalls),
		knownCostCents: delta(baseline.knownCostCents, candidate.knownCostCents),
		unknownCostCount: delta(baseline.unknownCostCount, candidate.unknownCostCount),
		timeoutCount: delta(baseline.timeoutCount, candidate.timeoutCount),
		crashCount: delta(baseline.crashCount, candidate.crashCount),
		leakCount: delta(baseline.leakCount, candidate.leakCount),
		invalidCount: delta(baseline.invalidCount, candidate.invalidCount),
		unknownCount: delta(baseline.unknownCount, candidate.unknownCount),
		failureCount: delta(baseline.failureCount, candidate.failureCount),
	};
}

type ComparisonIndeterminacy = "partial_confidence" | "solved_to_unknown";
type AuthorizedVersionComparison =
	| { status: "comparable"; baselineIdentityDigest: Digest; candidateIdentityDigest: Digest; regressions: readonly string[]; deltas: VersionStatsDeltas; statusTransitions: VersionStatusTransitions }
	| { status: "indeterminate"; reasons: readonly ComparisonIndeterminacy[]; regressions: readonly string[]; baselineIdentityDigest: Digest; candidateIdentityDigest: Digest; statusTransitions: VersionStatusTransitions }
	| { status: "incomparable"; reasons: readonly ("corpusDigest" | "calibrationDigest" | "benchmarkLockDigest")[] };
export type VersionComparison =
	| AuthorizedVersionComparison
	| Readonly<{ status: "unavailable"; reason: string }>;
function compareAuthorizedVersionStats(baselineValue: unknown, candidateValue: unknown): AuthorizedVersionComparison {
	const baseline = validateVersionStats(baselineValue);
	const candidate = validateVersionStats(candidateValue);
	const reasons = (["corpusDigest", "calibrationDigest", "benchmarkLockDigest"] as const).filter(field => baseline.identity[field] !== candidate.identity[field]);
	if (reasons.length > 0) return { status: "incomparable", reasons };
	const regressions = Object.keys(baseline.challengeStatus).filter(challengeId => baseline.challengeStatus[challengeId] === "solved" && candidate.challengeStatus[challengeId] === "unsolved").sort();
	const statusTransitions = {
		confidenceStatus: { baseline: baseline.confidenceStatus, candidate: candidate.confidenceStatus },
		holdoutStatus: { baseline: baseline.holdoutStatus, candidate: candidate.holdoutStatus },
	};
	const indeterminate = [
		...(baseline.confidenceStatus !== "complete" || candidate.confidenceStatus !== "complete" ? ["partial_confidence" as const] : []),
		...(Object.keys(baseline.challengeStatus).some(challengeId => baseline.challengeStatus[challengeId] === "solved" && candidate.challengeStatus[challengeId] === "unknown") ? ["solved_to_unknown" as const] : []),
	];
	if (indeterminate.length > 0) {
		return { status: "indeterminate", reasons: indeterminate, regressions, baselineIdentityDigest: baseline.identityDigest, candidateIdentityDigest: candidate.identityDigest, statusTransitions };
	}
	return {
		status: "comparable",
		baselineIdentityDigest: baseline.identityDigest,
		candidateIdentityDigest: candidate.identityDigest,
		regressions,
		deltas: comparisonDeltas(baseline, candidate),
		statusTransitions,
	};
}
export function compareVersionStats(baselineRequest: unknown, candidateRequest: unknown): VersionComparison {
	const baseline = computeVersionStats(baselineRequest);
	if (baseline.status !== "ready") return { status: "unavailable", reason: `baseline: ${baseline.reason}` };
	const candidate = computeVersionStats(candidateRequest);
	if (candidate.status !== "ready") return { status: "unavailable", reason: `candidate: ${candidate.reason}` };
	return compareAuthorizedVersionStats(baseline.stats, candidate.stats);
}
/** @internal Test-only authority-bypassing aggregation and comparison seams. */
export const __versionStatsTestOnly = Object.freeze({ computeAuthorizedVersionStats, compareAuthorizedVersionStats });
