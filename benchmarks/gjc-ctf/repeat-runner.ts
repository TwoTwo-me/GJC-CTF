import {
	assertBenchmarkLockMatchesManifest,
	type BenchmarkLockV1,
	type BenchmarkManifestV1,
	type BenchmarkSeedSchedule,
	validateBenchmarkLock,
	validateBenchmarkManifest,
} from "../../packages/coding-agent/src/ctf/contracts/benchmark";
import { canonicalDigest, canonicalJson, isDigest, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import { validateBenchmarkCalibration, type BenchmarkCalibrationPolicy } from "../../packages/coding-agent/src/ctf/runtime/policy";
import { metricFixtureDigest, validateMetricFixture, type MetricFixture } from "./metrics";
import type { MetricOutcome } from "../../packages/coding-agent/src/ctf/contracts/metrics";

export type FixtureRepeatLineage = Readonly<{
	backendPolicyDigest: Digest;
	oracleRegistryDigest: Digest;
	preflightDigest: Digest;
	effectiveSkillDigest: Digest;
}>;

export type RepeatRunnerRequest = Readonly<{
	manifest: unknown;
	lock: unknown;
	calibration: unknown;
	fixture: unknown;
	lineage: FixtureRepeatLineage;
	/** Local fixtures never become scored, even when an oracle is available. */
	oracleAdmission: "verified" | "unavailable";
}>;

export type RepeatRunResult = Readonly<{
	challengeId: string;
	repeatIndex: number;
	seed: `sha256:${string}`;
	outcome: MetricOutcome;
	validatedSolve: boolean;
}>;

export type NonScoredRepeatReport = Readonly<{
	schemaVersion: "gjc-ctf-repeat-report-1";
	status: "ready";
	scored: false;
	reason: "local_fixture";
	benchmarkId: string;
	benchmarkLockDigest: Digest;
	calibrationDigest: Digest;
	seedSchedule: BenchmarkSeedSchedule;
	lineage: FixtureRepeatLineage;
	oracleAdmission: "verified" | "unavailable";
	runs: readonly RepeatRunResult[];
	counts: Readonly<{ pass: number; fail: number; unknown: number }>;
	reportDigest: Digest;
}>;

export type RepeatRunnerResult =
	| Readonly<{ status: "ready"; report: NonScoredRepeatReport }>
	| Readonly<{ status: "unavailable"; reason: string }>;

function unavailable(error: unknown): RepeatRunnerResult {
	return { status: "unavailable", reason: error instanceof Error ? error.message : "repeat fixture is unavailable" };
}

function requireDigest(value: unknown, label: string): Digest {
	if (!isDigest(value)) throw new CtfError("benchmark_provenance_missing", `${label} is missing or invalid`);
	return value;
}

function validateLineage(lineage: FixtureRepeatLineage, manifest: BenchmarkManifestV1, lock: BenchmarkLockV1, calibration: BenchmarkCalibrationPolicy): void {
	if (lineage.backendPolicyDigest !== manifest.backendPolicyDigest || lineage.backendPolicyDigest !== lock.backendPolicyDigest) {
		throw new CtfError("benchmark_lock_mismatch", "repeat backend lineage does not match the immutable lock");
	}
	if (lineage.oracleRegistryDigest !== manifest.oracleRegistryDigest || lineage.oracleRegistryDigest !== lock.oracleRegistryDigest) {
		throw new CtfError("oracle_integrity_error", "repeat oracle lineage does not match the immutable lock");
	}
	if (lineage.effectiveSkillDigest !== canonicalDigest(manifest.skill) || canonicalDigest(lock.skill) !== lineage.effectiveSkillDigest) {
		throw new CtfError("benchmark_lock_mismatch", "repeat skill lineage does not match the immutable lock");
	}
	if (calibration.calibrationId !== manifest.calibrationId || calibration.operationalLimitsDigest !== manifest.operationalLimitsDigest || lock.calibrationId !== calibration.calibrationId) {
		throw new CtfError("uncalibrated_limits", "repeat calibration lineage does not match the immutable lock");
	}
	requireDigest(lineage.preflightDigest, "repeat preflight lineage");
}

function validatedRuns(manifest: BenchmarkManifestV1, lock: BenchmarkLockV1, fixture: MetricFixture): readonly RepeatRunResult[] {
	if (fixture.benchmarkLockDigest !== lock.lockDigest || fixture.fixtureDigest !== metricFixtureDigest(fixture)) {
		throw new CtfError("benchmark_lock_mismatch", "fixture is not content-addressed to the benchmark lock");
	}
	const eligible = manifest.corpus.filter(entry => !manifest.holdoutChallengeIds.includes(entry.challengeId)).map(entry => entry.challengeId);
	const schedule = manifest.seedSchedule;
	if (schedule === undefined || lock.seedSchedule === undefined) throw new CtfError("benchmark_lock_mismatch", "repeat runner requires a canonical seed schedule");
	const expected = new Map<string, Set<number>>();
	for (const challengeId of eligible) expected.set(challengeId, new Set());
	const runs: RepeatRunResult[] = [];
	for (const run of fixture.runs) {
		const seeds = schedule[run.challengeId];
		if (seeds === undefined || !expected.has(run.challengeId) || run.seed !== seeds[run.repeatIndex] || expected.get(run.challengeId)?.has(run.repeatIndex)) {
			throw new CtfError("benchmark_lock_mismatch", "fixture repeat identity does not match the canonical seed schedule");
		}
		expected.get(run.challengeId)?.add(run.repeatIndex);
		runs.push({
			challengeId: run.challengeId,
			repeatIndex: run.repeatIndex,
			seed: run.seed,
			outcome: run.outcome,
			validatedSolve: false,
		});
	}
	for (const [challengeId, indices] of expected) if (indices.size !== 5) throw new CtfError("benchmark_provenance_missing", `fixture does not contain five repeats for ${challengeId}`);
	return runs.sort((left, right) => canonicalJson([left.challengeId, left.repeatIndex]).localeCompare(canonicalJson([right.challengeId, right.repeatIndex])));
}

export function runDeterministicFixtureBenchmark(request: RepeatRunnerRequest): RepeatRunnerResult {
	try {
		const manifest = validateBenchmarkManifest(request.manifest);
		const lock = validateBenchmarkLock(request.lock);
		assertBenchmarkLockMatchesManifest(lock, manifest);
		const calibration = validateBenchmarkCalibration(request.calibration, { requireBenchmark: true });
		validateLineage(request.lineage, manifest, lock, calibration);
		const lockDigest = requireDigest(lock.lockDigest, "benchmark lock digest");
		const fixture = validateMetricFixture(request.fixture);
		const runs = validatedRuns(manifest, lock, fixture);
		const schedule = manifest.seedSchedule;
		if (schedule === undefined) throw new CtfError("benchmark_lock_mismatch", "repeat runner requires a canonical seed schedule");
		const counts = {
			pass: runs.filter(run => run.outcome === "pass" && run.validatedSolve).length,
			fail: runs.filter(run => run.outcome === "fail").length,
			unknown: runs.filter(run => run.outcome === "unknown").length,
		};
		const unsigned = {
			schemaVersion: "gjc-ctf-repeat-report-1" as const,
			status: "ready" as const,
			scored: false as const,
			reason: "local_fixture" as const,
			benchmarkId: manifest.benchmarkId,
			benchmarkLockDigest: lockDigest,
			calibrationDigest: calibration.calibrationDigest,
			seedSchedule: schedule as BenchmarkSeedSchedule,
			lineage: request.lineage,
			oracleAdmission: request.oracleAdmission,
			runs,
			counts,
		};
		return { status: "ready", report: Object.freeze({ ...unsigned, reportDigest: canonicalDigest(unsigned) }) };
	} catch (error) {
		return unavailable(error);
	}
}
