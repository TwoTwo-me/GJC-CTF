import { describe, expect, test } from "bun:test";
import { canonicalDigest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { metricsFingerprint } from "../../packages/coding-agent/src/ctf/contracts/metrics";
import { __versionStatsTestOnly, compareVersionStats, computeVersionStats, validateVersionStats, versionStatsJson } from "./version-stats";
import { authorizedVersionStatsRequest } from "./test-authority-fixture";

const digest = (value: string) => canonicalDigest(value);
const identity = {
	harnessDigest: digest("harness"), effectiveSkillDigest: digest("skill"), modelFingerprint: digest("model"), backendFingerprint: digest("backend"), toolchainDigest: digest("toolchain"), corpusDigest: digest("corpus"), calibrationDigest: digest("calibration"), benchmarkLockDigest: digest("lock"),
};
function run(challengeId: string, outcome: "pass" | "fail" | "unknown", options: { solved?: boolean; costUnknown?: boolean; wallTimeMs?: number } = {}) {
	const validatedSolve = options.solved ?? false;
	const result = { runId: `run-${challengeId}`, challengeId, verdict: "pass" };
	return {
		runId: `run-${challengeId}`, challengeId, repeatIndex: 0, seed: `sha256:${"a".repeat(64)}`, validatedSolve,
		...(validatedSolve ? { terminalGoalProof: { kind: "solved" as const, candidateId: `candidate-${challengeId}`, oracleResultDigest: canonicalDigest(result) }, signedOracleProof: { verified: true as const, result, entry: {}, key: {}, registryDigest: digest("registry") } } : {}),
		outcome, wallTimeMs: options.wallTimeMs ?? 100, firstValidTimeMs: validatedSolve ? 20 : null, manualInterventionCount: 0, inputTokens: 10, outputTokens: 20, cacheTokens: 3, toolCalls: 2,
		cost: options.costUnknown ? { status: "unknown" as const, reason: "provider omitted price", source: "provider" } : { status: "known" as const, cents: 1.5, source: "provider" }, codeCommit: "abc", benchmarkLockDigest: identity.benchmarkLockDigest, effectiveSkillDigest: identity.effectiveSkillDigest, modelFingerprint: identity.modelFingerprint, backendFingerprint: identity.backendFingerprint, calibrationDigest: identity.calibrationDigest, category: "web",
	};
}
function report(runs = [run("one", "pass", { solved: true }), run("two", "fail", { costUnknown: true, wallTimeMs: 200 })]) {
	const unsigned = { metricsSchemaVersion: "ctf-metrics-1" as const, benchmarkId: "benchmark", benchmarkLockDigest: identity.benchmarkLockDigest, calibrationDigest: identity.calibrationDigest, eligibleChallengeIds: ["one", "two"], createdAt: "2026-08-08T00:00:00.000Z", repeatCount: 5 as const, runs, passAt1: 0, passAt3: 0, categoryAggregates: [{ category: "web", numerator: 0, denominator: 2, excludedCount: 0, unknownCount: 0 }], p50WallTimeMs: null, p95WallTimeMs: null, manualInterventionCount: 0, unknownCount: 0, targetPassCount: 1, floorPassCount: 0, achievedPassCount: 1 };
	return { ...unsigned, fingerprint: metricsFingerprint(unsigned) };
}

describe("version statistics", () => {
	test("has deterministic identity and exact recomputed values", () => {
		const stats = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		expect(__versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() })).toEqual(stats);
		expect(stats.independentlyVerifiedSolveCount).toBe(1);
		expect(stats.passAt1).toEqual({ status: "known", value: 0.5 });
		expect(stats.inputTokens).toBe(20);
		expect(versionStatsJson(stats)).toBe(versionStatsJson(validateVersionStats(stats)));
	});
	test("retains unknown cost and unknown evidence", () => {
		const stats = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report([run("one", "unknown", { costUnknown: true })]) });
		expect(stats.unknownCostCount).toBe(1);
		expect(stats.independentlyVerifiedSolveRate.status).toBe("unknown");
		expect(stats.challengeStatus.two).toBe("unknown");
	});
	test("rejects tampered reports", () => {
		const tampered = report();
		tampered.runs[0].inputTokens = 999;
		expect(() => __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: tampered })).toThrow("fingerprint mismatch");
	});
	test("detects solved-to-unsolved regressions", () => {
		const baseline = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		const candidate = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report([run("one", "fail"), run("two", "fail")]) });
		const comparison = __versionStatsTestOnly.compareAuthorizedVersionStats(baseline, candidate);
		expect(comparison).toMatchObject({
			status: "comparable",
			regressions: ["one"],
			deltas: {
				independentlyVerifiedSolveCount: { status: "known", value: -1 },
				passAt1: { status: "known", value: -0.5 },
				firstValidLatencyMs: { status: "unknown" },
				inputTokens: { status: "known", value: 0 },
				knownCostCents: { status: "known", value: 1.5 },
				unknownCostCount: { status: "known", value: -1 },
				failureCount: { status: "known", value: 1 },
			},
			statusTransitions: { confidenceStatus: { baseline: "complete", candidate: "complete" }, holdoutStatus: { baseline: "unknown", candidate: "unknown" } },
		});
	});
	test("marks solved-to-unknown comparisons indeterminate", () => {
		const baseline = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		const candidate = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report([run("one", "unknown"), run("two", "fail")]) });
		expect(__versionStatsTestOnly.compareAuthorizedVersionStats(baseline, candidate)).toMatchObject({
			status: "indeterminate",
			reasons: ["partial_confidence", "solved_to_unknown"],
		});
	});
	test("does not clear regressions with partial evidence", () => {
		const baseline = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		const candidate = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report([run("one", "fail"), run("two", "unknown")]) });
		expect(__versionStatsTestOnly.compareAuthorizedVersionStats(baseline, candidate)).toMatchObject({
			status: "indeterminate",
			reasons: ["partial_confidence"],
			regressions: ["one"],
		});
	});
	test("marks corpus changes incomparable", () => {
		const baseline = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		const changedIdentity = { ...identity, corpusDigest: digest("other-corpus") };
		const candidate = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity: changedIdentity, report: report() });
		expect(__versionStatsTestOnly.compareAuthorizedVersionStats(baseline, candidate)).toEqual({ status: "incomparable", reasons: ["corpusDigest"] });
	});
	test("rejects tampered sealed statistics before comparison", () => {
		const baseline = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		const candidate = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		const tampered = { ...candidate, inputTokens: candidate.inputTokens + 1 };
		expect(() => __versionStatsTestOnly.compareAuthorizedVersionStats(baseline, tampered)).toThrow("fingerprint mismatch");
	});
	test("rejects mismatched production identity authority fields", () => {
		for (const identityOverride of [
			{ corpusDigest: digest("other-corpus") },
			{ modelFingerprint: digest("other-model") },
			{ backendFingerprint: digest("other-backend") },
			{ harnessDigest: digest("other-preflight") },
			{ toolchainDigest: digest("other-runtime") },
		]) {
			expect(computeVersionStats({ identity: { ...identity, ...identityOverride }, report: report() })).toMatchObject({ status: "unavailable" });
		}
	});
	test("authorizes real signed production statistics and comparison", () => {
		const authority = authorizedVersionStatsRequest();
		const baseline = authority;
		const candidate = baseline;
		const evaluatorCapability = { oracleTrustAnchors: authority.oracle.trustAnchors };
		expect(computeVersionStats(baseline)).toMatchObject({ status: "unavailable" });
		const baselineResult = computeVersionStats(baseline, evaluatorCapability);
		expect(baselineResult).toMatchObject({ status: "ready" });
		if (baselineResult.status !== "ready") throw new Error(baselineResult.reason);
		expect(baselineResult.stats.identity).toEqual(baseline.identity);
		const comparison = compareVersionStats(baseline, candidate, evaluatorCapability);
		expect(comparison).toMatchObject({ status: "comparable", deltas: { failureCount: { status: "known", value: 0 } } });
	});
	test("rejects harness and toolchain lineage drift", () => {
		const authority = authorizedVersionStatsRequest();
		for (const identity of [
			{ ...authority.identity, harnessDigest: digest("other-preflight") },
			{ ...authority.identity, toolchainDigest: digest("other-runtime") },
			{
				...authority.identity,
				harnessDigest: authority.runtimeEvidenceDigest,
				toolchainDigest: authority.preflightReportDigest,
			},
		]) {
			expect(computeVersionStats({ ...authority, identity })).toMatchObject({ status: "unavailable" });
		}
	});
	test("rejects raw reports and sealed stats from production comparison", () => {
		const raw = __versionStatsTestOnly.computeAuthorizedVersionStats({ identity, report: report() });
		expect(computeVersionStats({ identity, report: report() })).toMatchObject({ status: "unavailable" });
		expect(compareVersionStats(raw, raw)).toMatchObject({ status: "unavailable" });
	});
});
