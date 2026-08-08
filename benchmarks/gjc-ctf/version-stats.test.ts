import { describe, expect, test } from "bun:test";
import { canonicalDigest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { metricsFingerprint } from "../../packages/coding-agent/src/ctf/contracts/metrics";
import { compareVersionStats, computeVersionStats, validateVersionStats, versionStatsJson } from "./version-stats";
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
	test("validates deterministic production statistics and rejects tampering", () => {
		const authority = authorizedVersionStatsRequest();
		const evaluatorCapability = { oracleTrustAnchors: authority.oracle.trustAnchors };
		const result = computeVersionStats(authority, evaluatorCapability);
		expect(result.status).toBe("ready");
		if (result.status !== "ready") throw new Error(result.reason);
		expect(computeVersionStats(authority, evaluatorCapability)).toEqual(result);
		expect(versionStatsJson(result.stats)).toBe(versionStatsJson(validateVersionStats(result.stats)));
		expect(result.stats.independentlyVerifiedSolveCount).toBe(0);
		expect(result.stats.unknownCostCount).toBe(0);
		expect(result.stats.challengeStatus["fixture-challenge"]).toBe("unsolved");
		expect(() => validateVersionStats({ ...result.stats, inputTokens: result.stats.inputTokens + 1 })).toThrow(
			"fingerprint mismatch",
		);
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
		expect(computeVersionStats({ identity, report: report() })).toMatchObject({ status: "unavailable" });
		expect(compareVersionStats({ identity, report: report() }, { identity, report: report() })).toMatchObject({
			status: "unavailable",
		});
	});
});
