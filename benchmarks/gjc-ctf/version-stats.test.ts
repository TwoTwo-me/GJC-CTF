import { describe, expect, test } from "bun:test";
import { canonicalDigest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { metricsFingerprint } from "../../packages/coding-agent/src/ctf/contracts/metrics";
import {
	compareVersionStats,
	computeVersionStats,
	validateVersionStats,
	versionStatsIdentityDigest,
	versionStatsJson,
} from "./version-stats";
import { authorizedVersionStatsRequest } from "./test-authority-fixture";

const digest = (value: string) => canonicalDigest(value);

function evaluatorCapability(authority: ReturnType<typeof authorizedVersionStatsRequest>, reviewed = [authority.implementationIdentity]) {
	return {
		oracleTrustAnchors: authority.oracle.trustAnchors,
		reviewedImplementationIdentities: reviewed,
	};
}

function withImplementationIdentity(
	authority: ReturnType<typeof authorizedVersionStatsRequest>,
	implementationIdentity: ReturnType<typeof authorizedVersionStatsRequest>["implementationIdentity"],
) {
	const { fingerprint: _fingerprint, ...reportUnsigned } = authority.report;
	const report = {
		...reportUnsigned,
		implementationIdentity,
		fingerprint: metricsFingerprint({ ...reportUnsigned, implementationIdentity }),
	};
	return {
		...authority,
		implementationIdentity,
		identity: { ...authority.identity, implementationIdentity },
		report,
	};
}

describe("version statistics", () => {
	test("emits deterministic v2 production statistics and rejects v1 artifacts", () => {
		const authority = authorizedVersionStatsRequest();
		const capability = evaluatorCapability(authority);
		const result = computeVersionStats(authority, capability);
		expect(result.status).toBe("ready");
		if (result.status !== "ready") throw new Error(result.reason);
		expect(result.stats.schemaVersion).toBe("gjc-ctf-version-stats-2");
		expect(computeVersionStats(authority, capability)).toEqual(result);
		expect(versionStatsJson(result.stats)).toBe(versionStatsJson(validateVersionStats(result.stats)));
		expect(result.stats.independentlyVerifiedSolveCount).toBe(0);
		expect(result.stats.unknownCostCount).toBe(0);
		expect(result.stats.challengeStatus["fixture-challenge"]).toBe("unsolved");
		expect(() => validateVersionStats({ ...result.stats, schemaVersion: "gjc-ctf-version-stats-1" })).toThrow(
			"version statistics are invalid",
		);
		expect(() => validateVersionStats({ ...result.stats, identity: { ...result.stats.identity, harnessDigest: digest("legacy-harness") } })).toThrow(
			"version statistics are invalid",
		);
		expect(() => validateVersionStats({ ...result.stats, inputTokens: result.stats.inputTokens + 1 })).toThrow(
			"fingerprint mismatch",
		);
	});

	test("requires an externally reviewed stable implementation identity", () => {
		const authority = authorizedVersionStatsRequest();
		expect(computeVersionStats(authority, { oracleTrustAnchors: authority.oracle.trustAnchors })).toMatchObject({ status: "unavailable" });
		for (const component of [
			"harnessSourceDigest",
			"harnessBuildDigest",
			"toolchainDigest",
			"capabilityClosureDigest",
		] as const) {
			const implementationIdentity = { ...authority.implementationIdentity, [component]: digest(`other-${component}`) };
			expect(versionStatsIdentityDigest({ ...authority.identity, implementationIdentity })).not.toBe(
				versionStatsIdentityDigest(authority.identity),
			);
			expect(computeVersionStats(withImplementationIdentity(authority, implementationIdentity), evaluatorCapability(authority))).toMatchObject({ status: "unavailable" });
		}
	});

	test("rejects request, report, and reviewed-capability identity mismatches", () => {
		const authority = authorizedVersionStatsRequest();
		const alternate = { ...authority.implementationIdentity, harnessBuildDigest: digest("alternate-build") };
		const reviewed = evaluatorCapability(authority, [authority.implementationIdentity, alternate]);
		expect(computeVersionStats({ ...authority, implementationIdentity: alternate }, reviewed)).toMatchObject({ status: "unavailable" });
		expect(computeVersionStats({ ...authority, report: withImplementationIdentity(authority, alternate).report }, reviewed)).toMatchObject({ status: "unavailable" });
		expect(computeVersionStats(withImplementationIdentity(authority, alternate), evaluatorCapability(authority))).toMatchObject({ status: "unavailable" });
	});

	test("keeps signed receipt evidence mandatory independently of implementation identity", () => {
		const authority = authorizedVersionStatsRequest();
		const capability = evaluatorCapability(authority);
		expect(computeVersionStats({ ...authority, preflightReportDigest: undefined }, capability)).toMatchObject({ status: "unavailable" });
		expect(computeVersionStats({ ...authority, runtimeEvidenceDigest: undefined }, capability)).toMatchObject({ status: "unavailable" });
	});

	test("compares independently reviewed implementation versions with the same corpus, calibration, and lock", () => {
		const baseline = authorizedVersionStatsRequest();
		const alternate = { ...baseline.implementationIdentity, harnessSourceDigest: digest("alternate-source") };
		const candidate = withImplementationIdentity(baseline, alternate);
		const capability = evaluatorCapability(baseline, [baseline.implementationIdentity, alternate]);
		expect(compareVersionStats(baseline, candidate, capability)).toMatchObject({
			status: "comparable",
			deltas: { failureCount: { status: "known", value: 0 } },
		});
	});
});
