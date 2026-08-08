import { describe, expect, test } from "bun:test";
import { sha256Hex } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { createDeadlineVersionObservation, validateDeadlineVersionObservation } from "./deadline-observation";
import { assertLactfEvidenceActive, LACTF_REVOKED_EVIDENCE } from "./revoked-evidence";

const D = sha256Hex("diagnostic");
const UNKNOWN = ["solveRate", "passAt1", "passAt3", "firstValidLatencyMs", "cost"] as const;

function observation() {
	return createDeadlineVersionObservation({
		schemaVersion: "gjc-ctf-deadline-version-observation-1",
		generatedAt: "2026-08-08T05:00:00.000Z",
		hardStop: "2026-08-09T00:00:00.000Z",
		sourceCommit: "3379d4a7b36680764a34e7dc817cc3c94c244764",
		versions: [
			{
				versionId: "campaign-expanded-v2",
				scope: "six-challenge-campaign",
				evidenceDigest: D,
				effectiveSkillVersion: "unknown",
				effectiveSkillDigest: "unknown",
				routeRegistryDigest: "unknown",
				eligibleChallengeCount: 6,
				reviewedAnalyzerCount: 1,
				candidateOnlyCount: 4,
				localCheckerPassCount: 0,
				independentlyVerifiedSolveCount: 0,
				failureCount: 2,
				unknownMetrics: UNKNOWN,
			},
			{
				versionId: "tier1-analyzers-v1.1.0",
				scope: "tier1-analyzer-smoke",
				evidenceDigest: D,
				effectiveSkillVersion: "1.1.0",
				effectiveSkillDigest: D,
				routeRegistryDigest: D,
				eligibleChallengeCount: 3,
				reviewedAnalyzerCount: 3,
				candidateOnlyCount: 3,
				localCheckerPassCount: 3,
				independentlyVerifiedSolveCount: 0,
				failureCount: 0,
				unknownMetrics: UNKNOWN,
			},
		],
		comparison: {
			benchmarkStatus: "unavailable",
			comparable: false,
			reason: "scopes differ and benchmark authority is unavailable",
			diagnosticDeltas: {
				reviewedAnalyzerCount: 2,
				candidateOnlyCount: -1,
				localCheckerPassCount: 3,
				independentlyVerifiedSolveCount: 0,
				failureCount: -2,
			},
			regressions: [],
		},
		limitations: ["permission and pre-authorized independent oracle evidence are unavailable"],
	});
}

describe("deadline version observation", () => {
	test("seals a non-authoritative comparison and preserves unknowns", () => {
		const value = observation();
		expect(validateDeadlineVersionObservation(value)).toEqual(value);
		expect(value.comparison).toMatchObject({ benchmarkStatus: "unavailable", comparable: false });
		expect(value.versions.every(version => version.independentlyVerifiedSolveCount === 0)).toBe(true);
	});

	test("rejects digest tampering and false solve authority", () => {
		const value = observation();
		expect(() => validateDeadlineVersionObservation({ ...value, generatedAt: "2026-08-08T06:00:00.000Z" })).toThrow(/digest mismatch/);
		expect(() =>
			createDeadlineVersionObservation({
				...value,
				versions: [{ ...value.versions[0], independentlyVerifiedSolveCount: 1 }, value.versions[1]],
			}),
		).toThrow(/cannot claim/);
	});

	test("rejects every machine-registered invalidated campaign artifact", () => {
		for (const revocation of LACTF_REVOKED_EVIDENCE) {
			expect(() => assertLactfEvidenceActive(revocation.digest)).toThrow(/invalidated/u);
		}
	});
});
