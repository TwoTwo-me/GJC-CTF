import { canonicalDigest, digestsEqual, isDigest, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { assertLactfEvidenceActive } from "./revoked-evidence";

export type DiagnosticVersionObservation = Readonly<{
	versionId: string;
	scope: "six-challenge-campaign" | "tier1-analyzer-smoke";
	evidenceDigest: Digest;
	effectiveSkillVersion: string | "unknown";
	effectiveSkillDigest: Digest | "unknown";
	routeRegistryDigest: Digest | "unknown";
	eligibleChallengeCount: number;
	reviewedAnalyzerCount: number;
	candidateOnlyCount: number;
	localCheckerPassCount: number;
	independentlyVerifiedSolveCount: number;
	failureCount: number;
	unknownMetrics: readonly string[];
}>;

export type DeadlineVersionObservation = Readonly<{
	schemaVersion: "gjc-ctf-deadline-version-observation-1";
	generatedAt: string;
	hardStop: string;
	sourceCommit: string;
	versions: readonly [DiagnosticVersionObservation, DiagnosticVersionObservation];
	comparison: Readonly<{
		benchmarkStatus: "unavailable";
		comparable: false;
		reason: string;
		diagnosticDeltas: Readonly<{
			reviewedAnalyzerCount: number;
			candidateOnlyCount: number;
			localCheckerPassCount: number;
			independentlyVerifiedSolveCount: number;
			failureCount: number;
		}>;
		regressions: readonly string[];
	}>;
	limitations: readonly string[];
	observationDigest: Digest;
}>;

export type DeadlineObservationInput = Omit<DeadlineVersionObservation, "observationDigest">;

function nonNegativeInteger(value: number): boolean {
	return Number.isSafeInteger(value) && value >= 0;
}

function validateVersion(version: DiagnosticVersionObservation): void {
	if (!version.versionId || !isDigest(version.evidenceDigest)) throw new Error("diagnostic version identity is invalid");
	if (version.effectiveSkillDigest !== "unknown" && !isDigest(version.effectiveSkillDigest)) {
		throw new Error("diagnostic skill digest is invalid");
	}
	if (version.routeRegistryDigest !== "unknown" && !isDigest(version.routeRegistryDigest)) {
		throw new Error("diagnostic route digest is invalid");
	}
	for (const count of [
		version.eligibleChallengeCount,
		version.reviewedAnalyzerCount,
		version.candidateOnlyCount,
		version.localCheckerPassCount,
		version.independentlyVerifiedSolveCount,
		version.failureCount,
	]) {
		if (!nonNegativeInteger(count)) throw new Error("diagnostic version count is invalid");
	}
	if (version.independentlyVerifiedSolveCount !== 0) {
		throw new Error("untrusted diagnostic observations cannot claim independently verified solves");
	}
	if (version.unknownMetrics.length === 0 || new Set(version.unknownMetrics).size !== version.unknownMetrics.length) {
		throw new Error("diagnostic unknown metrics must be explicit and unique");
	}
}

export function createDeadlineVersionObservation(input: DeadlineObservationInput): DeadlineVersionObservation {
	for (const version of input.versions) validateVersion(version);
	for (const version of input.versions) assertLactfEvidenceActive(version.evidenceDigest);
	if (input.schemaVersion !== "gjc-ctf-deadline-version-observation-1") throw new Error("deadline observation schema is invalid");
	if (!Number.isFinite(Date.parse(input.generatedAt)) || !Number.isFinite(Date.parse(input.hardStop))) {
		throw new Error("deadline observation timestamps are invalid");
	}
	if (!/^[a-f0-9]{40}$/u.test(input.sourceCommit)) throw new Error("deadline observation source commit is invalid");
	if (input.versions[0].versionId === input.versions[1].versionId) throw new Error("deadline observation versions must be unique");
	if (input.comparison.benchmarkStatus !== "unavailable" || input.comparison.comparable !== false || !input.comparison.reason) {
		throw new Error("diagnostic comparison must remain unavailable and non-comparable");
	}
	if (input.limitations.length === 0 || input.limitations.some(value => value.length === 0)) {
		throw new Error("deadline observation limitations are required");
	}
	return Object.freeze({ ...input, observationDigest: canonicalDigest(input) });
}

export function validateDeadlineVersionObservation(value: DeadlineVersionObservation): DeadlineVersionObservation {
	assertLactfEvidenceActive(value.observationDigest);
	const { observationDigest, ...input } = value;
	const rebuilt = createDeadlineVersionObservation(input);
	if (!digestsEqual(rebuilt.observationDigest, observationDigest)) throw new Error("deadline observation digest mismatch");
	return value;
}
