import * as z from "zod/v4";
import { DigestSchema, TimestampSchema } from "../contracts/common";
import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";

const EvidenceRefSchema = z.string().regex(/^artifacts\/ctf\/[a-z0-9][a-z0-9._-]*\.json$/u);
const CountSchema = z.number().int().nonnegative();

function knownDigest(value: string): Digest {
	if (!isDigest(value)) throw new Error("configured LA CTF evidence digest is invalid");
	return value;
}
const CommonVersionSchema = z.object({
	versionId: z.string().min(1),
	scope: z.string().min(1),
	evidenceRef: EvidenceRefSchema,
	evidenceSchemaVersion: z.string().min(1),
	evidenceDigest: DigestSchema,
	eligibleChallengeCount: CountSchema,
	independentlyVerifiedSolveCount: z.literal(0),
});
const InvalidatedVersionSchema = CommonVersionSchema.extend({
	status: z.literal("invalidated"),
	statisticsUsable: z.literal(false),
	invalidatedCampaignDigest: DigestSchema,
	reason: z.string().min(1),
}).strict();
const DiagnosticVersionSchema = CommonVersionSchema.extend({
	status: z.literal("diagnostic-only"),
	reviewedAnalyzerCount: CountSchema,
	localCheckerPassCount: CountSchema,
	statisticsUsable: z.literal(false),
	reason: z.string().min(1),
}).strict();
const HarnessVersionSchema = CommonVersionSchema.extend({
	status: z.literal("verified-harness-unscored"),
	reviewedAnalyzerCount: CountSchema,
	tier1ChallengeCount: CountSchema,
	tier2ChallengeCount: CountSchema,
	focusedTestsPassed: CountSchema,
	testsFailed: z.literal(0),
	compiledSmokePassed: z.literal(true),
	scored: z.literal(false),
	tierExpansionAuthorized: z.literal(false),
	supersedesObservationDigest: DigestSchema,
}).strict();

export const LactfVersionObservationV2Schema = z
	.object({
		schemaVersion: z.literal("gjc-ctf-version-observation-2"),
		generatedAt: TimestampSchema,
		hardStop: TimestampSchema,
		sourceCommit: z.string().regex(/^[a-f0-9]{40}$/u),
		versions: z.array(z.union([InvalidatedVersionSchema, DiagnosticVersionSchema, HarnessVersionSchema])).min(1),
		comparison: z
			.object({
				benchmarkStatus: z.literal("unavailable"),
				comparable: z.literal(false),
				reason: z.string().min(1),
				unknownMetrics: z.array(z.string().min(1)).min(1),
			})
			.strict(),
		limitations: z.array(z.string().min(1)).min(1),
		observationDigest: DigestSchema,
	})
	.strict();
export type LactfVersionObservationV2 = z.infer<typeof LactfVersionObservationV2Schema>;
export const LactfVersionStatisticsInspectionSchema = z
	.object({
		schemaVersion: z.literal("gjc-ctf-stats-inspection-1"),
		versionsInspected: CountSchema,
		independentlyVerifiedSolveCount: z.literal(0),
		status: z.literal("unscored"),
		comparisonStatus: z.literal("unavailable"),
		comparable: z.literal(false),
		tier2Authorized: z.literal(false),
		limitationsRecorded: CountSchema,
	})
	.strict();
export type LactfVersionStatisticsInspection = z.infer<typeof LactfVersionStatisticsInspectionSchema>;

const INVALIDATION_EVIDENCE_REF = "artifacts/ctf/lactf-expanded-v2-invalidation.json";
const INVALIDATED_CAMPAIGN_DIGEST = knownDigest("3a834bd5cbb0a988e8c948ea454255d22ec3d3851b8617a64f6c1d920376e557");
const PREVIOUS_ACTIVE_OBSERVATION_DIGEST = knownDigest(
	"695ac99878d9ec731ba0eb7366b9295e4563db824e7fdefcef69ced8a35072a4",
);
const EXPECTED_EVIDENCE_BINDINGS = new Map<string, Readonly<{ schemaVersion: string; digest: Digest }>>([
	[
		INVALIDATION_EVIDENCE_REF,
		{
			schemaVersion: "gjc-ctf-campaign-invalidation-1",
			digest: knownDigest("8e9a3309ab0f37ccaff1e3a160711de579ecd3b6bec989ff45052e97f374e81e"),
		},
	],
	[
		"artifacts/ctf/lactf-tier1-local-evidence-v1.json",
		{
			schemaVersion: "gjc-ctf-tier1-local-evidence-1",
			digest: knownDigest("b04360563a970aba584045eb9917ee077e95a8dcd729a85ff8f8f3dd71a1cf5b"),
		},
	],
	[
		"artifacts/ctf/ctf-harness-v3-evidence.json",
		{
			schemaVersion: "gjc-ctf-harness-evidence-1",
			digest: knownDigest("421794061a38603a34a94e0e9489a5f4597564ee5acca5acd2c71f6ce9f470c3"),
		},
	],
]);
const REVOKED_OBSERVATION_DIGESTS = new Set<Digest>([
	knownDigest("3a834bd5cbb0a988e8c948ea454255d22ec3d3851b8617a64f6c1d920376e557"),
	knownDigest("c79832bdc48d24983b525f40ac6587ccb21651a3bcb4d3e668d27c1d6ef8d13a"),
	knownDigest("324f9efd0f9237b9fdcfd8d32c9d744929a878bceb48f4ffe575e4222c03f147"),
]);
const ACTIVE_OBSERVATION_DIGESTS = new Set<Digest>([
	knownDigest("5d8a9d154d08e4899c26ea1387ebd2a3ada9c0d8810f613dc195ebdeb2308099"),
]);

export function validateLactfVersionStatisticsArtifact(value: unknown): LactfVersionObservationV2 {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error("LA CTF version statistics artifact is invalid");
	}
	const rawDigest = "observationDigest" in value ? value.observationDigest : undefined;
	if (isDigest(rawDigest) && REVOKED_OBSERVATION_DIGESTS.has(rawDigest)) {
		throw new Error("LA CTF version statistics artifact is invalidated");
	}
	const parsed = LactfVersionObservationV2Schema.safeParse(value);
	if (!parsed.success) throw new Error("LA CTF version statistics artifact is not the active v2 schema");
	const observation = parsed.data;
	if (new Set(observation.versions.map(version => version.versionId)).size !== observation.versions.length) {
		throw new Error("LA CTF version identifiers must be unique");
	}
	const invalidated = observation.versions.filter(version => version.status === "invalidated");
	if (
		invalidated.length === 0 ||
		invalidated.some(
			version =>
				version.evidenceRef !== INVALIDATION_EVIDENCE_REF ||
				!digestsEqual(version.invalidatedCampaignDigest, INVALIDATED_CAMPAIGN_DIGEST),
		)
	) {
		throw new Error("LA CTF invalidated versions must bind the invalidation receipt and campaign digest");
	}
	const currentHarnesses = observation.versions.filter(version => version.status === "verified-harness-unscored");
	if (
		currentHarnesses.length !== 1 ||
		!digestsEqual(currentHarnesses[0]!.supersedesObservationDigest, PREVIOUS_ACTIVE_OBSERVATION_DIGEST) ||
		REVOKED_OBSERVATION_DIGESTS.has(currentHarnesses[0]!.supersedesObservationDigest)
	) {
		throw new Error(
			"LA CTF observation must contain one current harness that supersedes the prior active observation",
		);
	}
	for (const version of observation.versions) {
		const expected = EXPECTED_EVIDENCE_BINDINGS.get(version.evidenceRef);
		if (
			expected === undefined ||
			version.evidenceSchemaVersion !== expected.schemaVersion ||
			!digestsEqual(version.evidenceDigest, expected.digest)
		) {
			throw new Error("LA CTF evidence reference does not match its reviewed content binding");
		}
	}
	const { observationDigest, ...unsigned } = observation;
	if (!isDigest(observationDigest)) throw new Error("LA CTF version statistics artifact digest is invalid");
	if (!digestsEqual(canonicalDigest(unsigned), observationDigest)) {
		throw new Error("LA CTF version statistics artifact digest mismatch");
	}
	if (REVOKED_OBSERVATION_DIGESTS.has(observationDigest)) {
		throw new Error("LA CTF version statistics artifact is invalidated");
	}
	if (!ACTIVE_OBSERVATION_DIGESTS.has(observationDigest)) {
		throw new Error("LA CTF version statistics artifact is not an active diagnostic observation");
	}
	return observation;
}
export function projectLactfVersionStatisticsInspection(
	observation: LactfVersionObservationV2,
): LactfVersionStatisticsInspection {
	return LactfVersionStatisticsInspectionSchema.parse({
		schemaVersion: "gjc-ctf-stats-inspection-1",
		versionsInspected: observation.versions.length,
		independentlyVerifiedSolveCount: 0,
		status: "unscored",
		comparisonStatus: "unavailable",
		comparable: false,
		tier2Authorized: false,
		limitationsRecorded: observation.limitations.length,
	});
}
