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
	eligibleChallengeCount: CountSchema,
	independentlyVerifiedSolveCount: z.literal(0),
});
const InvalidatedVersionSchema = CommonVersionSchema.extend({
	status: z.literal("invalidated"),
	statisticsUsable: z.literal(false),
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
	testsPassed: CountSchema,
	testsFailed: z.literal(0),
	compiledSmokePassed: z.literal(true),
	scored: z.literal(false),
	tierExpansionAuthorized: z.literal(false),
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
				knownHarnessDeltas: z.record(z.string(), z.number().int()),
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
const REVOKED_OBSERVATION_DIGESTS = new Set<Digest>([
	knownDigest("3a834bd5cbb0a988e8c948ea454255d22ec3d3851b8617a64f6c1d920376e557"),
	knownDigest("c79832bdc48d24983b525f40ac6587ccb21651a3bcb4d3e668d27c1d6ef8d13a"),
	knownDigest("324f9efd0f9237b9fdcfd8d32c9d744929a878bceb48f4ffe575e4222c03f147"),
]);
const ACTIVE_OBSERVATION_DIGESTS = new Set<Digest>([
	knownDigest("695ac99878d9ec731ba0eb7366b9295e4563db824e7fdefcef69ced8a35072a4"),
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
	if (invalidated.length === 0 || invalidated.some(version => version.evidenceRef !== INVALIDATION_EVIDENCE_REF)) {
		throw new Error("LA CTF invalidated versions must reference the machine-readable invalidation receipt");
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
