import * as z from "zod/v4";
import { canonicalDigest, digestsEqual } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { DigestSchema, TimestampSchema } from "../../packages/coding-agent/src/ctf/contracts/common";
import { assertLactfEvidenceActive } from "./revoked-evidence";

const EvidenceRefSchema = z.string().regex(/^artifacts\/ctf\/[a-z0-9][a-z0-9._-]*\.json$/u);
const CountSchema = z.number().int().nonnegative();
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

export const LactfVersionObservationV2Schema = z.object({
	schemaVersion: z.literal("gjc-ctf-version-observation-2"),
	generatedAt: TimestampSchema,
	hardStop: TimestampSchema,
	sourceCommit: z.string().regex(/^[a-f0-9]{40}$/u),
	versions: z.array(z.union([InvalidatedVersionSchema, DiagnosticVersionSchema, HarnessVersionSchema])).min(1),
	comparison: z.object({
		benchmarkStatus: z.literal("unavailable"),
		comparable: z.literal(false),
		reason: z.string().min(1),
		knownHarnessDeltas: z.record(z.string(), z.number().int()),
		unknownMetrics: z.array(z.string().min(1)).min(1),
	}).strict(),
	limitations: z.array(z.string().min(1)).min(1),
	observationDigest: DigestSchema,
}).strict();
export type LactfVersionObservationV2 = z.infer<typeof LactfVersionObservationV2Schema>;

export function validateLactfVersionStatisticsArtifact(value: unknown): LactfVersionObservationV2 {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error("LA CTF version statistics artifact is invalid");
	}
	const candidate = value as Record<string, unknown>;
	assertLactfEvidenceActive(candidate.observationDigest);
	const parsed = LactfVersionObservationV2Schema.safeParse(value);
	if (!parsed.success) throw new Error("LA CTF version statistics artifact is not the active v2 schema");
	const observation = parsed.data;
	if (new Set(observation.versions.map(version => version.versionId)).size !== observation.versions.length) {
		throw new Error("LA CTF version identifiers must be unique");
	}
	const invalidated = observation.versions.filter(version => version.status === "invalidated");
	if (
		invalidated.length === 0 ||
		invalidated.some(version => version.evidenceRef !== "artifacts/ctf/lactf-expanded-v2-invalidation.json")
	) {
		throw new Error("LA CTF invalidated versions must reference the machine-readable invalidation receipt");
	}
	const { observationDigest, ...unsigned } = observation;
	if (!digestsEqual(canonicalDigest(unsigned), observationDigest)) {
		throw new Error("LA CTF version statistics artifact digest mismatch");
	}
	return observation;
}
