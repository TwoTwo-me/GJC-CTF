import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, PositiveIntegerSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { SandboxPreflightV1Schema } from "./sandbox";

const SafeRelativePathSchema = z
	.string()
	.min(1)
	.max(512)
	.refine(
		value =>
			!value.includes("\0") &&
			!/^[\\/]/.test(value) &&
			!/^[A-Za-z]:/.test(value) &&
			!value.split(/[\\/]+/).includes(".."),
		"must be a confined relative path",
	);
const AdapterReferenceSchema = z
	.string()
	.min(1)
	.max(256)
	.regex(/^[a-z][a-z0-9._/-]*$/)
	.refine(value => !value.split("/").includes(".."), "must not escape its reference namespace");
const AdapterArgumentSchema = z
	.string()
	.min(1)
	.max(256)
	.refine(value => !/[\0\r\n]/.test(value) && !/[;&|`$<>]/.test(value), "must not contain shell syntax");
const LocalOriginSchema = z
	.string()
	.max(256)
	.refine(value => {
		try {
			const origin = new URL(value);
			return (
				origin.protocol === "http:" &&
				(origin.hostname === "127.0.0.1" || origin.hostname === "localhost") &&
				origin.pathname === "/" &&
				origin.search === "" &&
				origin.hash === ""
			);
		} catch {
			return false;
		}
	}, "must be a loopback HTTP origin");
const SanitizedReasonSchema = z
	.string()
	.min(1)
	.max(512)
	.refine(
		value =>
			!/[\0\r\n]/.test(value) &&
			!/(?:secret|password|token|private[ _-]?key|stderr)/i.test(value) &&
			!/(?:^|\s)(?:\/|[A-Za-z]:[\\/])/.test(value),
		"must be a bounded sanitized reason",
	);

export const EvaluationAdapterRoleSchema = z.enum(["solver", "service", "checker", "browser", "browser-bridge"]);
export type EvaluationAdapterRole = z.infer<typeof EvaluationAdapterRoleSchema>;
export const EvaluationTransportSchema = z.enum(["stdio", "http"]);
export type EvaluationTransport = z.infer<typeof EvaluationTransportSchema>;
export const PublicSecretPolicySchema = z.enum(["required", "supported", "not-feasible"]);
export type PublicSecretPolicy = z.infer<typeof PublicSecretPolicySchema>;
export const CandidateEncodingSchema = z.enum(["utf8", "base64"]);
export type CandidateEncoding = z.infer<typeof CandidateEncodingSchema>;

const AdapterBaseSchema = z
	.object({
		adapterId: CtfIdSchema,
	})
	.strict();

export const OfflineCheckerAdapterV1Schema = AdapterBaseSchema.extend({
	kind: z.literal("offline-checker"),
	roles: z.tuple([z.literal("checker")]),
	checkerRef: AdapterReferenceSchema,
	checkerDigest: DigestSchema,
	workingDirectory: SafeRelativePathSchema,
	arguments: z.array(AdapterArgumentSchema).max(32),
}).strict();
export type OfflineCheckerAdapterV1 = z.infer<typeof OfflineCheckerAdapterV1Schema>;

export const ProcessServiceAdapterV1Schema = AdapterBaseSchema.extend({
	kind: z.literal("process-service"),
	roles: z.tuple([z.literal("service")]),
	serviceRef: AdapterReferenceSchema,
	serviceDigest: DigestSchema,
	transport: EvaluationTransportSchema,
	workingDirectory: SafeRelativePathSchema,
	arguments: z.array(AdapterArgumentSchema).max(32),
	origin: LocalOriginSchema.optional(),
})
	.strict()
	.superRefine((adapter, context) => {
		if (adapter.transport === "http" && adapter.origin === undefined)
			context.addIssue({
				code: "custom",
				message: "HTTP process service requires a loopback origin",
				path: ["origin"],
			});
		if (adapter.transport === "stdio" && adapter.origin !== undefined)
			context.addIssue({
				code: "custom",
				message: "stdio process service cannot expose an origin",
				path: ["origin"],
			});
	});
export type ProcessServiceAdapterV1 = z.infer<typeof ProcessServiceAdapterV1Schema>;

export const ContainerServiceAdapterV1Schema = AdapterBaseSchema.extend({
	kind: z.literal("container-service"),
	roles: z.tuple([z.literal("service")]),
	imageDigest: DigestSchema,
	transport: z.literal("http"),
	origin: LocalOriginSchema,
	entryPath: SafeRelativePathSchema,
}).strict();
export type ContainerServiceAdapterV1 = z.infer<typeof ContainerServiceAdapterV1Schema>;

export const BrowserSessionAdapterV1Schema = AdapterBaseSchema.extend({
	kind: z.literal("browser-session"),
	roles: z.tuple([z.literal("browser"), z.literal("browser-bridge")]),
	browserDigest: DigestSchema,
	transport: z.literal("http"),
	origin: LocalOriginSchema,
	entryPath: SafeRelativePathSchema,
}).strict();
export type BrowserSessionAdapterV1 = z.infer<typeof BrowserSessionAdapterV1Schema>;

export const EvaluationAdapterV1Schema = z.discriminatedUnion("kind", [
	OfflineCheckerAdapterV1Schema,
	ProcessServiceAdapterV1Schema,
	ContainerServiceAdapterV1Schema,
	BrowserSessionAdapterV1Schema,
]);
export type EvaluationAdapterV1 = z.infer<typeof EvaluationAdapterV1Schema>;

export const EvaluationSpecV1Schema = z
	.object({
		schemaVersion: z.literal("ctf-evaluation-spec-1"),
		evaluationId: CtfIdSchema,
		challengeId: CtfIdSchema,
		descriptorDigest: DigestSchema,
		secretPolicy: PublicSecretPolicySchema,
		candidate: z
			.object({ encoding: CandidateEncodingSchema, maxBytes: PositiveIntegerSchema.max(16 * 1024 * 1024) })
			.strict(),
		adapters: z.array(EvaluationAdapterV1Schema).min(1).max(32),
		specDigest: DigestSchema,
	})
	.strict();
export type EvaluationSpecV1 = z.infer<typeof EvaluationSpecV1Schema>;

export const EvaluationComponentPreflightV1Schema = z
	.object({
		adapterId: CtfIdSchema,
		preflight: SandboxPreflightV1Schema,
	})
	.strict();
export type EvaluationComponentPreflightV1 = z.infer<typeof EvaluationComponentPreflightV1Schema>;
export const EvaluationPreflightV1Schema = z
	.object({
		schemaVersion: z.literal("ctf-evaluation-preflight-1"),
		components: z.array(EvaluationComponentPreflightV1Schema).min(1).max(32),
		passed: z.boolean(),
		preflightDigest: DigestSchema,
	})
	.strict();
export type EvaluationPreflightV1 = z.infer<typeof EvaluationPreflightV1Schema>;

export const EvaluationLineageV1Schema = z
	.object({
		schemaVersion: z.literal("ctf-evaluation-lineage-1"),
		runId: CtfIdSchema,
		challengeId: CtfIdSchema,
		descriptorDigest: DigestSchema,
		specDigest: DigestSchema,
		corpusDigest: DigestSchema,
		sourceDigest: DigestSchema,
		visiblePolicyDigest: DigestSchema,
		toolDigest: DigestSchema,
		backendDigest: DigestSchema,
		runtimeDigest: DigestSchema,
		safetyDigest: DigestSchema,
		limitsDigest: DigestSchema,
		calibrationDigest: DigestSchema,
		preflightDigest: DigestSchema,
		candidateDigest: DigestSchema,
		inputDigest: DigestSchema,
		instanceCommitmentDigest: DigestSchema,
		verifiedOracleDigest: DigestSchema.optional(),
		lineageDigest: DigestSchema,
	})
	.strict();
export type EvaluationLineageV1 = z.infer<typeof EvaluationLineageV1Schema>;

const ResultBaseSchema = z
	.object({
		schemaVersion: z.literal("ctf-evaluation-result-1"),
		evaluationId: CtfIdSchema,
		lineage: EvaluationLineageV1Schema,
		resultDigest: DigestSchema,
	})
	.strict();
export const CandidateEvaluationResultV1Schema = ResultBaseSchema.extend({
	kind: z.literal("candidate"),
	candidateDigest: DigestSchema,
}).strict();
export type CandidateEvaluationResultV1 = z.infer<typeof CandidateEvaluationResultV1Schema>;
export const VerifiedEvaluationResultV1Schema = ResultBaseSchema.extend({
	kind: z.literal("verified"),
	candidateDigest: DigestSchema,
	verdict: z.enum(["pass", "fail", "invalid", "error"]),
	oracleId: CtfIdSchema,
	verifiedOracleDigest: DigestSchema,
}).strict();
export type VerifiedEvaluationResultV1 = z.infer<typeof VerifiedEvaluationResultV1Schema>;
export const UnavailableEvaluationResultV1Schema = ResultBaseSchema.extend({
	kind: z.literal("unavailable"),
	phase: z.enum(["preflight", "adapter", "candidate", "verification"]),
	code: z.enum(["not_available", "not_supported", "not_feasible", "preflight_failed"]),
	sanitizedReason: SanitizedReasonSchema,
}).strict();
export type UnavailableEvaluationResultV1 = z.infer<typeof UnavailableEvaluationResultV1Schema>;
export const EvaluationResultV1Schema = z.discriminatedUnion("kind", [
	CandidateEvaluationResultV1Schema,
	VerifiedEvaluationResultV1Schema,
	UnavailableEvaluationResultV1Schema,
]);
export type EvaluationResultV1 = z.infer<typeof EvaluationResultV1Schema>;

export function evaluationSpecDigest(spec: EvaluationSpecV1 | Omit<EvaluationSpecV1, "specDigest">): Digest {
	return canonicalDigest(spec, ["specDigest"]);
}
export function evaluationPreflightDigest(
	preflight: EvaluationPreflightV1 | Omit<EvaluationPreflightV1, "preflightDigest">,
): Digest {
	return canonicalDigest(preflight, ["preflightDigest"]);
}
export function evaluationLineageDigest(
	lineage: EvaluationLineageV1 | Omit<EvaluationLineageV1, "lineageDigest">,
): Digest {
	return canonicalDigest(lineage, ["lineageDigest"]);
}
export function evaluationResultDigest(result: EvaluationResultV1 | Omit<EvaluationResultV1, "resultDigest">): Digest {
	return canonicalDigest(result, ["resultDigest"]);
}

function parseOrThrow<T>(schema: z.ZodType<T>, value: unknown, message: string): T {
	const parsed = schema.safeParse(value);
	if (!parsed.success) throw new CtfError("invalid_manifest", message, { details: { issues: parsed.error.issues } });
	return parsed.data;
}

export function validateEvaluationSpec(value: unknown): EvaluationSpecV1 {
	const spec = parseOrThrow(EvaluationSpecV1Schema, value, "evaluation spec is invalid");
	if (new Set(spec.adapters.map(adapter => adapter.adapterId)).size !== spec.adapters.length)
		throw new CtfError("invalid_manifest", "evaluation spec adapter IDs must be unique");
	if (!digestsEqual(evaluationSpecDigest(spec), spec.specDigest))
		throw new CtfError("digest_mismatch", "evaluation spec digest mismatch");
	return spec;
}
export function validateEvaluationPreflight(value: unknown): EvaluationPreflightV1 {
	const preflight = parseOrThrow(EvaluationPreflightV1Schema, value, "evaluation preflight is invalid");
	if (new Set(preflight.components.map(component => component.adapterId)).size !== preflight.components.length)
		throw new CtfError("invalid_manifest", "evaluation preflight adapter IDs must be unique");
	if (preflight.passed !== preflight.components.every(component => component.preflight.passed))
		throw new CtfError("unsafe_sandbox", "evaluation preflight pass status does not match components");
	if (!digestsEqual(evaluationPreflightDigest(preflight), preflight.preflightDigest))
		throw new CtfError("digest_mismatch", "evaluation preflight digest mismatch");
	return preflight;
}
export function validateEvaluationLineage(value: unknown): EvaluationLineageV1 {
	const lineage = parseOrThrow(EvaluationLineageV1Schema, value, "evaluation lineage is invalid");
	if (!digestsEqual(evaluationLineageDigest(lineage), lineage.lineageDigest))
		throw new CtfError("digest_mismatch", "evaluation lineage digest mismatch");
	return lineage;
}
export function validateEvaluationResult(value: unknown): EvaluationResultV1 {
	const result = parseOrThrow(EvaluationResultV1Schema, value, "evaluation result is invalid");
	const lineage = validateEvaluationLineage(result.lineage);
	if (result.kind === "candidate" && result.candidateDigest !== lineage.candidateDigest)
		throw new CtfError("integrity_error", "candidate result does not match lineage candidate");
	if (result.kind === "verified") {
		if (
			result.candidateDigest !== lineage.candidateDigest ||
			result.verifiedOracleDigest !== lineage.verifiedOracleDigest
		)
			throw new CtfError("oracle_integrity_error", "verified result does not match candidate or oracle lineage");
	}
	if (!digestsEqual(evaluationResultDigest(result), result.resultDigest))
		throw new CtfError("digest_mismatch", "evaluation result digest mismatch");
	return result;
}

export const EvaluationSpecSchema = EvaluationSpecV1Schema;
export const EvaluationPreflightSchema = EvaluationPreflightV1Schema;
export const EvaluationLineageSchema = EvaluationLineageV1Schema;
export const EvaluationResultSchema = EvaluationResultV1Schema;
export const parseEvaluationSpec = validateEvaluationSpec;
export const parseEvaluationPreflight = validateEvaluationPreflight;
export const parseEvaluationLineage = validateEvaluationLineage;
export const parseEvaluationResult = validateEvaluationResult;
