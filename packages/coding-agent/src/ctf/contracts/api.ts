import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, NonNegativeIntegerSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const ProjectionStatusSchema = z.enum(["current", "lagging", "integrity_error", "rebuilding", "unavailable"]);
export type ProjectionStatus = z.infer<typeof ProjectionStatusSchema>;
export const CTF_API_UNKNOWN_DIGEST = "0".repeat(64);

export const CtfApiIdentitySchema = z
	.object({
		competitionId: CtfIdSchema,
		challengeId: CtfIdSchema.optional(),
		runId: CtfIdSchema.optional(),
	})
	.strict();
export type CtfApiIdentity = z.infer<typeof CtfApiIdentitySchema>;

export const CtfApiRequestSchema = z
	.object({
		apiSchemaVersion: z.literal(CTF_SCHEMA_VERSIONS.api),
		method: z.literal("GET"),
		path: z.string().min(1).max(2048),
		query: z.record(z.string(), z.string()).optional(),
	})
	.strict();
export type CtfApiRequest = z.infer<typeof CtfApiRequestSchema>;

export const CtfApiErrorSchema = z
	.object({
		code: z.string().min(1),
		message: z.string().min(1),
		retryable: z.boolean(),
		details: z.record(z.string(), z.unknown()).optional(),
	})
	.strict();
export type CtfApiError = z.infer<typeof CtfApiErrorSchema>;

const CtfApiMetadataShape = z
	.object({
		apiSchemaVersion: z.literal(CTF_SCHEMA_VERSIONS.api),
		identity: CtfApiIdentitySchema,
		canonicalRevision: NonNegativeIntegerSchema,
		canonicalDigest: DigestSchema,
		projectionRevision: NonNegativeIntegerSchema,
		projectionDigest: DigestSchema,
		projectionStatus: ProjectionStatusSchema,
		benchmarkLockDigest: DigestSchema.optional(),
		effectiveSkillDigest: DigestSchema.optional(),
		generatedAt: TimestampSchema,
	})
	.strict();

const CtfApiMetadataSchema = CtfApiMetadataShape.extend({
	canonicalRevision: PositiveIntegerSchema,
});

export const CtfApiSuccessEnvelopeSchema = CtfApiMetadataSchema.extend({
	data: z.record(z.string(), z.unknown()),
	error: z.undefined().optional(),
}).strict();

export const CtfApiErrorEnvelopeSchema = CtfApiMetadataShape.extend({
	data: z.undefined().optional(),
	error: CtfApiErrorSchema,
}).strict();

function validateApiMetadata(
	response: Pick<
		z.infer<typeof CtfApiMetadataShape>,
		"canonicalRevision" | "projectionRevision" | "projectionStatus" | "canonicalDigest" | "projectionDigest"
	>,
	ctx: z.RefinementCtx,
): void {
	if (response.projectionStatus === "current") {
		if (response.canonicalRevision <= 0 || response.projectionRevision <= 0) {
			ctx.addIssue({
				code: "custom",
				path: ["projectionStatus"],
				message: "current projection must have a verified non-zero revision",
			});
		}
		if (response.canonicalDigest === CTF_API_UNKNOWN_DIGEST || response.projectionDigest === CTF_API_UNKNOWN_DIGEST) {
			ctx.addIssue({
				code: "custom",
				path: ["projectionStatus"],
				message: "current projection must have verified digests",
			});
		}
		if (
			response.projectionRevision !== response.canonicalRevision ||
			response.projectionDigest !== response.canonicalDigest
		) {
			ctx.addIssue({
				code: "custom",
				path: ["projectionStatus"],
				message: "current projection must match canonical revision and digest",
			});
		}
	}
	if (
		response.projectionStatus === "lagging" &&
		(response.canonicalRevision <= 0 || response.projectionRevision <= 0)
	) {
		ctx.addIssue({
			code: "custom",
			path: ["projectionStatus"],
			message: "lagging projection must have verified non-zero revisions",
		});
	}
	if (
		response.projectionStatus === "lagging" &&
		(response.canonicalDigest === CTF_API_UNKNOWN_DIGEST || response.projectionDigest === CTF_API_UNKNOWN_DIGEST)
	) {
		ctx.addIssue({
			code: "custom",
			path: ["projectionStatus"],
			message: "lagging projection must have verified digests",
		});
	}
}

export const CtfApiEnvelopeSchema = z
	.union([CtfApiSuccessEnvelopeSchema, CtfApiErrorEnvelopeSchema])
	.superRefine((response, ctx) => {
		if (isCtfApiSuccess(response) && response.error !== undefined) {
			ctx.addIssue({ code: "custom", path: ["error"], message: "success envelopes must omit the error field" });
		}
		if (isCtfApiError(response) && response.data !== undefined) {
			ctx.addIssue({ code: "custom", path: ["data"], message: "error envelopes must omit the data field" });
		}
		validateApiMetadata(response, ctx);
		if (
			(response.projectionStatus === "integrity_error" ||
				response.projectionStatus === "rebuilding" ||
				response.projectionStatus === "unavailable") &&
			response.data !== undefined
		) {
			ctx.addIssue({
				code: "custom",
				path: ["data"],
				message: "unverified projections must not expose graph/run data",
			});
		}
	});
export type CtfApiSuccessEnvelope = z.infer<typeof CtfApiSuccessEnvelopeSchema>;
export type CtfApiErrorEnvelope = z.infer<typeof CtfApiErrorEnvelopeSchema>;
export type CtfApiEnvelope = z.infer<typeof CtfApiEnvelopeSchema>;

export type CtfApiSuccessResponse<T extends Record<string, unknown> = Record<string, unknown>> = Omit<
	CtfApiSuccessEnvelope,
	"data"
> & { data: T };
export type CtfApiResponse<T extends Record<string, unknown> = Record<string, unknown>> =
	| CtfApiSuccessResponse<T>
	| CtfApiErrorEnvelope;

export function isCtfApiSuccess(value: unknown): value is CtfApiSuccessEnvelope {
	if (typeof value !== "object" || value === null) return false;
	const record = value as Record<string, unknown>;
	return (
		typeof record.data === "object" &&
		record.data !== null &&
		!Array.isArray(record.data) &&
		record.error === undefined
	);
}

export function isCtfApiError(value: unknown): value is CtfApiErrorEnvelope {
	if (typeof value !== "object" || value === null) return false;
	const record = value as Record<string, unknown>;
	return (
		typeof record.error === "object" &&
		record.error !== null &&
		!Array.isArray(record.error) &&
		record.data === undefined
	);
}

export function validateApiEnvelope(value: unknown): CtfApiEnvelope {
	const parsed = CtfApiEnvelopeSchema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_api_request", "CTF API response envelope is invalid", {
			details: { issues: parsed.error.issues },
		});
	const response = parsed.data;
	assertKnownMajor(response.apiSchemaVersion, "api");
	return response;
}

export function parseApiEnvelope(value: unknown): CtfApiEnvelope {
	return validateApiEnvelope(value);
}
export const ApiResponseSchema = CtfApiEnvelopeSchema;
export const parseApiResponse = validateApiEnvelope;
export const parseCtfApiEnvelope = parseApiEnvelope;
export const validateCtfApiEnvelope = validateApiEnvelope;
export const parseCtfApiResponse = parseApiEnvelope;
export function validateApiRequest(value: unknown): CtfApiRequest {
	const parsed = CtfApiRequestSchema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_api_request", "CTF API request is invalid", {
			details: { issues: parsed.error.issues },
		});
	assertKnownMajor(parsed.data.apiSchemaVersion, "api");
	return parsed.data;
}
