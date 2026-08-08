import * as z from "zod/v4";
import { CTF_SCHEMA_VERSIONS } from "./version";

export const CTF_ERROR_CODES = [
	"unknown_schema_major",
	"digest_mismatch",
	"invalid_digest",
	"invalid_manifest",
	"invalid_registration",
	"registration_repair_required",
	"idempotency_conflict",
	"revision_conflict",
	"integrity_error",
	"invalid_edge",
	"invalid_transition",
	"missing_provenance",
	"missing_evidence",
	"cross_challenge_reference",
	"stale_run_fence",
	"stale_claim",
	"benchmark_lock_mismatch",
	"benchmark_lock_skill_mismatch",
	"benchmark_provenance_missing",
	"uncalibrated_limits",
	"unsafe_sandbox",
	"oracle_integrity_error",
	"unsupported_migration",
	"invalid_api_request",
	"unsupported_operation",
] as const;
export type CtfErrorCode = (typeof CTF_ERROR_CODES)[number];
export const CTF_EXIT_CLASSES = {
	usage: 2,
	conflict: 3,
	integrity: 4,
	isolation: 5,
	provenance: 6,
	benchmarkLock: 7,
	calibration: 8,
	runtime: 9,
} as const;
export type CtfExitClass = keyof typeof CTF_EXIT_CLASSES;

export const CtfErrorCodeSchema = z.enum(CTF_ERROR_CODES);
export const CtfErrorDetailSchema = z.record(z.string(), z.unknown());
export const CtfErrorEnvelopeSchema = z.object({
	schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.api),
	error: z.object({
		code: CtfErrorCodeSchema,
		message: z.string().min(1),
		retryable: z.boolean(),
		details: CtfErrorDetailSchema.optional(),
	}),
});
export type CtfErrorEnvelope = z.infer<typeof CtfErrorEnvelopeSchema>;

export class CtfError extends Error {
	readonly code: CtfErrorCode;
	readonly retryable: boolean;
	readonly details: Record<string, unknown> | undefined;

	constructor(
		code: CtfErrorCode,
		message: string,
		options: { retryable?: boolean; details?: Record<string, unknown> } = {},
	) {
		super(message);
		this.name = "CtfError";
		this.code = code;
		this.retryable = options.retryable ?? false;
		this.details = options.details;
	}

	toEnvelope(): CtfErrorEnvelope {
		return {
			schemaVersion: CTF_SCHEMA_VERSIONS.api,
			error: {
				code: this.code,
				message: this.message,
				retryable: this.retryable,
				...(this.details ? { details: this.details } : {}),
			},
		};
	}
}

export function ctfError(
	code: CtfErrorCode,
	message: string,
	options?: { retryable?: boolean; details?: Record<string, unknown> },
): CtfError {
	return new CtfError(code, message, options);
}

export function errorEnvelope(
	error: CtfError | Error,
	fallbackCode: CtfErrorCode = "unsupported_operation",
): CtfErrorEnvelope {
	if (error instanceof CtfError) return error.toEnvelope();
	return {
		schemaVersion: CTF_SCHEMA_VERSIONS.api,
		error: { code: fallbackCode, message: error.message, retryable: false },
	};
}
