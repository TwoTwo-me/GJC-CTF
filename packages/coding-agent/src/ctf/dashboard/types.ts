import type {
	CtfApiEnvelope,
	CtfApiError,
	CtfApiErrorEnvelope,
	CtfApiResponse,
	CtfApiSuccessResponse,
	ProjectionStatus,
} from "../contracts/api";
import { CTF_API_UNKNOWN_DIGEST } from "../contracts/api";
import type { Digest } from "../contracts/digest";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";

export { CtfApiEnvelopeSchema as CtfDashboardApiEnvelopeSchema } from "../contracts/api";
export const CTF_DASHBOARD_API_SCHEMA_VERSION = CTF_SCHEMA_VERSIONS.api;
export const CTF_DASHBOARD_DEFAULT_PORT = 3850;
export const CTF_DASHBOARD_UNKNOWN_DIGEST = CTF_API_UNKNOWN_DIGEST as Digest;

export const CTF_DASHBOARD_PROJECTION_STATUSES = [
	"current",
	"lagging",
	"integrity_error",
	"rebuilding",
] as const satisfies readonly ProjectionStatus[];
export type CtfDashboardProjectionStatus = (typeof CTF_DASHBOARD_PROJECTION_STATUSES)[number];

export type CtfDashboardJsonObject = Record<string, unknown>;

export type CtfDashboardIdentity = CtfApiEnvelope["identity"];
export type CtfDashboardError = CtfApiError;
export type CtfDashboardSuccessEnvelope<T extends CtfDashboardJsonObject = CtfDashboardJsonObject> =
	CtfApiSuccessResponse<T>;
export type CtfDashboardErrorEnvelope = CtfApiErrorEnvelope;
export type CtfDashboardApiEnvelope<T extends CtfDashboardJsonObject = CtfDashboardJsonObject> = CtfApiResponse<T>;
/**
 * Error details are intentionally filtered at the dashboard boundary. Reader
 * implementations may carry richer internal details, but only these identity
 * and readiness fields are safe to publish.
 */
const CTF_DASHBOARD_ERROR_ID_KEYS = new Set([
	"competitionId",
	"requestedCompetitionId",
	"workspaceCompetitionId",
	"manifestCompetitionId",
	"challengeId",
	"requestedChallengeId",
	"runId",
	"requestedRunId",
]);
const CTF_DASHBOARD_ERROR_REVISION_KEYS = new Set([
	"canonicalRevision",
	"projectionRevision",
	"projectionCanonicalRevision",
]);
const CTF_DASHBOARD_ERROR_SOURCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CTF_DASHBOARD_ERROR_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const CTF_DASHBOARD_ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'`(=:])(?:\/[^\s"'`<>()]*|[A-Za-z]:[\\/][^\s"'`<>]*)/;
const CTF_DASHBOARD_FILESYSTEM_CAUSE_PATTERN =
	/\b(?:EACCES|EADDRINUSE|EBADF|EBUSY|EEXIST|EFAULT|EINVAL|EIO|EISDIR|EMFILE|ENFILE|ENOENT|ENOMEM|ENOSPC|ENOTDIR|ENOTEMPTY|EPERM|EPIPE|EROFS|ETIMEDOUT)\b|no such file or directory|permission denied|read-only file system|syscall/i;

/** Keep ordinary stable messages while replacing path-bearing or filesystem causes with a safe fallback. */
export function sanitizeCtfDashboardErrorMessage(value: unknown, fallback: string): string {
	if (typeof value !== "string") return fallback;
	const message = value.trim();
	if (
		message.length === 0 ||
		CTF_DASHBOARD_ABSOLUTE_PATH_PATTERN.test(message) ||
		CTF_DASHBOARD_FILESYSTEM_CAUSE_PATTERN.test(message)
	) {
		return fallback;
	}
	return message;
}

/** Retain only non-sensitive identity/readiness details; paths, causes, and nested values are dropped. */
export function sanitizeCtfDashboardErrorDetails(
	value: CtfDashboardJsonObject | undefined,
): CtfDashboardJsonObject | undefined {
	if (value === undefined) return undefined;
	const safe: CtfDashboardJsonObject = {};
	for (const [key, detail] of Object.entries(value)) {
		if (CTF_DASHBOARD_ERROR_ID_KEYS.has(key)) {
			if (typeof detail === "string" && CTF_DASHBOARD_ERROR_ID_PATTERN.test(detail)) safe[key] = detail;
			continue;
		}
		if (CTF_DASHBOARD_ERROR_REVISION_KEYS.has(key)) {
			if (typeof detail === "number" && Number.isSafeInteger(detail) && detail >= 0) safe[key] = detail;
			continue;
		}
		if (key === "source" && typeof detail === "string" && CTF_DASHBOARD_ERROR_SOURCE_PATTERN.test(detail))
			safe[key] = detail;
	}
	return Object.keys(safe).length === 0 ? undefined : safe;
}

/** Build a public error without exposing reader internals or filesystem failures. */
export function sanitizeCtfDashboardError(error: CtfDashboardError, fallbackMessage: string): CtfDashboardError {
	const details = sanitizeCtfDashboardErrorDetails(error.details);
	return {
		code: error.code,
		message: sanitizeCtfDashboardErrorMessage(error.message, fallbackMessage),
		retryable: error.retryable,
		...(details === undefined ? {} : { details }),
	};
}
export type CtfDashboardResponse<T extends CtfDashboardJsonObject = CtfDashboardJsonObject> =
	CtfDashboardApiEnvelope<T>;

export interface CtfDashboardMetadataScope {
	competitionId?: string;
	challengeId?: string;
	runId?: string;
}

/** Metadata independently verified against the canonical journal/checkpoint. */
export interface CtfCanonicalMetadata {
	competitionId?: string;
	challengeId?: string;
	runId?: string;
	canonicalRevision: number;
	canonicalDigest: Digest;
	benchmarkLockDigest?: Digest;
	effectiveSkillDigest?: Digest;
	checkpointDigest?: Digest;
	journalByteOffset?: number;
}

export type CtfCanonicalMetadataReadResult =
	| { status: "available"; metadata: CtfCanonicalMetadata }
	| {
			status: "unavailable" | "integrity_error";
			code: string;
			message: string;
			details?: CtfDashboardJsonObject;
			metadata?: Partial<CtfCanonicalMetadata>;
	  };

export interface CtfProjectionMetadata {
	projectionRevision: number;
	projectionDigest: Digest;
}

export type CtfProjectionMetadataReadResult =
	| { status: "available"; metadata: CtfProjectionMetadata }
	| {
			status: "unavailable" | "integrity_error" | "rebuilding";
			code: string;
			message: string;
			details?: CtfDashboardJsonObject;
			metadata?: Partial<CtfProjectionMetadata>;
	  };

export type CtfDashboardRoute =
	| { kind: "competition"; competitionId: string }
	| { kind: "challenge-status"; challengeId: string }
	| { kind: "challenge-graph"; challengeId: string; revision?: number }
	| { kind: "run"; runId: string }
	| { kind: "run-events"; runId: string; cursor?: string }
	| { kind: "run-metrics"; runId: string }
	| { kind: "health" };

export type CtfDashboardProjectionValue = CtfDashboardJsonObject | null | undefined;

export interface CtfDashboardProjectionFailure {
	status: "unavailable" | "integrity_error" | "rebuilding";
	code: string;
	message: string;
	details?: CtfDashboardJsonObject;
	metadata?: Partial<CtfProjectionMetadata>;
}

export type CtfDashboardProjectionReadResult = CtfDashboardProjectionValue | CtfDashboardProjectionFailure;

/**
 * Reader seam for the derived projection. Canonical metadata is deliberately a
 * separate required method: a SQLite row, by itself, can never establish health.
 * Implementations may use readRoute or the route-specific methods; readRoute has
 * precedence when both are supplied.
 */
export interface CtfDashboardCanonicalMetadataReader {
	readCanonicalMetadata(scope?: CtfDashboardMetadataScope): Promise<CtfCanonicalMetadataReadResult>;
	/** A state identity is explicit so a dashboard cannot silently select another workspace. */
	readonly stateIdentity?: CtfDashboardStateIdentity;
}

export interface CtfDashboardStateIdentity {
	competitionId: string;
	stateRoot: string;
	challengeId?: string;
}

export interface CtfDashboardProjectionReader extends CtfDashboardCanonicalMetadataReader {
	readProjectionMetadata(scope?: CtfDashboardMetadataScope): Promise<CtfProjectionMetadataReadResult>;
	readRoute?(route: CtfDashboardRoute): Promise<CtfDashboardProjectionReadResult>;
	readCompetition?(competitionId: string): Promise<CtfDashboardProjectionReadResult>;
	readChallengeStatus?(challengeId: string): Promise<CtfDashboardProjectionReadResult>;
	readChallengeGraph?(challengeId: string, revision?: number): Promise<CtfDashboardProjectionReadResult>;
	readRun?(runId: string): Promise<CtfDashboardProjectionReadResult>;
	readRunEvents?(runId: string, cursor?: string): Promise<CtfDashboardProjectionReadResult>;
	readRunMetrics?(runId: string): Promise<CtfDashboardProjectionReadResult>;
}

export interface CtfDashboardSnapshot {
	canonical: CtfCanonicalMetadataReadResult;
	projection: CtfProjectionMetadataReadResult;
	projectionStatus: CtfDashboardProjectionStatus;
}

export type CtfDashboardAssetSource = (pathname: string) => Promise<Response | undefined> | Response | undefined;

export type CtfDashboardAssetArchive = Record<string, string>;

export function isCtfDashboardProjectionStatus(value: unknown): value is CtfDashboardProjectionStatus {
	return typeof value === "string" && (CTF_DASHBOARD_PROJECTION_STATUSES as readonly string[]).includes(value);
}

export function isCtfDashboardJsonObject(value: unknown): value is CtfDashboardJsonObject {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
