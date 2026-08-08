import { type CtfApiErrorEnvelope, type CtfApiSuccessResponse, parseApiEnvelope } from "../contracts/api";
import { isProjectionFailure, readCtfDashboardRoute, readCtfDashboardSnapshot } from "./projection-reader";
import {
	CTF_DASHBOARD_API_SCHEMA_VERSION,
	CTF_DASHBOARD_UNKNOWN_DIGEST,
	type CtfDashboardApiEnvelope,
	type CtfDashboardError,
	type CtfDashboardIdentity,
	type CtfDashboardJsonObject,
	type CtfDashboardMetadataScope,
	type CtfDashboardProjectionReader,
	type CtfDashboardProjectionReadResult,
	type CtfDashboardRoute,
	isCtfDashboardJsonObject,
	sanitizeCtfDashboardError,
} from "./types";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const API_PREFIX = "/api/ctf/v1/";

export interface CtfDashboardApiOptions {
	projectionReader: CtfDashboardProjectionReader;
	now?: () => Date;
}

export interface CtfDashboardRouteParseFailure {
	code: "invalid_route" | "invalid_id" | "invalid_query";
	message: string;
	details?: CtfDashboardJsonObject;
}

export type CtfDashboardRouteParseResult = CtfDashboardRoute | CtfDashboardRouteParseFailure;

function decodeSegment(value: string): string | undefined {
	try {
		const decoded = decodeURIComponent(value);
		return ID_PATTERN.test(decoded) ? decoded : undefined;
	} catch {
		return undefined;
	}
}

function parseNumericQuery(value: string | null, name: string): number | undefined | CtfDashboardRouteParseFailure {
	if (value === null || value === "") return undefined;
	if (!/^\d+$/.test(value)) return { code: "invalid_query", message: `${name} must be a non-negative integer` };
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed)) return { code: "invalid_query", message: `${name} is out of range` };
	return parsed;
}

/** Stable, exact GET route table. Unknown routes are never forwarded to a reader. */
export function parseCtfDashboardRoute(url: URL): CtfDashboardRouteParseResult {
	if (!url.pathname.startsWith(API_PREFIX)) return { code: "invalid_route", message: "not a CTF API route" };
	const parts = url.pathname.slice(API_PREFIX.length).split("/");
	if (parts.length === 2 && parts[0] === "competition") {
		const competitionId = decodeSegment(parts[1]);
		return competitionId === undefined
			? { code: "invalid_id", message: "competition id is invalid" }
			: { kind: "competition", competitionId };
	}
	if (parts.length === 3 && parts[0] === "challenges" && parts[2] === "status") {
		const challengeId = decodeSegment(parts[1]);
		return challengeId === undefined
			? { code: "invalid_id", message: "challenge id is invalid" }
			: { kind: "challenge-status", challengeId };
	}
	if (parts.length === 3 && parts[0] === "challenges" && parts[2] === "graph") {
		const challengeId = decodeSegment(parts[1]);
		if (challengeId === undefined) return { code: "invalid_id", message: "challenge id is invalid" };
		const revision = parseNumericQuery(url.searchParams.get("revision"), "revision");
		return typeof revision === "object"
			? revision
			: { kind: "challenge-graph", challengeId, ...(revision === undefined ? {} : { revision }) };
	}
	if (parts.length === 2 && parts[0] === "runs") {
		const runId = decodeSegment(parts[1]);
		return runId === undefined ? { code: "invalid_id", message: "run id is invalid" } : { kind: "run", runId };
	}
	if (parts.length === 3 && parts[0] === "runs" && parts[2] === "events") {
		const runId = decodeSegment(parts[1]);
		if (runId === undefined) return { code: "invalid_id", message: "run id is invalid" };
		const cursor = url.searchParams.get("cursor") ?? undefined;
		if (cursor !== undefined && cursor.length > 4096) return { code: "invalid_query", message: "cursor is too long" };
		return { kind: "run-events", runId, ...(cursor === undefined ? {} : { cursor }) };
	}
	if (parts.length === 3 && parts[0] === "runs" && parts[2] === "metrics") {
		const runId = decodeSegment(parts[1]);
		return runId === undefined
			? { code: "invalid_id", message: "run id is invalid" }
			: { kind: "run-metrics", runId };
	}
	if (parts.length === 1 && parts[0] === "health") return { kind: "health" };
	return { code: "invalid_route", message: "unknown CTF API route" };
}

function routeScope(route: CtfDashboardRoute | undefined): CtfDashboardMetadataScope | undefined {
	if (!route) return undefined;
	switch (route.kind) {
		case "competition":
			return { competitionId: route.competitionId };
		case "challenge-status":
		case "challenge-graph":
			return { challengeId: route.challengeId };
		case "run":
		case "run-events":
		case "run-metrics":
			return { runId: route.runId };
		case "health":
			return undefined;
	}
}

function routeIdentity(route: CtfDashboardRoute | undefined, canonicalCompetitionId?: string): CtfDashboardIdentity {
	const identity: CtfDashboardIdentity = {
		competitionId:
			canonicalCompetitionId !== undefined && ID_PATTERN.test(canonicalCompetitionId)
				? canonicalCompetitionId
				: "unknown",
	};
	if (!route) return identity;
	switch (route.kind) {
		case "competition":
			identity.competitionId = route.competitionId;
			break;
		case "challenge-status":
		case "challenge-graph":
			identity.challengeId = route.challengeId;
			break;
		case "run":
		case "run-events":
		case "run-metrics":
			identity.runId = route.runId;
			break;
		case "health":
			break;
	}
	return identity;
}

function generatedAt(now: () => Date): string {
	const value = now();
	return Number.isNaN(value.getTime()) ? new Date(0).toISOString() : value.toISOString();
}

function snapshotMetadata(
	snapshot: Awaited<ReturnType<typeof readCtfDashboardSnapshot>> | undefined,
): Pick<
	CtfDashboardApiEnvelope,
	| "canonicalRevision"
	| "canonicalDigest"
	| "projectionRevision"
	| "projectionDigest"
	| "projectionStatus"
	| "benchmarkLockDigest"
	| "effectiveSkillDigest"
> {
	const canonical = snapshot?.canonical.metadata;
	const projection = snapshot?.projection.metadata;
	return {
		canonicalRevision: canonical?.canonicalRevision ?? 0,
		canonicalDigest: canonical?.canonicalDigest ?? CTF_DASHBOARD_UNKNOWN_DIGEST,
		projectionRevision: projection?.projectionRevision ?? 0,
		projectionDigest: projection?.projectionDigest ?? CTF_DASHBOARD_UNKNOWN_DIGEST,
		projectionStatus: snapshot?.projectionStatus ?? "integrity_error",
		...(canonical?.benchmarkLockDigest === undefined ? {} : { benchmarkLockDigest: canonical.benchmarkLockDigest }),
		...(canonical?.effectiveSkillDigest === undefined
			? {}
			: { effectiveSkillDigest: canonical.effectiveSkillDigest }),
	};
}

type DashboardMetadata = Pick<
	CtfDashboardApiEnvelope,
	| "canonicalRevision"
	| "canonicalDigest"
	| "projectionRevision"
	| "projectionDigest"
	| "projectionStatus"
	| "benchmarkLockDigest"
	| "effectiveSkillDigest"
>;
type DashboardEnvelopeBase = Omit<CtfApiErrorEnvelope, "data" | "error">;

function envelope<T extends CtfDashboardJsonObject>(
	identity: CtfDashboardIdentity,
	metadata: DashboardMetadata,
	now: () => Date,
	data: T,
): CtfApiSuccessResponse<T>;
function envelope(
	identity: CtfDashboardIdentity,
	metadata: DashboardMetadata,
	now: () => Date,
	data: undefined,
	error: CtfDashboardError,
): CtfApiErrorEnvelope;
function envelope<T extends CtfDashboardJsonObject>(
	identity: CtfDashboardIdentity,
	metadata: DashboardMetadata,
	now: () => Date,
	data?: T,
	error?: CtfDashboardError,
): CtfDashboardApiEnvelope<T> {
	const base: DashboardEnvelopeBase = {
		apiSchemaVersion: CTF_DASHBOARD_API_SCHEMA_VERSION,
		identity,
		...metadata,
		generatedAt: generatedAt(now),
	};
	if (error !== undefined)
		return { ...base, error: sanitizeCtfDashboardError(error, "CTF dashboard request could not be completed") };
	if (data === undefined) throw new Error("CTF API success envelope requires data");
	return { ...base, data } as CtfApiSuccessResponse<T>;
}

export function parseCtfDashboardApiEnvelope(value: unknown): CtfDashboardApiEnvelope {
	return parseApiEnvelope(value);
}

export const validateCtfDashboardApiEnvelope = parseCtfDashboardApiEnvelope;
export const parseCtfDashboardApiResponse = parseCtfDashboardApiEnvelope;
export { isCtfApiError as isCtfDashboardError, isCtfApiSuccess as isCtfDashboardSuccess } from "../contracts/api";

function errorFromFailure(value: CtfDashboardProjectionReadResult): CtfDashboardError | undefined {
	if (!isProjectionFailure(value)) return undefined;
	return {
		code: value.code,
		message: value.message,
		retryable: value.status === "unavailable" || value.status === "rebuilding",
		...(value.details === undefined ? {} : { details: value.details }),
	};
}

function responseBody<T extends CtfDashboardJsonObject>(body: CtfDashboardApiEnvelope<T>, status: number): Response {
	return Response.json(body, {
		status,
		headers: {
			"Cache-Control": "no-store",
			"Content-Type": "application/json; charset=utf-8",
		},
	});
}

function routeDataStatus(snapshotStatus: CtfDashboardApiEnvelope["projectionStatus"]): number {
	return snapshotStatus === "current" ? 200 : 503;
}

function notFoundError(route: CtfDashboardRoute): CtfDashboardError {
	return { code: "not_found", message: `${route.kind} was not found`, retryable: false };
}

/** Build a fully enveloped error for local-policy and server failures. */
export function createCtfDashboardErrorResponse(
	status: number,
	code: string,
	message: string,
	now: () => Date = () => new Date(),
	details?: CtfDashboardJsonObject,
): Response {
	const error: CtfDashboardError = {
		code,
		message,
		retryable: status >= 500,
		...(details === undefined ? {} : { details }),
	};
	return responseBody(
		envelope({ competitionId: "unknown" }, snapshotMetadata(undefined), now, undefined, error),
		status,
	);
}

/**
 * Dispatch read-only CTF routes. This function does not inspect stats storage or
 * expose a mutation route; local-policy is intentionally a separate boundary.
 */
export function createCtfDashboardApiHandler(options: CtfDashboardApiOptions): (request: Request) => Promise<Response> {
	const now = options.now ?? (() => new Date());
	return async (request: Request): Promise<Response> => {
		let url: URL;
		try {
			url = new URL(request.url);
		} catch {
			return createCtfDashboardErrorResponse(400, "invalid_request", "request URL is invalid", now);
		}
		if (request.method !== "GET")
			return createCtfDashboardErrorResponse(405, "method_not_allowed", "only GET is supported", now);

		const parsed = parseCtfDashboardRoute(url);
		const route = "kind" in parsed ? parsed : undefined;
		if (!route) {
			const failure = parsed as CtfDashboardRouteParseFailure;
			return responseBody(
				envelope({ competitionId: "unknown" }, snapshotMetadata(undefined), now, undefined, {
					code: failure.code,
					message: failure.message,
					retryable: false,
					...(failure.details === undefined ? {} : { details: failure.details }),
				}),
				failure.code === "invalid_route" ? 404 : 400,
			);
		}
		let snapshot: Awaited<ReturnType<typeof readCtfDashboardSnapshot>> | undefined;
		try {
			snapshot = await readCtfDashboardSnapshot(options.projectionReader, routeScope(route));
		} catch {
			// readCtfDashboardSnapshot is defensive, but preserve the fail-closed boundary if a custom reader violates it.
			return createCtfDashboardErrorResponse(
				503,
				"canonical_metadata_unavailable",
				"CTF canonical metadata could not be verified",
				now,
			);
		}
		const metadata = snapshotMetadata(snapshot);
		const canonicalCompetitionId =
			snapshot.canonical.status === "available" ? snapshot.canonical.metadata.competitionId : undefined;
		const scopedIdentity = routeIdentity(route, canonicalCompetitionId);

		if (snapshot.projectionStatus === "integrity_error") {
			const sourceFailure = snapshot.canonical.status !== "available" ? snapshot.canonical : snapshot.projection;
			const error: CtfDashboardError =
				sourceFailure.status === "available"
					? {
							code: "projection_integrity_error",
							message: "CTF projection does not match canonical metadata",
							retryable: true,
						}
					: {
							code: sourceFailure.code,
							message: sourceFailure.message,
							retryable: sourceFailure.status !== "integrity_error",
							...(sourceFailure.details === undefined ? {} : { details: sourceFailure.details }),
						};
			return responseBody(envelope(scopedIdentity, metadata, now, undefined, error), 503);
		}
		if (snapshot.projectionStatus === "rebuilding") {
			return responseBody(
				envelope(scopedIdentity, metadata, now, undefined, {
					code: "projection_rebuilding",
					message: "CTF projection is rebuilding",
					retryable: true,
				}),
				503,
			);
		}
		if (snapshot.projectionStatus === "lagging" && route.kind !== "health") {
			return responseBody(
				envelope(scopedIdentity, metadata, now, undefined, {
					code: "projection_lagging",
					message: "CTF projection is behind canonical state",
					retryable: true,
					details: {
						canonicalRevision: metadata.canonicalRevision,
						projectionRevision: metadata.projectionRevision,
					},
				}),
				503,
			);
		}

		if (route.kind === "health") {
			return responseBody(
				envelope(scopedIdentity, metadata, now, {
					ready: snapshot.projectionStatus === "current",
					canonicalVerified: snapshot.canonical.status === "available",
					projectionStatus: snapshot.projectionStatus,
				}),
				200,
			);
		}

		const value = await readCtfDashboardRoute(options.projectionReader, route);
		const routeFailure = errorFromFailure(value);
		if (routeFailure) {
			return responseBody(envelope(scopedIdentity, metadata, now, undefined, routeFailure), 503);
		}
		if (value === undefined || value === null) {
			return responseBody(envelope(scopedIdentity, metadata, now, undefined, notFoundError(route)), 404);
		}
		if (!isCtfDashboardJsonObject(value)) {
			return responseBody(
				envelope(scopedIdentity, metadata, now, undefined, {
					code: "projection_data_invalid",
					message: "CTF projection returned a non-object response",
					retryable: false,
				}),
				503,
			);
		}
		return responseBody(envelope(scopedIdentity, metadata, now, value), routeDataStatus(snapshot.projectionStatus));
	};
}

export const createApiHandler = createCtfDashboardApiHandler;
export const dispatchCtfDashboardRoute = parseCtfDashboardRoute;
