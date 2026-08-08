/// <reference lib="dom" />
import {
	CTF_DASHBOARD_API_SCHEMA_VERSION,
	CTF_DASHBOARD_UNKNOWN_DIGEST,
	type CtfDashboardApiEnvelope,
	type CtfDashboardError,
	type CtfDashboardIdentity,
} from "./types";

export interface CtfDashboardPolicyRejection {
	status: 403 | 405;
	code: "forbidden_origin" | "forbidden_host" | "forbidden_port" | "forbidden_protocol" | "method_not_allowed";
	message: string;
	allow?: "GET";
}

function localHost(hostname: string): boolean {
	return hostname === "127.0.0.1" || hostname === "localhost";
}

function expectedAuthorities(boundPort: number): ReadonlySet<string> {
	if (boundPort === 80) return new Set(["127.0.0.1", "127.0.0.1:80", "localhost", "localhost:80"]);
	return new Set([`127.0.0.1:${boundPort}`, `localhost:${boundPort}`]);
}

function requestPort(url: URL): number {
	if (url.port !== "") return Number(url.port);
	return url.protocol === "https:" ? 443 : 80;
}

/**
 * Host/Origin/method checks intentionally remain CTF-owned. The stats server's
 * private validator is not imported, so this policy can evolve independently.
 */
export function inspectCtfDashboardLocalPolicy(
	req: Request,
	url: URL,
	boundPort: number,
): CtfDashboardPolicyRejection | undefined {
	if (url.protocol !== "http:")
		return { status: 403, code: "forbidden_protocol", message: "CTF dashboard requires http on loopback" };
	if (!localHost(url.hostname))
		return { status: 403, code: "forbidden_host", message: "CTF dashboard is loopback-only" };
	if (!Number.isInteger(boundPort) || boundPort < 1 || boundPort > 65535 || requestPort(url) !== boundPort) {
		return { status: 403, code: "forbidden_port", message: "request port does not match the dashboard listener" };
	}
	const authority = req.headers.get("Host");
	if (authority === null || !expectedAuthorities(boundPort).has(authority)) {
		return { status: 403, code: "forbidden_host", message: "Host must name the loopback dashboard listener" };
	}
	const origin = req.headers.get("Origin");
	if (origin !== null) {
		try {
			const parsed = new URL(origin);
			if (
				parsed.origin !== origin ||
				parsed.protocol !== "http:" ||
				!localHost(parsed.hostname) ||
				requestPort(parsed) !== boundPort ||
				parsed.origin !== url.origin
			) {
				return {
					status: 403,
					code: "forbidden_origin",
					message: "Origin must match the loopback dashboard listener",
				};
			}
		} catch {
			return { status: 403, code: "forbidden_origin", message: "Origin is invalid" };
		}
	}
	if (req.method !== "GET")
		return { status: 405, code: "method_not_allowed", message: "only GET is supported", allow: "GET" };
	return undefined;
}

function policyEnvelope(rejection: CtfDashboardPolicyRejection, generatedAt: string): CtfDashboardApiEnvelope {
	const identity: CtfDashboardIdentity = { competitionId: "unknown" };
	const error: CtfDashboardError = {
		code: rejection.code,
		message: rejection.message,
		retryable: false,
	};
	return {
		apiSchemaVersion: CTF_DASHBOARD_API_SCHEMA_VERSION,
		identity,
		canonicalRevision: 0,
		canonicalDigest: CTF_DASHBOARD_UNKNOWN_DIGEST,
		projectionRevision: 0,
		projectionDigest: CTF_DASHBOARD_UNKNOWN_DIGEST,
		projectionStatus: "integrity_error",
		generatedAt,
		error,
	};
}

/** Return an enveloped policy response so even rejected requests expose no bare status shape. */
export function ctfDashboardPolicyResponse(
	rejection: CtfDashboardPolicyRejection,
	now: () => Date = () => new Date(),
): Response {
	const date = now();
	const generatedAt = Number.isNaN(date.getTime()) ? new Date(0).toISOString() : date.toISOString();
	const headers: HeadersInit = {
		"Cache-Control": "no-store",
		"Content-Type": "application/json; charset=utf-8",
	};
	if (rejection.allow !== undefined) headers.Allow = rejection.allow;
	return Response.json(policyEnvelope(rejection, generatedAt), { status: rejection.status, headers });
}

/** Compatibility helper for callers that want a direct Response validator. */
export function validateCtfDashboardLocalPolicy(
	req: Request,
	url: URL,
	boundPort: number,
	now?: () => Date,
): Response | undefined {
	const rejection = inspectCtfDashboardLocalPolicy(req, url, boundPort);
	return rejection === undefined ? undefined : ctfDashboardPolicyResponse(rejection, now);
}

export const validateLocalPolicy = validateCtfDashboardLocalPolicy;
export const validateCtfDashboardRequest = validateCtfDashboardLocalPolicy;
export const validateApiRequest = validateCtfDashboardLocalPolicy;
