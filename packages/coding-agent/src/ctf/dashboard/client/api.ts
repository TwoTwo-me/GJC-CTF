import type { CtfDashboardApiEnvelope, CtfDashboardJsonObject } from "../types";

export type CtfDashboardClientResponse = CtfDashboardApiEnvelope<CtfDashboardJsonObject>;

export async function getCtfDashboard(pathname: string, init?: RequestInit): Promise<CtfDashboardClientResponse> {
	const headers = new Headers(init?.headers);
	headers.set("Accept", "application/json");
	const response = await fetch(pathname, { ...init, method: "GET", headers });
	let body: unknown;
	try {
		body = await response.json();
	} catch {
		throw new Error(`CTF dashboard returned a non-JSON response (${response.status})`);
	}
	if (typeof body !== "object" || body === null || !("apiSchemaVersion" in body) || !("projectionStatus" in body)) {
		throw new Error("CTF dashboard returned an invalid response envelope");
	}
	if (!response.ok && !("error" in body)) throw new Error(`CTF dashboard request failed (${response.status})`);
	return body as CtfDashboardClientResponse;
}

export function competitionPath(id: string): string {
	return `/api/ctf/v1/competition/${encodeURIComponent(id)}`;
}

export function challengeStatusPath(id: string): string {
	return `/api/ctf/v1/challenges/${encodeURIComponent(id)}/status`;
}

export function challengeGraphPath(id: string, revision?: number): string {
	const suffix = revision === undefined ? "" : `?revision=${encodeURIComponent(String(revision))}`;
	return `/api/ctf/v1/challenges/${encodeURIComponent(id)}/graph${suffix}`;
}

export function runPath(id: string): string {
	return `/api/ctf/v1/runs/${encodeURIComponent(id)}`;
}

export function runEventsPath(id: string, cursor?: string): string {
	return `/api/ctf/v1/runs/${encodeURIComponent(id)}/events${cursor === undefined ? "" : `?cursor=${encodeURIComponent(cursor)}`}`;
}

export function runMetricsPath(id: string): string {
	return `/api/ctf/v1/runs/${encodeURIComponent(id)}/metrics`;
}

export function healthPath(): string {
	return "/api/ctf/v1/health";
}
