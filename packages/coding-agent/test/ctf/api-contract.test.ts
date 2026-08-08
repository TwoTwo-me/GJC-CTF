import { describe, expect, it } from "bun:test";
import { parseCtfArgv } from "../../src/ctf/cli";
import { CTF_SCHEMA_VERSIONS, isCtfApiError, isCtfApiSuccess, parseApiEnvelope } from "../../src/ctf/contracts";
import { parseCtfDashboardApiEnvelope } from "../../src/ctf/dashboard/api";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const GENERATED_AT = "2026-01-01T00:00:00.000Z";

function metadata(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
	return {
		apiSchemaVersion: CTF_SCHEMA_VERSIONS.api,
		identity: { competitionId: "competition-1" },
		canonicalRevision: 3,
		canonicalDigest: DIGEST_A,
		projectionRevision: 3,
		projectionDigest: DIGEST_A,
		projectionStatus: "current",
		generatedAt: GENERATED_AT,
		...overrides,
	};
}

function success(data: Record<string, unknown> = { ready: true }): Record<string, unknown> {
	return { ...metadata(), data };
}

function error(
	status: "unavailable" | "integrity_error" | "rebuilding" | "lagging" = "integrity_error",
	overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
	return {
		...metadata({
			canonicalRevision: status === "lagging" ? 4 : 0,
			canonicalDigest: status === "lagging" ? DIGEST_A : "0".repeat(64),
			projectionRevision: status === "lagging" ? 3 : 0,
			projectionDigest: status === "lagging" ? DIGEST_B : "0".repeat(64),
			projectionStatus: status,
		}),
		error: {
			code: status === "lagging" ? "projection_lagging" : "canonical_metadata_unavailable",
			message: "CTF state is not available",
			retryable: true,
		},
		...overrides,
	};
}

describe("CTF CLI and API envelope contracts", () => {
	it("parses every CLI surface with its command discriminant", () => {
		const surfaces = [
			["init", "--json"],
			["status", "--json"],
			["challenge", "add"],
			["solve", "challenge-1"],
			["dashboard"],
			["resume", "run-1"],
		] as const;
		for (const argv of surfaces) {
			const invocation = parseCtfArgv(argv);
			expect(invocation.kind).toBe("command");
			if (invocation.kind !== "command") continue;
			expect(invocation.command).toBe(argv[0] === "challenge" ? "challenge add" : argv[0]);
		}
	});

	it("keeps success and explicit error envelopes as typed discriminants", () => {
		const parsedSuccess = parseApiEnvelope(success());
		const parsedError = parseApiEnvelope(error());
		expect(isCtfApiSuccess(parsedSuccess)).toBe(true);
		expect(isCtfApiError(parsedSuccess)).toBe(false);
		expect(isCtfApiSuccess(parsedError)).toBe(false);
		expect(isCtfApiError(parsedError)).toBe(true);
		if (isCtfApiSuccess(parsedSuccess)) expect(parsedSuccess.data.ready).toBe(true);
		if (isCtfApiError(parsedError)) expect(parsedError.error.code).toBe("canonical_metadata_unavailable");
	});

	it("accepts unavailable, integrity, and lagging metadata without claiming health", () => {
		const unavailable = parseCtfDashboardApiEnvelope(error("unavailable"));
		const integrityError = parseCtfDashboardApiEnvelope(error("integrity_error"));
		const rebuilding = parseCtfDashboardApiEnvelope(error("rebuilding"));
		const lagging = parseCtfDashboardApiEnvelope(error("lagging"));
		expect(unavailable.projectionStatus).toBe("unavailable");
		expect(unavailable.canonicalRevision).toBe(0);
		expect(unavailable.canonicalDigest).toBe("0".repeat(64));
		expect(integrityError.projectionStatus).toBe("integrity_error");
		expect(integrityError.canonicalRevision).toBe(0);
		expect(rebuilding.projectionStatus).toBe("rebuilding");
		expect(rebuilding.canonicalRevision).toBe(0);
		expect(lagging.projectionStatus).toBe("lagging");
		expect(lagging.canonicalRevision).toBe(4);
		expect(lagging.projectionRevision).toBe(3);
	});

	it("rejects malformed and falsely healthy envelopes", () => {
		expect(() =>
			parseApiEnvelope({ ...success(), error: { code: "bad", message: "both", retryable: false } }),
		).toThrow();
		expect(() =>
			parseApiEnvelope({ ...metadata({ canonicalRevision: 0, projectionRevision: 0 }), data: { ready: true } }),
		).toThrow();
		expect(() =>
			parseApiEnvelope({ ...metadata({ projectionStatus: "integrity_error" }), data: { graph: [] } }),
		).toThrow();
		expect(() => parseApiEnvelope({ ...error("lagging", { projectionRevision: 0 }) })).toThrow();
		expect(() =>
			parseApiEnvelope({
				...metadata({ canonicalDigest: "0".repeat(64), projectionDigest: "0".repeat(64) }),
				data: { ready: true },
			}),
		).toThrow();
		expect(() =>
			parseApiEnvelope({ ...metadata({ projectionStatus: "rebuilding" }), data: { graph: [] } }),
		).toThrow();
		expect(() =>
			parseApiEnvelope({ ...metadata({ projectionStatus: "unavailable" }), data: { graph: [] } }),
		).toThrow();
	});

	it("rejects an error-shaped envelope without its explicit error object", () => {
		const malformed = metadata({ projectionStatus: "integrity_error", canonicalRevision: 0, projectionRevision: 0 });
		expect(() => parseApiEnvelope(malformed)).toThrow();
	});
});
