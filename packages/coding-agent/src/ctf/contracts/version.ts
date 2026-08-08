import * as z from "zod/v4";

/** Independent schema identifiers used by the CTF control-plane contracts. */
export const CTF_SCHEMA_VERSIONS = {
	manifest: "ctf-manifest-1",
	registration: "ctf-registration-1",
	event: "ctf-event-1",
	state: "ctf-state-1",
	runOwner: "ctf-run-owner-1",
	intent: "ctf-intent-2",
	graph: "ctf-graph-1",
	ranking: "ctf-rank-v1",
	benchmark: "ctf-benchmark-1",
	benchmarkLock: "ctf-benchmark-lock-1",
	oracleEntry: "ctf-oracle-entry-1",
	oracleResult: "ctf-oracle-result-1",
	metrics: "ctf-metrics-1",
	api: "ctf-api-1",
	skill: "ctf-skill-1",
	safetyMaxima: "ctf-safety-maxima-1",
	operationalLimits: "ctf-operational-limits-1",
} as const;

export type CtfSchemaName = keyof typeof CTF_SCHEMA_VERSIONS;
export type CtfSchemaVersion = (typeof CTF_SCHEMA_VERSIONS)[CtfSchemaName];

export const CtfSchemaVersionSchema = z.string().regex(/^ctf-[a-z0-9-]+-(?:v?\d+)$/);

export class CtfVersionError extends Error {
	readonly code = "unknown_schema_major" as const;
	readonly schemaVersion: string;
	readonly expected?: string;

	constructor(schemaVersion: string, expected?: string) {
		super(`Unsupported CTF schema version: ${schemaVersion}${expected ? ` (expected ${expected})` : ""}`);
		this.name = "CtfVersionError";
		this.schemaVersion = schemaVersion;
		this.expected = expected;
	}
}

/** Return the numeric major in a CTF schema identifier, rejecting malformed identifiers. */
export function schemaMajor(schemaVersion: string): number {
	const match = /^ctf-[a-z0-9-]+-(?:v?)(\d+)$/.exec(schemaVersion);
	if (!match) throw new CtfVersionError(schemaVersion);
	return Number(match[1]);
}

/** Require an exact supported schema identifier; no implicit migration is performed. */
export function assertSupportedSchemaVersion(
	schemaVersion: unknown,
	expected: CtfSchemaVersion | readonly CtfSchemaVersion[],
): asserts schemaVersion is CtfSchemaVersion {
	if (typeof schemaVersion !== "string") throw new CtfVersionError(String(schemaVersion));
	const accepted = typeof expected === "string" ? [expected] : expected;
	if (!accepted.includes(schemaVersion as CtfSchemaVersion)) {
		throw new CtfVersionError(schemaVersion, accepted.join(" or "));
	}
}

/** Parse and gate one of the independently versioned contract families. */
export function assertKnownMajor(
	schemaVersion: unknown,
	schema: CtfSchemaName,
): asserts schemaVersion is CtfSchemaVersion {
	assertSupportedSchemaVersion(schemaVersion, CTF_SCHEMA_VERSIONS[schema]);
}

export function isSupportedSchemaVersion(
	schemaVersion: unknown,
	schema: CtfSchemaName,
): schemaVersion is CtfSchemaVersion {
	return typeof schemaVersion === "string" && schemaVersion === CTF_SCHEMA_VERSIONS[schema];
}
export const CTF_SCHEMA_VERSION = CTF_SCHEMA_VERSIONS;
export const SUPPORTED_CTF_SCHEMA_VERSIONS = CTF_SCHEMA_VERSIONS;
export const parseCtfSchemaVersion = schemaMajor;
export const isKnownCtfSchemaVersion = isSupportedSchemaVersion;
export const CTF_VERSION_FIELDS = {
	manifestVersion: CTF_SCHEMA_VERSIONS.manifest,
	stateSchemaVersion: CTF_SCHEMA_VERSIONS.state,
	graphSchemaVersion: CTF_SCHEMA_VERSIONS.graph,
	apiSchemaVersion: CTF_SCHEMA_VERSIONS.api,
	metricsSchemaVersion: CTF_SCHEMA_VERSIONS.metrics,
	benchmarkSchemaVersion: CTF_SCHEMA_VERSIONS.benchmark,
	skillVersion: CTF_SCHEMA_VERSIONS.skill,
} as const;
