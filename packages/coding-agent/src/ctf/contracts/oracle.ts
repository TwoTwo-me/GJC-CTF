import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const OracleEntryV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.oracleEntry),
		oracleId: CtfIdSchema,
		protocolVersion: z.string().min(1).max(64),
		executableRef: z.string().min(1).max(1024),
		imageDigest: DigestSchema,
		artifactDigest: DigestSchema,
		backendDigest: DigestSchema.optional(),
		allowedChallengeIds: z.array(CtfIdSchema).min(1),
		publicKeyId: CtfIdSchema,
		signerKeyId: CtfIdSchema,
		signature: z.string().min(1).max(4096),
		outputSchemaVersion: z.string().min(1).max(64),
	})
	.strict();
export type OracleEntryV1 = z.infer<typeof OracleEntryV1Schema>;

export const OracleSanitizedSummaryV1Schema = z.enum(["pass", "fail", "invalid", "error", "unavailable"]);
export type OracleSanitizedSummaryV1 = z.infer<typeof OracleSanitizedSummaryV1Schema>;

export const TrustedOracleKeyV1Schema = z
	.object({
		keyId: CtfIdSchema,
		algorithm: z.enum(["ed25519"]),
		publicKey: z.string().min(1),
		fingerprint: DigestSchema,
		active: z.boolean(),
	})
	.strict();
export type TrustedOracleKeyV1 = z.infer<typeof TrustedOracleKeyV1Schema>;

export const OracleRegistryV1Schema = z
	.object({
		schemaVersion: z.literal("ctf-oracle-registry-1"),
		entries: z.array(OracleEntryV1Schema),
		registryDigest: DigestSchema,
	})
	.strict();
export type OracleRegistryV1 = z.infer<typeof OracleRegistryV1Schema>;
export const TrustedOracleRegistryV1Schema = z
	.object({
		registry: OracleRegistryV1Schema,
		keys: z.array(TrustedOracleKeyV1Schema).min(1),
	})
	.strict();
export type TrustedOracleRegistryV1 = z.infer<typeof TrustedOracleRegistryV1Schema>;
export const OracleTrustAnchorsV1Schema = z
	.object({
		registrySignerFingerprint: DigestSchema,
		resultSignerFingerprint: DigestSchema,
	})
	.strict();
export type OracleTrustAnchorsV1 = z.infer<typeof OracleTrustAnchorsV1Schema>;

export type TrustedOracleRegistry = TrustedOracleRegistryV1;
export const OracleResultV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.oracleResult),
		oracleId: CtfIdSchema,
		runId: CtfIdSchema,
		challengeId: CtfIdSchema,
		nonce: CtfIdSchema,
		candidateDigest: DigestSchema,
		inputDigest: DigestSchema,
		verdict: z.enum(["pass", "fail", "invalid", "error"]),
		verifierVersion: z.string().min(1).max(128),
		outputDigest: DigestSchema,
		sanitizedSummary: OracleSanitizedSummaryV1Schema,

		signature: z.string().min(1).max(16_384),
		issuedAt: TimestampSchema.optional(),
	})
	.strict();
export type OracleResultV1 = z.infer<typeof OracleResultV1Schema>;

export function oracleEntryDigest(entry: OracleEntryV1): Digest {
	return canonicalDigest(entry);
}

export function oracleRegistryDigest(registry: OracleRegistryV1 | Omit<OracleRegistryV1, "registryDigest">): Digest {
	return canonicalDigest(registry, ["registryDigest"]);
}

export function oracleResultDigest(result: OracleResultV1): Digest {
	return canonicalDigest(result);
}

export function validateOracleEntry(value: unknown): OracleEntryV1 {
	const parsed = OracleEntryV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("oracle_integrity_error", "oracle registry entry is invalid", {
			details: { issues: parsed.error.issues },
		});
	const entry = parsed.data;
	assertKnownMajor(entry.schemaVersion, "oracleEntry");
	if (new Set(entry.allowedChallengeIds).size !== entry.allowedChallengeIds.length)
		throw new CtfError("oracle_integrity_error", "oracle allowlist contains duplicate challenge IDs");
	return entry;
}

export function validateOracleRegistry(value: unknown): OracleRegistryV1 {
	const parsed = OracleRegistryV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("oracle_integrity_error", "oracle registry is invalid", {
			details: { issues: parsed.error.issues },
		});
	const registry = parsed.data;
	const ids = new Set<string>();
	for (const entry of registry.entries) {
		validateOracleEntry(entry);
		if (ids.has(entry.oracleId))
			throw new CtfError("oracle_integrity_error", `duplicate oracle ID: ${entry.oracleId}`);
		ids.add(entry.oracleId);
	}
	if (!digestsEqual(oracleRegistryDigest(registry), registry.registryDigest))
		throw new CtfError("digest_mismatch", "oracle registry digest mismatch");
	return registry;
}
export function validateTrustedOracleRegistryShape(value: unknown): TrustedOracleRegistryV1 {
	const parsed = TrustedOracleRegistryV1Schema.safeParse(value);
	if (!parsed.success) {
		throw new CtfError("oracle_integrity_error", "trusted oracle registry is invalid", {
			details: { issues: parsed.error.issues },
		});
	}
	return parsed.data;
}
export function validateOracleTrustAnchors(value: unknown): OracleTrustAnchorsV1 {
	const parsed = OracleTrustAnchorsV1Schema.safeParse(value);
	if (!parsed.success) {
		throw new CtfError("oracle_integrity_error", "oracle trust anchors are invalid", {
			details: { issues: parsed.error.issues },
		});
	}
	if (parsed.data.registrySignerFingerprint === parsed.data.resultSignerFingerprint)
		throw new CtfError("oracle_integrity_error", "oracle trust-anchor roles must use distinct principals");
	return parsed.data;
}

export function validateOracleResult(
	value: unknown,
	entry?: OracleEntryV1,
	expected?: { runId: string; challengeId: string; nonce: string; candidateDigest: string; inputDigest: string },
): OracleResultV1 {
	const parsed = OracleResultV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("oracle_integrity_error", "oracle result is invalid", {
			details: { issues: parsed.error.issues },
		});
	const result = parsed.data;
	assertKnownMajor(result.schemaVersion, "oracleResult");
	if (entry !== undefined) {
		validateOracleEntry(entry);
		if (entry.oracleId !== result.oracleId || !entry.allowedChallengeIds.includes(result.challengeId))
			throw new CtfError("oracle_integrity_error", "oracle result is not authorized for this challenge");
	}
	if (expected !== undefined) {
		for (const field of ["runId", "challengeId", "nonce", "candidateDigest", "inputDigest"] as const) {
			if (result[field] !== expected[field])
				throw new CtfError("oracle_integrity_error", `oracle result ${field} does not match request`);
		}
	}
	return result;
}
export const OracleEntrySchema = OracleEntryV1Schema;
export const OracleResultSchema = OracleResultV1Schema;
export const TrustedOracleRegistrySchema = TrustedOracleRegistryV1Schema;
export const parseOracleEntry = validateOracleEntry;
export const parseOracleResult = validateOracleResult;
export const parseTrustedOracleRegistry = validateTrustedOracleRegistryShape;
export const OracleTrustAnchorsSchema = OracleTrustAnchorsV1Schema;
export const parseOracleTrustAnchors = validateOracleTrustAnchors;
