import { createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalJson, type Digest, digestsEqual, isDigest, sha256Hex } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type OracleEntryV1,
	type OracleRegistryV1,
	type OracleResultV1,
	oracleRegistryDigest,
	type TrustedOracleKeyV1,
	type TrustedOracleRegistryV1,
	validateOracleEntry,
	validateOracleRegistry,
	validateOracleResult,
	validateTrustedOracleRegistryShape,
} from "../contracts/oracle";
export type TrustedOracleRegistry = TrustedOracleRegistryV1;
export type OracleRequestIdentity = Readonly<{
	runId: string;
	challengeId: string;
	nonce: string;
	candidateDigest: Digest;
	inputDigest: Digest;
}>;

export type VerifiedOracleResult = Readonly<{
	verified: true;
	result: OracleResultV1;
	entry: OracleEntryV1;
	key: TrustedOracleKeyV1;
	registryDigest: Digest;
}>;

function oracleFailure(message: string, details?: Record<string, unknown>): never {
	throw new CtfError("oracle_integrity_error", message, { details });
}

function decodeSignature(value: string): Buffer {
	const trimmed = value.trim();
	if (!trimmed) oracleFailure("oracle signature is empty");
	if (/^[a-f0-9]+$/i.test(trimmed) && trimmed.length % 2 === 0) return Buffer.from(trimmed, "hex");
	try {
		const decoded = Buffer.from(trimmed, "base64");
		if (decoded.length === 0 || decoded.toString("base64").replace(/=+$/, "") !== trimmed.replace(/=+$/, ""))
			oracleFailure("oracle signature encoding is invalid");
		return decoded;
	} catch {
		oracleFailure("oracle signature encoding is invalid");
	}
}

function publicKeyObject(key: TrustedOracleKeyV1): ReturnType<typeof createPublicKey> {
	try {
		if (key.publicKey.includes("BEGIN PUBLIC KEY")) return createPublicKey(key.publicKey);
		const der = Buffer.from(key.publicKey, "base64");
		if (der.length === 0) oracleFailure(`trusted oracle key ${key.keyId} is empty`);
		return createPublicKey({ key: der, format: "der", type: "spki" });
	} catch {
		oracleFailure(`trusted oracle key ${key.keyId} cannot be parsed`);
	}
}

function verifySignedPayload(payload: unknown, signature: string, key: TrustedOracleKeyV1): boolean {
	try {
		return verifySignature(
			null,
			Buffer.from(canonicalJson(payload), "utf8"),
			publicKeyObject(key),
			decodeSignature(signature),
		);
	} catch (error) {
		if (error instanceof CtfError) throw error;
		oracleFailure(`signature verification failed for trusted oracle key ${key.keyId}`);
	}
}

function verifyKeyFingerprint(key: TrustedOracleKeyV1): void {
	if (!isDigest(key.fingerprint) || !digestsEqual(sha256Hex(key.publicKey), key.fingerprint))
		oracleFailure(`trusted oracle key ${key.keyId} fingerprint mismatch`);
}

function keyById(keys: readonly TrustedOracleKeyV1[], keyId: string): TrustedOracleKeyV1 {
	const matches = keys.filter(key => key.keyId === keyId);
	if (matches.length !== 1 || matches[0] === undefined)
		oracleFailure(`trusted oracle key is missing or duplicated: ${keyId}`);
	const key = matches[0];
	verifyKeyFingerprint(key);
	if (!key.active) oracleFailure(`trusted oracle key is inactive: ${keyId}`);
	return key;
}

/** Validate registry integrity and signatures before any result can be trusted. */
export function validateTrustedOracleRegistry(value: unknown): TrustedOracleRegistry {
	const trusted = validateTrustedOracleRegistryShape(value);
	const registry = validateOracleRegistry(trusted.registry);
	const ids = new Set<string>();
	for (const key of trusted.keys) {
		if (ids.has(key.keyId)) oracleFailure(`duplicate trusted oracle key: ${key.keyId}`);
		ids.add(key.keyId);
		if (key.algorithm !== "ed25519") oracleFailure(`unsupported trusted oracle algorithm: ${key.algorithm}`);
		verifyKeyFingerprint(key);
	}
	for (const entry of registry.entries) {
		const signerKey = keyById(trusted.keys, entry.signerKeyId);
		keyById(trusted.keys, entry.publicKeyId);
		const { signature: _signature, ...unsignedEntry } = entry;
		if (!verifySignedPayload(unsignedEntry, entry.signature, signerKey))
			oracleFailure(`oracle entry signature is invalid: ${entry.oracleId}`);
	}
	return { registry, keys: [...trusted.keys] };
}

/**
 * Verify an oracle result against the pinned registry, challenge allowlist,
 * request identity, and trusted Ed25519 signature.  There is no inferred
 * success path: callers only receive a value with `verified: true` here.
 */
export function verifyTrustedOracleResult(
	trusted: TrustedOracleRegistry,
	value: unknown,
	expected: OracleRequestIdentity,
): VerifiedOracleResult {
	const checked = validateTrustedOracleRegistry(trusted);
	const parsed = validateOracleResult(value, undefined, expected);
	const entry = checked.registry.entries.find(candidate => candidate.oracleId === parsed.oracleId);
	if (entry === undefined) oracleFailure(`oracle is not registered: ${parsed.oracleId}`);
	validateOracleEntry(entry);
	if (parsed.schemaVersion !== entry.outputSchemaVersion)
		oracleFailure("oracle result schema version does not match registered output schema");
	if (!entry.allowedChallengeIds.includes(parsed.challengeId))
		oracleFailure(`oracle is not authorized for challenge: ${parsed.challengeId}`);
	const key = keyById(checked.keys, entry.publicKeyId);
	const { signature: _signature, ...unsignedResult } = parsed;
	if (!verifySignedPayload(unsignedResult, parsed.signature, key)) oracleFailure("oracle result signature is invalid");
	return {
		verified: true,
		result: parsed,
		entry,
		key,
		registryDigest: checked.registry.registryDigest as Digest,
	};
}
/**
 * Validate an oracle registry and, when supplied, bind it to an expected digest.
 * This checks registry metadata only; it never evaluates a result or creates evidence.
 */
export function validateOracleRegistryBinding(value: unknown, expectedDigest?: Digest): OracleRegistryV1 {
	const registry = validateOracleRegistry(value);
	if (expectedDigest !== undefined && !digestsEqual(registry.registryDigest, expectedDigest)) {
		throw new CtfError("digest_mismatch", "oracle registry digest mismatch");
	}
	return registry;
}

export function trustedOracleRegistryDigest(trusted: TrustedOracleRegistry): Digest {
	const checked = validateTrustedOracleRegistry(trusted);
	return oracleRegistryDigest(checked.registry);
}

export function oracleResultSigningPayload(result: OracleResultV1): string {
	const { signature: _signature, ...unsignedResult } = result;
	return canonicalJson(unsignedResult);
}

export const validateTrustedRegistry = validateTrustedOracleRegistry;
export const verifyOracleResult = verifyTrustedOracleResult;
