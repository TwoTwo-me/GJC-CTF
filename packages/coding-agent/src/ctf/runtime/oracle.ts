import { createPublicKey, type KeyObject, verify as verifySignature } from "node:crypto";
import { canonicalJson, type Digest, digestsEqual, isDigest, sha256Hex } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type OracleEntryV1,
	type OracleEvaluationIdentityV2,
	type OracleRegistryV1,
	type OracleResultV1,
	type OracleResultV2,
	type OracleTrustAnchorsV1,
	oracleRegistryDigest,
	type TrustedOracleKeyV1,
	type TrustedOracleRegistryV1,
	validateOracleEntry,
	validateOracleRegistry,
	validateOracleResult,
	validateOracleResultV2,
	validateOracleTrustAnchors,
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
export type VerifiedAnchoredOracleResultV2 = Readonly<{
	verified: true;
	result: OracleResultV2;
	entry: OracleEntryV1;
	oracleRegistryDigest: Digest;
	registrySignerFingerprint: Digest;
	resultSignerFingerprint: Digest;
}>;

export class AnchoredOracleAuthority {
	readonly #anchors: OracleTrustAnchorsV1;
	readonly #expectedRegistryDigest: Digest;

	private constructor(anchors: OracleTrustAnchorsV1, expectedRegistryDigest: Digest) {
		this.#anchors = anchors;
		this.#expectedRegistryDigest = expectedRegistryDigest;
	}

	static create(trustAnchors: unknown, expectedRegistryDigest: Digest): AnchoredOracleAuthority {
		if (!isDigest(expectedRegistryDigest)) oracleFailure("expected oracle registry digest is invalid");
		return new AnchoredOracleAuthority(validateOracleTrustAnchors(trustAnchors), expectedRegistryDigest);
	}

	verify(registry: unknown, value: unknown, expected: OracleEvaluationIdentityV2): VerifiedAnchoredOracleResultV2 {
		const trusted = validateAnchoredOracleRegistry(registry, this.#anchors);
		if (!digestsEqual(trusted.registry.registryDigest, this.#expectedRegistryDigest))
			oracleFailure("anchored oracle registry digest does not match the expected registry");
		const result = validateOracleResultV2(value, undefined, expected);
		const entry = trusted.registry.entries.find(candidate => candidate.oracleId === result.oracleId);
		if (entry === undefined) oracleFailure(`oracle is not registered: ${result.oracleId}`);
		if (result.schemaVersion !== entry.outputSchemaVersion)
			oracleFailure("oracle V2 result schema version does not match registered output schema");
		if (!entry.allowedChallengeIds.includes(result.identity.challengeId))
			oracleFailure(`oracle is not authorized for challenge: ${result.identity.challengeId}`);
		const resultKey = keyById(trusted.keys, entry.publicKeyId);
		const { signature: _signature, ...unsignedResult } = result;
		if (!verifySignedPayload(unsignedResult, result.signature, resultKey))
			oracleFailure("oracle V2 result signature is invalid");
		return {
			verified: true,
			result,
			entry,
			oracleRegistryDigest: requireOracleDigest(trusted.registry.registryDigest, "anchored oracle registry digest"),
			registrySignerFingerprint: requireOracleDigest(
				this.#anchors.registrySignerFingerprint,
				"registry signer fingerprint",
			),
			resultSignerFingerprint: requireOracleDigest(resultKey.fingerprint, "result signer fingerprint"),
		};
	}
}

export function createAnchoredOracleAuthority(
	trustAnchors: unknown,
	expectedRegistryDigest: Digest,
): AnchoredOracleAuthority {
	return AnchoredOracleAuthority.create(trustAnchors, expectedRegistryDigest);
}

function oracleFailure(message: string, details?: Record<string, unknown>): never {
	throw new CtfError("oracle_integrity_error", message, { details });
}

function requireOracleDigest(value: unknown, label: string): Digest {
	if (!isDigest(value)) oracleFailure(`${label} is invalid`);
	return value;
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

function publicKeyObject(key: TrustedOracleKeyV1): KeyObject {
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

/** Validate registry integrity and signatures without assigning an authority root. */
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
 * Validate an authority against independently configured signer fingerprints.
 * Unlike shape/signature validation, this cannot make a caller-provided key a root.
 */
export function validateAnchoredOracleRegistry(value: unknown, trustAnchors: unknown): TrustedOracleRegistry {
	const anchors = validateOracleTrustAnchors(trustAnchors);
	const trusted = validateTrustedOracleRegistry(value);
	const activeKeys = trusted.keys.filter(key => key.active);
	if (activeKeys.length !== 2) oracleFailure("anchored oracle registry must contain exactly two active keys");
	const activeFingerprints = new Set(activeKeys.map(key => key.fingerprint));
	if (
		activeFingerprints.size !== 2 ||
		!activeFingerprints.has(anchors.registrySignerFingerprint) ||
		!activeFingerprints.has(anchors.resultSignerFingerprint)
	) {
		oracleFailure("anchored oracle registry active keys do not exactly match trust anchors");
	}
	for (const entry of trusted.registry.entries) {
		const registrySigner = keyById(trusted.keys, entry.signerKeyId);
		const resultSigner = keyById(trusted.keys, entry.publicKeyId);
		if (registrySigner.fingerprint !== anchors.registrySignerFingerprint)
			oracleFailure(`oracle entry registry signer does not match trust anchor: ${entry.oracleId}`);
		if (resultSigner.fingerprint !== anchors.resultSignerFingerprint)
			oracleFailure(`oracle entry result signer does not match trust anchor: ${entry.oracleId}`);
		if (
			registrySigner.keyId === resultSigner.keyId ||
			registrySigner.publicKey === resultSigner.publicKey ||
			registrySigner.fingerprint === resultSigner.fingerprint
		)
			oracleFailure(`oracle entry signer roles are not distinct: ${entry.oracleId}`);
	}
	return trusted;
}

/**
 * Verify an oracle result using only an externally supplied exact trust-anchor set.
 */
export function verifyAnchoredOracleResult(
	trusted: unknown,
	trustAnchors: unknown,
	value: unknown,
	expected: OracleRequestIdentity,
): VerifiedOracleResult {
	const checked = validateAnchoredOracleRegistry(trusted, trustAnchors);
	return verifyTrustedOracleResult(checked, value, expected);
}

/**
 * Verify an oracle result against a caller-supplied registry. This validates shape
 * and signatures only; it is non-authoritative without `verifyAnchoredOracleResult`.
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
