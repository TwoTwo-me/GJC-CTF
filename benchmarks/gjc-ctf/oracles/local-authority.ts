import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { canonicalDigest, canonicalJson, type Digest, sha256Hex } from "../../../packages/coding-agent/src/ctf/contracts/digest";
import {
	oracleRegistryDigest,
	type OracleEntryV1,
	type OracleRegistryV1,
	type OracleResultV1,
	type TrustedOracleKeyV1,
	type TrustedOracleRegistryV1,
} from "../../../packages/coding-agent/src/ctf/contracts/oracle";
import {
	type OracleRequestIdentity,
	type VerifiedOracleResult,
	verifyTrustedOracleResult,
} from "../../../packages/coding-agent/src/ctf/runtime/oracle";

export type LocalOracleObservation = Readonly<{
	verdict: "pass" | "fail" | "unavailable";
	sourceDigest: Digest;
	inputDigest: Digest;
	candidateDigest: Digest;
	reason?: string;
}>;

export type LocalOracleDescriptor = Readonly<{
	oracleId: string;
	challengeId: string;
	artifactDigest: Digest;
}>;

export type LocalOracleResultRequest = Readonly<{
	oracleId: string;
	runId: string;
	challengeId: string;
	nonce: string;
	observation: LocalOracleObservation;
	issuedAt: string;
}>;

export type EphemeralLocalOracleAuthority = Readonly<{
	/** Public registry only. This locally generated authority is never benchmark trust by itself. */
	trustedRegistry: TrustedOracleRegistryV1;
	signAndVerify(request: LocalOracleResultRequest): VerifiedOracleResult;
}>;

function signCanonical(value: unknown, privateKey: KeyObject): string {
	return sign(null, Buffer.from(canonicalJson(value)), privateKey).toString("base64");
}

function entryFor(
	descriptor: LocalOracleDescriptor,
	keyId: string,
	privateKey: KeyObject,
): OracleEntryV1 {
	const unsigned = {
		schemaVersion: "ctf-oracle-entry-1" as const,
		oracleId: descriptor.oracleId,
		protocolVersion: "local-checker-v1",
		executableRef: `gjc-ctf-local:${descriptor.oracleId}`,
		imageDigest: descriptor.artifactDigest,
		artifactDigest: descriptor.artifactDigest,
		backendDigest: descriptor.artifactDigest,
		allowedChallengeIds: [descriptor.challengeId],
		publicKeyId: keyId,
		signerKeyId: keyId,
		outputSchemaVersion: "ctf-oracle-result-1",
	};
	return Object.freeze({ ...unsigned, signature: signCanonical(unsigned, privateKey) });
}

/**
 * Creates an ephemeral local signing boundary for diagnostic evaluation. Its public
 * output proves result integrity, but it does not replace a pre-authorized benchmark registry.
 */
export function createEphemeralLocalOracleAuthority(
	descriptors: readonly LocalOracleDescriptor[],
): EphemeralLocalOracleAuthority {
	if (descriptors.length === 0 || new Set(descriptors.map(item => item.oracleId)).size !== descriptors.length) {
		throw new Error("local oracle descriptors must be non-empty and unique");
	}
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
	const keyId = "local-oracle-key-v1";
	const key: TrustedOracleKeyV1 = Object.freeze({
		keyId,
		algorithm: "ed25519",
		publicKey: publicKeyText,
		fingerprint: sha256Hex(publicKeyText),
		active: true,
	});
	const entries = Object.freeze(descriptors.map(descriptor => entryFor(descriptor, keyId, privateKey)));
	const unsignedRegistry = { schemaVersion: "ctf-oracle-registry-1" as const, entries };
	const registry: OracleRegistryV1 = Object.freeze({
		...unsignedRegistry,
		registryDigest: oracleRegistryDigest(unsignedRegistry),
	});
	const trustedRegistry: TrustedOracleRegistryV1 = Object.freeze({ registry, keys: Object.freeze([key]) });
	return Object.freeze({
		trustedRegistry,
		signAndVerify(request: LocalOracleResultRequest): VerifiedOracleResult {
			const entry = entries.find(candidate => candidate.oracleId === request.oracleId);
			if (entry === undefined || !entry.allowedChallengeIds.includes(request.challengeId)) {
				throw new Error("local oracle is not authorized for the challenge");
			}
			const outputDigest = canonicalDigest(request.observation);
			const unsignedResult = {
				schemaVersion: "ctf-oracle-result-1" as const,
				oracleId: request.oracleId,
				runId: request.runId,
				challengeId: request.challengeId,
				nonce: request.nonce,
				candidateDigest: request.observation.candidateDigest,
				inputDigest: request.observation.inputDigest,
				verdict: request.observation.verdict === "pass" ? "pass" as const : request.observation.verdict === "fail" ? "fail" as const : "error" as const,
				verifierVersion: "gjc-ctf-local-oracle-v1",
				outputDigest,
				sanitizedSummary: request.observation.verdict === "pass"
					? "candidate satisfied the source-bound local checker"
					: "candidate did not satisfy the source-bound local checker",
				issuedAt: request.issuedAt,
			};
			const result: OracleResultV1 = Object.freeze({
				...unsignedResult,
				signature: signCanonical(unsignedResult, privateKey),
			});
			const expected: OracleRequestIdentity = {
				runId: result.runId,
				challengeId: result.challengeId,
				nonce: result.nonce,
				candidateDigest: result.candidateDigest,
				inputDigest: result.inputDigest,
			};
			return verifyTrustedOracleResult(trustedRegistry, result, expected);
		},
	});
}
