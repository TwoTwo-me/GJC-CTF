import { expect, test } from "bun:test";
import {
	validateOracleResult,
	validateOracleTrustAnchors,
} from "../../../packages/coding-agent/src/ctf/contracts/oracle";
import { canonicalDigest } from "../../../packages/coding-agent/src/ctf/contracts/digest";
import {
	type OracleRequestIdentity,
	verifyAnchoredOracleResult,
	verifyTrustedOracleResult,
} from "../../../packages/coding-agent/src/ctf/runtime/oracle";

import { createEphemeralLocalOracleAuthority } from "./local-authority";

const artifactDigest = canonicalDigest("reviewed-verifier");
const observation = {
	verdict: "pass" as const,
	sourceDigest: canonicalDigest("source"),
	inputDigest: canonicalDigest("input"),
	candidateDigest: canonicalDigest("candidate"),
};
function anchorsFor(authority: ReturnType<typeof createEphemeralLocalOracleAuthority>) {
	const registrySigner = authority.trustedRegistry.keys.find(key => key.keyId === "local-oracle-registry-signer-v1");
	const resultSigner = authority.trustedRegistry.keys.find(key => key.keyId === "local-oracle-result-signer-v1");
	if (registrySigner === undefined || resultSigner === undefined)
		throw new Error("ephemeral authority must expose both signer principals");
	return {
		registrySignerFingerprint: registrySigner.fingerprint,
		resultSignerFingerprint: resultSigner.fingerprint,
	};
}

function expectedFor(result: { runId: string; challengeId: string; nonce: string }): OracleRequestIdentity {
	return {
		runId: result.runId,
		challengeId: result.challengeId,
		nonce: result.nonce,
		candidateDigest: observation.candidateDigest,
		inputDigest: observation.inputDigest,
	};
}


test("ephemeral local authority signs and immediately verifies digest-only observations", () => {
	const authority = createEphemeralLocalOracleAuthority([
		{ oracleId: "local-checker", challengeId: "challenge-one", artifactDigest },
	]);
	const verified = authority.signAndVerify({
		oracleId: "local-checker",
		runId: "run-one",
		challengeId: "challenge-one",
		nonce: "nonce-one",
		observation,
		issuedAt: "2026-08-08T00:00:00.000Z",
	});
	expect(verified.verified).toBe(true);
	expect(verified.result.verdict).toBe("pass");
	expect(verified.result.candidateDigest).toBe(observation.candidateDigest);
	expect(JSON.stringify(verified)).not.toContain("candidate-one");
	expect(verified.entry.signerKeyId).not.toBe(verified.entry.publicKeyId);
	expect(verified.entry.signerKeyId).toBe("local-oracle-registry-signer-v1");
	expect(verified.entry.publicKeyId).toBe("local-oracle-result-signer-v1");
	expect(verifyAnchoredOracleResult(authority.trustedRegistry, anchorsFor(authority), verified.result, expectedFor(verified.result)).verified)
		.toBe(true);
});


test("forged results and cross-challenge requests fail closed", () => {
	const authority = createEphemeralLocalOracleAuthority([
		{ oracleId: "local-checker", challengeId: "challenge-one", artifactDigest },
	]);
	expect(() => authority.signAndVerify({
		oracleId: "local-checker",
		runId: "run-two",
		challengeId: "challenge-two",
		nonce: "nonce-two",
		observation,
		issuedAt: "2026-08-08T00:00:00.000Z",
	})).toThrow(/not authorized/);
	const verified = authority.signAndVerify({
		oracleId: "local-checker",
		runId: "run-one",
		challengeId: "challenge-one",
		nonce: "nonce-one",
		observation,
		issuedAt: "2026-08-08T00:00:00.000Z",
	});
	expect(() => verifyTrustedOracleResult(
		authority.trustedRegistry,
		{ ...verified.result, candidateDigest: canonicalDigest("forged") },
		{
			runId: verified.result.runId,
			challengeId: verified.result.challengeId,
			nonce: verified.result.nonce,
			candidateDigest: canonicalDigest("forged"),
			inputDigest: verified.result.inputDigest,
		},
	)).toThrow(/signature/);
});
test("anchored verification rejects self-rooting and non-exact role anchors", () => {
	const authority = createEphemeralLocalOracleAuthority([
		{ oracleId: "local-checker", challengeId: "challenge-one", artifactDigest },
	]);
	const verified = authority.signAndVerify({
		oracleId: "local-checker",
		runId: "run-one",
		challengeId: "challenge-one",
		nonce: "nonce-one",
		observation,
		issuedAt: "2026-08-08T00:00:00.000Z",
	});
	const anchors = anchorsFor(authority);
	expect(() => validateOracleTrustAnchors({
		registrySignerFingerprint: anchors.registrySignerFingerprint,
		resultSignerFingerprint: anchors.registrySignerFingerprint,
	})).toThrow(/distinct principals/);
	expect(() => validateOracleTrustAnchors({
		registrySignerFingerprint: anchors.registrySignerFingerprint,
	})).toThrow(/trust anchors are invalid/);
	expect(() => validateOracleTrustAnchors({
		...anchors,
		extraFingerprint: canonicalDigest("extra"),
	})).toThrow(/trust anchors are invalid/);
	expect(() => verifyAnchoredOracleResult(authority.trustedRegistry, {
		registrySignerFingerprint: canonicalDigest("unrelated"),
		resultSignerFingerprint: anchors.resultSignerFingerprint,
	}, verified.result, expectedFor(verified.result))).toThrow(/active keys do not exactly match/);
	expect(() => verifyAnchoredOracleResult(authority.trustedRegistry, {
		registrySignerFingerprint: anchors.resultSignerFingerprint,
		resultSignerFingerprint: anchors.registrySignerFingerprint,
	}, verified.result, expectedFor(verified.result))).toThrow(/registry signer does not match/);
	const registrySigner = authority.trustedRegistry.keys[0];
	if (registrySigner === undefined) throw new Error("ephemeral authority must expose registry signer");
	expect(() => verifyAnchoredOracleResult({
		...authority.trustedRegistry,
		keys: [...authority.trustedRegistry.keys, { ...registrySigner, keyId: "extra-active-key" }],
	}, anchors, verified.result, expectedFor(verified.result))).toThrow(/exactly two active keys/);
});

test("oracle summaries reject arbitrary signed text", () => {
	const authority = createEphemeralLocalOracleAuthority([
		{ oracleId: "local-checker", challengeId: "challenge-one", artifactDigest },
	]);
	const verified = authority.signAndVerify({
		oracleId: "local-checker",
		runId: "run-one",
		challengeId: "challenge-one",
		nonce: "nonce-one",
		observation,
		issuedAt: "2026-08-08T00:00:00.000Z",
	});
	expect(() => validateOracleResult({
		...verified.result,
		sanitizedSummary: "candidate plaintext must never be signed into evidence",
	})).toThrow(/oracle result is invalid/);
});
