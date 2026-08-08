import { expect, test } from "bun:test";
import { canonicalDigest } from "../../../packages/coding-agent/src/ctf/contracts/digest";
import { verifyTrustedOracleResult } from "../../../packages/coding-agent/src/ctf/runtime/oracle";
import { createEphemeralLocalOracleAuthority } from "./local-authority";

const artifactDigest = canonicalDigest("reviewed-verifier");
const observation = {
	verdict: "pass" as const,
	sourceDigest: canonicalDigest("source"),
	inputDigest: canonicalDigest("input"),
	candidateDigest: canonicalDigest("candidate"),
};

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
