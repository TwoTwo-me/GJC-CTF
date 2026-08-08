import { describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { type FixtureRunnerRequest, runFixture } from "../../../../benchmarks/gjc-ctf/fixture-runner";
import { metricFixtureDigest } from "../../../../benchmarks/gjc-ctf/metrics";
import {
	canonicalJson,
	challengeDescriptorDigest,
	type Digest,
	oracleRegistryDigest,
	sha256Hex,
} from "../../src/ctf/contracts";
import { safetyPolicyDigest } from "../../src/ctf/contracts/sandbox";
import { trustedOracleRegistryDigest } from "../../src/ctf/runtime/oracle";
import { benchmarkCalibrationDigest } from "../../src/ctf/runtime/policy";
import { initCtfWorkspace, registerChallenge } from "../../src/ctf/workspace";
import { DIGEST_A, DIGEST_B, DIGEST_C, EVIDENCE_DIGEST, FIXED_TIME, makeDescriptor, SKILL } from "./fixtures";

const SAFETY_BASE = {
	schemaVersion: "ctf-safety-maxima-1" as const,
	policyId: "fixture-safety",
	wallMsMax: 10_000,
	cpuCoresMax: 2,
	memoryBytesMax: 4_096,
	pidsMax: 16,
	outputBytesMax: 4_096,
	fileDescriptorsMax: 64,
	tmpBytesMax: 4_096,
	networkMode: "off" as const,
	capabilities: "none" as const,
	devices: "none" as const,
	hostMounts: "none" as const,
	credentials: "none" as const,
};
const SAFETY = { ...SAFETY_BASE, policyDigest: safetyPolicyDigest(SAFETY_BASE) };

function signedOracleAuthority(runId: string, challengeId: string, candidateDigest: Digest, inputDigest: Digest) {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
	const key = {
		keyId: "fixture-key",
		algorithm: "ed25519" as const,
		publicKey: publicKeyText,
		fingerprint: sha256Hex(publicKeyText),
		active: true,
	};
	const unsignedEntry = {
		schemaVersion: "ctf-oracle-entry-1" as const,
		oracleId: "oracle-1",
		protocolVersion: "fixture-1",
		executableRef: "fixture://oracle",
		imageDigest: DIGEST_A,
		artifactDigest: DIGEST_B,
		allowedChallengeIds: [challengeId],
		publicKeyId: key.keyId,
		signerKeyId: key.keyId,
		outputSchemaVersion: "ctf-oracle-result-1",
	};
	const entry = {
		...unsignedEntry,
		signature: sign(null, Buffer.from(canonicalJson(unsignedEntry)), privateKey).toString("base64"),
	};
	const registry = {
		schemaVersion: "ctf-oracle-registry-1" as const,
		entries: [entry],
		registryDigest: oracleRegistryDigest({ schemaVersion: "ctf-oracle-registry-1", entries: [entry] }),
	};
	const unsignedResult = {
		schemaVersion: "ctf-oracle-result-1" as const,
		oracleId: "oracle-1",
		runId,
		challengeId,
		nonce: "nonce-1",
		candidateDigest,
		inputDigest,
		verdict: "pass" as const,
		verifierVersion: "fixture-verifier-1",
		outputDigest: EVIDENCE_DIGEST,
		sanitizedSummary: "pass",
	};
	const result = {
		...unsignedResult,
		signature: sign(null, Buffer.from(canonicalJson(unsignedResult)), privateKey).toString("base64"),
	};
	const trustedRegistry = { registry, keys: [key] };
	return {
		registry: trustedRegistry,
		registryDigest: trustedOracleRegistryDigest(trustedRegistry),
		result,
	};
}

async function requestAt(root: string): Promise<FixtureRunnerRequest> {
	const initialized = await initCtfWorkspace(root, "fixture-test", { skill: SKILL });
	const baseDescriptor = makeDescriptor();
	const descriptorWithoutDigest = {
		...baseDescriptor,
		safetyPolicyDigest: SAFETY.policyDigest,
		limits: { ...baseDescriptor.limits, safetyPolicyDigest: SAFETY.policyDigest },
	};
	const workspace = await registerChallenge(initialized.workspace, {
		...descriptorWithoutDigest,
		descriptorDigest: challengeDescriptorDigest(descriptorWithoutDigest),
	});
	const runId = "fixture-run-1";
	const inputDigest = DIGEST_B;
	const candidateDigest = DIGEST_A;
	const calibrationUnsigned = {
		schemaVersion: "ctf-benchmark-calibration-1" as const,
		calibrationId: "calibration-1",
		operationalLimitsDigest: DIGEST_C,
		selectedFor: "fixture" as const,
		eligibleDenominator: 1,
		thresholds: { passAt1: 1 },
	};
	const calibration = { ...calibrationUnsigned, calibrationDigest: benchmarkCalibrationDigest(calibrationUnsigned) };
	const fixtureWithoutDigest = {
		schemaVersion: "gjc-ctf-metric-fixture-1" as const,
		fixtureId: "fixture-1",
		benchmarkLockDigest: DIGEST_A,
		runs: [
			{
				runId,
				challengeId: "challenge-one",
				repeatIndex: 0,
				seed: `sha256:${"e".repeat(64)}` as `sha256:${string}`,
				outcome: "pass" as const,
				validatedSolve: true,
				wallTimeMs: 5,
			},
		],
	};
	const fixture = { ...fixtureWithoutDigest, fixtureDigest: metricFixtureDigest(fixtureWithoutDigest) };
	return {
		workspace,
		runId,
		challengeId: "challenge-one",
		occurredAt: FIXED_TIME,
		candidateDigest,
		inputDigest,
		benchmarkLockDigest: DIGEST_A,
		calibration,
		policy: {
			safetyMaxima: SAFETY,
			runtime: {
				rootless: true,
				userNamespace: "keep-id",
				networkMode: "off",
				capabilities: "none",
				devices: "none",
				hostMounts: "none",
				credentials: "none",
				seccompDigest: DIGEST_A,
			},
		},
		oracle: signedOracleAuthority(runId, "challenge-one", candidateDigest, inputDigest),
		fixture,
	};
}

describe("deterministic local CTF fixture vertical slice", () => {
	it("carries one run ID and digest lineage through authorities, events, graph, dashboard, oracle, and metrics", async () => {
		const root = await fs.mkdtemp("/tmp/gjc-fixture-");
		const request = await requestAt(root);
		try {
			const result = await runFixture(request);
			expect(result.status).toBe("ready");
			if (result.status !== "ready") return;
			expect(result.report.runId).toBe(request.runId);
			expect(result.report.outcome).toBe("pass");
			expect(result.report.dashboard.projectionStatus).toBe("current");
			expect(result.report.evidence.lineage.runId).toBe(request.runId);
			expect(result.report.evidence.lineage.oracleOutputDigest).toBe(EVIDENCE_DIGEST);
			expect(result.report.evidence.lineage.canonicalDigest).toBe(result.report.evidence.lineage.projectionDigest);
			expect(result.report.evidence.eventIds).toEqual([
				`${request.runId}:created`,
				`${request.runId}:oracle`,
				`${request.runId}:terminal`,
			]);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("fails closed when the signed oracle authority is missing", async () => {
		const root = await fs.mkdtemp("/tmp/gjc-fixture-missing-");
		const request = await requestAt(root);
		try {
			const result = await runFixture({ ...request, oracle: { ...request.oracle, result: undefined } });
			expect(result.status).toBe("unavailable");
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
