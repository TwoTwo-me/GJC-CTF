import type { Digest } from "../../src/ctf/contracts";
import {
	type ChallengeDescriptor,
	challengeDescriptorDigest,
	type IntentV2,
	intentPayloadDigest,
	type SkillRef,
} from "../../src/ctf/contracts";

export const DIGEST_A = "a".repeat(64) as Digest;
export const DIGEST_B = "b".repeat(64) as Digest;
export const DIGEST_C = "c".repeat(64) as Digest;
export const EVIDENCE_DIGEST = "d".repeat(64) as Digest;
export const FIXED_TIME = "2026-01-01T00:00:00.000Z";

export const SKILL: SkillRef = {
	id: "ctf-skill",
	version: "1.0.0",
	digest: DIGEST_A,
};

export function makeDescriptor(
	idOrOverrides: string | Partial<ChallengeDescriptor> = "challenge-one",
	sourceRevision = "source-rev-1",
): ChallengeDescriptor {
	const overrides = typeof idOrOverrides === "string" ? { id: idOrOverrides, sourceRevision } : idOrOverrides;
	const { descriptorDigest: _descriptorDigest, ...descriptorOverrides } = overrides;
	const base: Omit<ChallengeDescriptor, "descriptorDigest"> = {
		id: "challenge-one",
		category: "misc",
		sourcePath: "fixtures/challenge",
		sourceRevision: "source-rev-1",
		sourceSha256: DIGEST_B,
		trustLevel: "fixture",
		executionClass: "static",
		visibleArtifactAllowlist: ["answer.txt"],
		backend: {
			kind: "fixture",
			version: "1",
			toolVersions: { runner: "1" },
		},
		networkMode: "off",
		limits: {
			calibrationId: "calibration-1",
			limitsDigest: DIGEST_C,
			wallMs: 1_000,
			cpuCores: 1,
			memoryBytes: 1_024,
			pids: 1,
			outputBytes: 1_024,
			fileDescriptors: 16,
			tmpBytes: 1_024,
			safetyPolicyDigest: DIGEST_C,
		},
		safetyPolicyDigest: DIGEST_C,
		calibrationId: "calibration-1",
		oracleId: "oracle-1",
		registeredAt: FIXED_TIME,
		...descriptorOverrides,
	};
	return { ...base, descriptorDigest: challengeDescriptorDigest(base) };
}

export function makeIntent(overrides: Partial<IntentV2> = {}): IntentV2 {
	const payload = overrides.payload ?? { action: "inspect", value: "fixture" };
	const base: IntentV2 = {
		schemaVersion: "ctf-intent-2",
		intentId: "intent-1",
		intentVersion: 1,
		competitionId: "competition-1",
		challengeId: "challenge-one",
		runId: "run-1",
		runFencingToken: 1,
		teamName: "team-one",
		taskId: "task-one",
		workerId: "worker-one",
		lane: "lane-one",
		requiredRole: "solver",
		claimToken: "claim-one",
		claimExpiresAt: FIXED_TIME,
		claimProofDigest: DIGEST_A,
		baseRevision: 0,
		idempotencyKey: "intent-key-1",
		payloadDigest: intentPayloadDigest({ payload }),
		createdAt: FIXED_TIME,
		action: {
			actionId: "action-one",
			kind: "inspect",
			parameters: {},
		},
		evidenceRefs: [EVIDENCE_DIGEST],
		payload,
	};
	const merged = { ...base, ...overrides, payload };
	return { ...merged, payloadDigest: intentPayloadDigest({ payload: merged.payload }) };
}
