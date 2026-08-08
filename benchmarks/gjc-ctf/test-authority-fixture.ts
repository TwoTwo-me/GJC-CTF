import { generateKeyPairSync, sign } from "node:crypto";
import { benchmarkManifestDigest, benchmarkRepeatSeed } from "../../packages/coding-agent/src/ctf/contracts/benchmark";
import { createBenchmarkLock } from "./manifest";
import { canonicalDigest, canonicalJson, sha256Hex } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { oracleEvidenceDigest, oracleTransitionDigest } from "../../packages/coding-agent/src/ctf/contracts/event";
import { metricsFingerprint } from "../../packages/coding-agent/src/ctf/contracts/metrics";
import { oracleEntryDigest, oracleRegistryDigest, oracleResultDigest } from "../../packages/coding-agent/src/ctf/contracts/oracle";
import { operationalLimitsDigest, safetyPolicyDigest } from "../../packages/coding-agent/src/ctf/contracts/sandbox";
import { benchmarkCalibrationDigest } from "../../packages/coding-agent/src/ctf/runtime/policy";
import { oracleTransitionSignaturePayload } from "../../packages/coding-agent/src/ctf/graph/ontology";

const digest = (value: string) => canonicalDigest(value);

/** A complete fixed-budget authority bundle for production benchmark API tests. */
export function authorizedVersionStatsRequest() {
	const createKey = (keyId: string) => {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
		return {
			privateKey,
			key: {
				keyId,
				algorithm: "ed25519" as const,
				publicKey: publicKeyText,
				fingerprint: sha256Hex(publicKeyText),
				active: true,
			},
		};
	};
	const registryAuthority = createKey("fixture-registry-key");
	const resultAuthority = createKey("fixture-result-key");
	const entryUnsigned = { schemaVersion: "ctf-oracle-entry-1" as const, oracleId: "fixture-oracle", protocolVersion: "oracle-1", executableRef: "oracle:v1", imageDigest: digest("image"), artifactDigest: digest("artifact"), allowedChallengeIds: ["fixture-challenge"], publicKeyId: resultAuthority.key.keyId, signerKeyId: registryAuthority.key.keyId, outputSchemaVersion: "ctf-oracle-result-1" };
	const entry = { ...entryUnsigned, signature: sign(null, Buffer.from(canonicalJson(entryUnsigned)), registryAuthority.privateKey).toString("base64") };
	const registry = { schemaVersion: "ctf-oracle-registry-1" as const, entries: [entry], registryDigest: oracleRegistryDigest({ schemaVersion: "ctf-oracle-registry-1", entries: [entry] }) };
	const skill = { effectiveId: "fixture-skill", effectiveVersion: "1.0.0", contentDigest: digest("skill-content"), loaderDigest: digest("loader"), buildDigest: digest("build"), workspaceOverrideDigest: null };
	const safetyBase = { schemaVersion: "ctf-safety-maxima-1" as const, policyId: "fixture-safety", wallMsMax: 10000, cpuCoresMax: 2, memoryBytesMax: 4096, pidsMax: 16, outputBytesMax: 4096, fileDescriptorsMax: 64, tmpBytesMax: 4096, networkMode: "off" as const, capabilities: "none" as const, devices: "none" as const, hostMounts: "none" as const, credentials: "none" as const };
	const safety = { ...safetyBase, policyDigest: safetyPolicyDigest(safetyBase) };
	const limitsBase = { schemaVersion: "ctf-operational-limits-1" as const, calibrationId: "fixture-calibration", measuredAt: "2026-01-01T00:00:00.000Z", evidenceDigest: digest("limits-evidence"), wallMs: 1000, cpuCores: 1, memoryBytes: 1024, pids: 1, outputBytes: 1024, fileDescriptors: 16, tmpBytes: 1024, safetyPolicyId: safety.policyId, safetyPolicyDigest: safety.policyDigest, selectedFor: "benchmark" as const };
	const limits = { ...limitsBase, limitsDigest: operationalLimitsDigest(limitsBase) };
	const calibrationUnsigned = { schemaVersion: "ctf-benchmark-calibration-1" as const, calibrationId: "fixture-calibration", operationalLimitsDigest: limits.limitsDigest, selectedFor: "benchmark" as const, eligibleDenominator: 1, thresholds: { passAt1: 0, targetPassCount: 0, floorPassCount: 0 } };
	const calibration = { ...calibrationUnsigned, calibrationDigest: benchmarkCalibrationDigest(calibrationUnsigned) };
	const seeds = { "fixture-challenge": [0, 1, 2, 3, 4].map(index => benchmarkRepeatSeed("fixture-benchmark", "fixture-challenge", index)) };
	const manifestUnsigned = { schemaVersion: "ctf-benchmark-1" as const, benchmarkId: "fixture-benchmark", createdAt: "2026-01-01T00:00:00.000Z", sourceCommit: "commit", corpus: [{ challengeId: "fixture-challenge", category: "fixture", sourceRef: "source", sourceRevision: "revision", sourceSha256: digest("source"), permissionRef: "permission", artifactDigests: [digest("artifact")], executionClass: "verified-local/rootless-podman-network-off", backendDigest: digest("backend"), solverVisibleAllowlist: ["input.txt"], oracleId: entry.oracleId, oracleDigest: oracleEntryDigest(entry) }], holdoutChallengeIds: [], eligibilityPolicyVersion: "fixture-eligibility", objective: "competition-solve-first" as const, budget: { wallMs: 1000, inputTokens: 0, outputTokens: 0, toolCalls: 0, costCents: 0 }, repeatCount: 5 as const, seedSchedule: seeds, seeds: seeds["fixture-challenge"], modelPolicyId: "fixture-model", modelConfigDigest: digest("model"), skill, backendPolicyDigest: digest("backend-policy"), oracleRegistryDigest: registry.registryDigest, safetyPolicyDigest: safety.policyDigest, calibrationId: calibration.calibrationId, operationalLimitsDigest: limits.limitsDigest, reportRoot: "reports" };
	const manifest = { ...manifestUnsigned, manifestDigest: benchmarkManifestDigest(manifestUnsigned) };
	const lock = createBenchmarkLock(manifest);
	const context = { eventType: "node" as const, challengeId: "fixture-challenge", before: { state: "planned" }, after: { state: "verified" } };
	const preflightReportDigest = digest("preflight");
	function proof(authority: "preflight" | "oracle", refs: readonly string[], runtimeEvidenceDigest: string) {
		const signer = authority === "preflight" ? registryAuthority : resultAuthority;
		const unsigned = { schemaVersion: "ctf-oracle-transition-proof-1" as const, authority, registryDigest: registry.registryDigest, oracleEntryDigest: oracleEntryDigest(entry), ...(authority === "preflight" ? { preflightReportDigest } : { oracleResultDigest: runtimeEvidenceDigest }), transitionDigest: oracleTransitionDigest({ eventType: "node_transition", before: context.before, after: context.after }), evidenceDigest: oracleEvidenceDigest(refs), signerKeyId: signer.key.keyId, signatureAlgorithm: "ed25519" as const, signature: "unsigned" };
		return { ...unsigned, signature: sign(null, Buffer.from(canonicalJson(oracleTransitionSignaturePayload({ eventType: "node_transition", challengeId: context.challengeId, proof: unsigned }))), signer.privateKey).toString("base64") };
	}
	const runs = seeds["fixture-challenge"].map((seed, repeatIndex) => {
		const resultUnsigned = { schemaVersion: "ctf-oracle-result-1" as const, oracleId: entry.oracleId, runId: `fixture-run-${repeatIndex}`, challengeId: "fixture-challenge", nonce: `nonce-${repeatIndex}`, candidateDigest: digest(`candidate-${repeatIndex}`), inputDigest: digest(`input-${repeatIndex}`), verdict: "fail" as const, verifierVersion: "v1", outputDigest: digest(`output-${repeatIndex}`), sanitizedSummary: "fail" };
		const result = { ...resultUnsigned, signature: sign(null, Buffer.from(canonicalJson(resultUnsigned)), resultAuthority.privateKey).toString("base64") };
		const runtimeEvidenceDigest = oracleResultDigest(result); const evidenceRefs = [preflightReportDigest, runtimeEvidenceDigest];
		return { runId: result.runId, challengeId: "fixture-challenge", repeatIndex, seed, validatedSolve: false, outcome: "fail" as const, wallTimeMs: 100, firstValidTimeMs: null, manualInterventionCount: 0, inputTokens: 0, outputTokens: 0, cacheTokens: 0, toolCalls: 0, cost: { status: "known" as const, cents: 0, source: "meter" }, codeCommit: "commit", benchmarkLockDigest: lock.lockDigest, effectiveSkillDigest: canonicalDigest(skill), modelFingerprint: lock.modelConfigDigest, backendFingerprint: lock.backendPolicyDigest, calibrationDigest: calibration.calibrationDigest, category: "fixture", preflightReportDigest, runtimeEvidenceDigest, evidenceRefs, preflightProof: proof("preflight", evidenceRefs, runtimeEvidenceDigest), runtimeProof: proof("oracle", evidenceRefs, runtimeEvidenceDigest), signedOracleProof: { verified: true as const, result, entry, key: resultAuthority.key, registryDigest: registry.registryDigest }, oracleProofContext: context };
	});
	const reportUnsigned = { metricsSchemaVersion: "ctf-metrics-1" as const, benchmarkId: manifest.benchmarkId, benchmarkLockDigest: lock.lockDigest, calibrationDigest: calibration.calibrationDigest, eligibleChallengeIds: ["fixture-challenge"], createdAt: "2026-01-01T00:00:00.000Z", repeatCount: 5 as const, seedSchedule: seeds, seeds: seeds["fixture-challenge"], runs, passAt1: 0, passAt3: 0, categoryAggregates: [{ category: "fixture", numerator: 0, denominator: 1, excludedCount: 0, unknownCount: 0 }], p50WallTimeMs: 100, p95WallTimeMs: 100, manualInterventionCount: 0, unknownCount: 0, targetPassCount: 0, floorPassCount: 0, achievedPassCount: 0 };
	const report = { ...reportUnsigned, fingerprint: metricsFingerprint(reportUnsigned) };
	const runtimeEvidenceDigest = runs[0].runtimeEvidenceDigest;
	const evidenceRefs = [preflightReportDigest, runtimeEvidenceDigest];
	return { identity: { harnessDigest: preflightReportDigest, effectiveSkillDigest: canonicalDigest(skill), modelFingerprint: lock.modelConfigDigest, backendFingerprint: lock.backendPolicyDigest, toolchainDigest: runtimeEvidenceDigest, corpusDigest: lock.corpusDigest, calibrationDigest: calibration.calibrationDigest, benchmarkLockDigest: lock.lockDigest }, report, manifest, lock, calibration, objective: manifest.objective, seedSchedule: lock.seedSchedule, seeds: lock.seeds, benchmarkId: lock.benchmarkId, benchmarkLockDigest: lock.lockDigest, calibrationId: calibration.calibrationId, calibrationDigest: calibration.calibrationDigest, eligibleDenominator: 1, eligibleChallengeIds: ["fixture-challenge"], effectiveSkill: skill, operationalLimits: limits, safetyMaxima: safety, safetyPolicyDigest: safety.policyDigest, oracle: { oracleId: entry.oracleId, oracleDigest: oracleEntryDigest(entry), trustedRegistry: { registry, keys: [registryAuthority.key, resultAuthority.key] }, trustAnchors: { registrySignerFingerprint: registryAuthority.key.fingerprint, resultSignerFingerprint: resultAuthority.key.fingerprint } }, targetPassCount: 0, floorPassCount: 0, achievedPassCount: 0, preflightReportDigest, runtimeEvidenceDigest, evidenceRefs, preflightProof: proof("preflight", evidenceRefs, runtimeEvidenceDigest), runtimeProof: proof("oracle", evidenceRefs, runtimeEvidenceDigest), oracleProofContext: context };
}
