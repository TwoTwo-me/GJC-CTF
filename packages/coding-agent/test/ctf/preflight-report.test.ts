import { describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalDigest, canonicalJson, sha256Hex } from "../../src/ctf/contracts/digest";
import { challengeDescriptorDigest, manifestDigest } from "../../src/ctf/contracts/manifest";
import { oracleRegistryDigest } from "../../src/ctf/contracts/oracle";
import { operationalLimitsDigest, safetyPolicyDigest, validatePreflightReport } from "../../src/ctf/contracts/sandbox";
import {
	buildCompletePreflightReport,
	buildFixturePreflightReport,
	validatePreflightDescriptorBinding,
} from "../../src/ctf/runtime/policy";
import { DIGEST_A, DIGEST_B, DIGEST_C, FIXED_TIME, makeDescriptor } from "./fixtures";

const safetyBase = {
	schemaVersion: "ctf-safety-maxima-1" as const,
	policyId: "safety-policy-1",
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
const safety = { ...safetyBase, policyDigest: safetyPolicyDigest(safetyBase) };
const limitsBase = {
	schemaVersion: "ctf-operational-limits-1" as const,
	calibrationId: "calibration-1",
	measuredAt: FIXED_TIME,
	evidenceDigest: DIGEST_C,
	wallMs: 1_000,
	cpuCores: 1,
	memoryBytes: 1_024,
	pids: 1,
	outputBytes: 1_024,
	fileDescriptors: 16,
	tmpBytes: 1_024,
	safetyPolicyId: safety.policyId,
	safetyPolicyDigest: safety.policyDigest,
	selectedFor: "fixture" as const,
};
const limits = { ...limitsBase, limitsDigest: operationalLimitsDigest(limitsBase) };
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyText = publicKey.export({ format: "der", type: "spki" }).toString("base64");
const oracleKey = {
	keyId: "key-1",
	algorithm: "ed25519" as const,
	publicKey: publicKeyText,
	fingerprint: sha256Hex(publicKeyText),
	active: true,
};
const oracleEntryUnsigned = {
	schemaVersion: "ctf-oracle-entry-1" as const,
	oracleId: "oracle-1",
	protocolVersion: "1",
	executableRef: "oracle:v1",
	imageDigest: DIGEST_B,
	artifactDigest: DIGEST_C,
	allowedChallengeIds: ["challenge-one"],
	publicKeyId: oracleKey.keyId,
	signerKeyId: oracleKey.keyId,
	outputSchemaVersion: "ctf-oracle-result-1",
};
const oracleEntry = {
	...oracleEntryUnsigned,
	signature: sign(null, Buffer.from(canonicalJson(oracleEntryUnsigned)), privateKey).toString("base64"),
};
const oracleRegistryBase = {
	schemaVersion: "ctf-oracle-registry-1" as const,
	entries: [oracleEntry],
};
const oracleRegistry = { ...oracleRegistryBase, registryDigest: oracleRegistryDigest(oracleRegistryBase) };
const trustedOracleRegistry = { registry: oracleRegistry, keys: [oracleKey] };

const request = {
	challengeId: "challenge-one",
	sourceRevision: "source-revision-1",
	sourceSha256: DIGEST_A,
	visibleArtifactAllowlist: ["answer.txt"],
	executionClass: "fixture/static" as const,
	backendDigest: DIGEST_A,
	imageDigest: DIGEST_B,
	toolDigests: { runner: DIGEST_C },
	networkMode: "off" as const,
	oracleId: "oracle-1",
	oracleRegistry: trustedOracleRegistry,
	safetyMaxima: safety,
	operationalLimits: limits,
	runtime: {
		rootless: false,
		userNamespace: "keep-id" as const,
		networkMode: "off" as const,
		capabilities: "none" as const,
		devices: "none" as const,
		hostMounts: "none" as const,
		credentials: "none" as const,
		seccompDigest: DIGEST_A,
		imageDigest: DIGEST_B,
	},
};
const boundDescriptorBase = {
	...makeDescriptor(),
	sourceRevision: request.sourceRevision,
	sourceSha256: request.sourceSha256,
	limits: {
		...makeDescriptor().limits,
		limitsDigest: limits.limitsDigest,
		safetyPolicyDigest: safety.policyDigest,
	},
	safetyPolicyDigest: safety.policyDigest,
};
const boundDescriptor = {
	...boundDescriptorBase,
	descriptorDigest: challengeDescriptorDigest(boundDescriptorBase),
};
const manifestBase = {
	schemaVersion: "ctf-manifest-1" as const,
	competitionId: "competition-one",
	manifestRevision: 1,
	createdAt: FIXED_TIME,
	toolVersion: "1.0.0",
	skill: { id: "skill-one", version: "1.0.0", digest: DIGEST_A },
	challenges: [boundDescriptor],
};
const registeredManifest = { ...manifestBase, manifestDigest: manifestDigest(manifestBase) };
const completeRequest = {
	...request,
	backendDigest: canonicalDigest(boundDescriptor.backend),
	registeredDescriptor: boundDescriptor,
	registeredManifest,
};

function expectCode(operation: () => unknown, code: string): void {
	try {
		operation();
		throw new Error("expected operation to reject");
	} catch (error) {
		if (error instanceof Error && error.message === "expected operation to reject") throw error;
		expect(error).toMatchObject({ code });
	}
}

describe("complete CTF preflight reports", () => {
	it("builds and validates a content-addressed report from registered authority", () => {
		const report = buildCompletePreflightReport(completeRequest);
		expect(report.passed).toBe(true);
		expect(validatePreflightReport(report).reportDigest).toBe(report.reportDigest);
	});
	it("rejects unbound production preflight reports", () => {
		expectCode(() => buildCompletePreflightReport(request as never), "invalid_manifest");
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, registeredManifest: undefined } as never),
			"invalid_manifest",
		);
	});
	it("keeps unbound fixture preflight explicitly unavailable and non-scoreable", () => {
		const fixture = buildFixturePreflightReport({
			executionClass: "fixture/static",
			safetyMaxima: safety,
			operationalLimits: limits,
			runtime: request.runtime,
			expectedImageDigest: request.imageDigest,
		});
		expect(fixture.availability).toBe("unavailable");
		expect(fixture.scoreable).toBe(false);
		expectCode(() => validatePreflightReport(fixture), "missing_provenance");
	});
	it("rejects bare, keyless, and invalidly signed oracle registries", () => {
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, oracleRegistry }),
			"oracle_integrity_error",
		);
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, oracleRegistry: { registry: oracleRegistry, keys: [] } }),
			"oracle_integrity_error",
		);
		const invalidRegistryBase = {
			...oracleRegistryBase,
			entries: [{ ...oracleEntry, signature: "invalid-signature" }],
		};
		const invalidRegistry = {
			...invalidRegistryBase,
			registryDigest: oracleRegistryDigest(invalidRegistryBase),
		};
		expectCode(
			() =>
				buildCompletePreflightReport({
					...completeRequest,
					oracleRegistry: { registry: invalidRegistry, keys: [oracleKey] },
				}),
			"oracle_integrity_error",
		);
	});
	it("rejects missing report fields and report digest tampering", () => {
		const report = buildCompletePreflightReport(completeRequest);
		const missing = { ...report } as Record<string, unknown>;
		delete missing.sourceSha256;
		expectCode(() => validatePreflightReport(missing), "missing_provenance");
		expectCode(() => validatePreflightReport({ ...report, reportDigest: DIGEST_C }), "digest_mismatch");
	});
	it("rejects mismatched oracle and runtime bindings", () => {
		const report = buildCompletePreflightReport(completeRequest);
		expectCode(() => validatePreflightReport({ ...report, oracleRegistryDigest: DIGEST_A }), "digest_mismatch");
		expectCode(() => validatePreflightReport({ ...report, imageDigest: DIGEST_C }), "digest_mismatch");
	});
	it("rejects limits above immutable maxima and unsafe artifact paths", () => {
		const overMaxBase = { ...limitsBase, wallMs: safety.wallMsMax + 1 };
		const overMax = { ...overMaxBase, limitsDigest: operationalLimitsDigest(overMaxBase) };
		expectCode(() => buildCompletePreflightReport({ ...completeRequest, operationalLimits: overMax }), "unsafe_sandbox");
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, visibleArtifactAllowlist: ["../answer.txt"] }),
			"missing_provenance",
		);
	});
	it("rejects rooted, UNC, drive, NUL, and traversal artifact paths in direct reports", () => {
		const report = buildCompletePreflightReport(completeRequest);
		for (const artifactPath of [
			"/answer.txt",
			"\\answer.txt",
			"\\\\server\\share\\answer.txt",
			"C:/answer.txt",
			"C:answer.txt",
			"\0answer.txt",
			"nested/../answer.txt",
			"nested\\..\\answer.txt",
		]) {
			expectCode(
				() => validatePreflightReport({ ...report, visibleArtifactAllowlist: [artifactPath] }),
				"missing_provenance",
			);
		}
	});
	it("rejects incomplete tool digests and deferred external execution", () => {
		expectCode(() => buildCompletePreflightReport({ ...completeRequest, toolDigests: {} }), "missing_provenance");
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, executionClass: "external-untrusted/proxmox-deferred" }),
			"unsafe_sandbox",
		);
	});
	it("binds preflight provenance to its registered descriptor and manifest", () => {
		const report = buildCompletePreflightReport(completeRequest);
		expect(report.challengeId).toBe(boundDescriptor.id);
		expect(
			validatePreflightDescriptorBinding(completeRequest, boundDescriptor, registeredManifest).descriptorDigest,
		).toBe(boundDescriptor.descriptorDigest);
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, challengeId: "challenge-two" }),
			"missing_provenance",
		);
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, sourceRevision: "forged-revision" }),
			"digest_mismatch",
		);
		expectCode(() => buildCompletePreflightReport({ ...completeRequest, oracleId: "oracle-two" }), "oracle_integrity_error");
		expectCode(
			() => buildCompletePreflightReport({ ...completeRequest, visibleArtifactAllowlist: ["other.txt"] }),
			"missing_provenance",
		);
		expectCode(() => buildCompletePreflightReport({ ...completeRequest, backendDigest: DIGEST_A }), "digest_mismatch");
	});
	it("rejects descriptors absent from registered manifests", () => {
		const unregisteredDescriptorBase = { ...boundDescriptorBase, id: "challenge-two" };
		const unregisteredDescriptor = {
			...unregisteredDescriptorBase,
			descriptorDigest: challengeDescriptorDigest(unregisteredDescriptorBase),
		};
		expectCode(
			() =>
				buildCompletePreflightReport({
					...completeRequest,
					registeredDescriptor: unregisteredDescriptor,
				}),
			"invalid_manifest",
		);
	});
	it("rejects Windows drive and UNC source paths in descriptors", () => {
		const driveBase = { ...boundDescriptorBase, sourcePath: "C:\\challenge" };
		const uncBase = { ...boundDescriptorBase, sourcePath: "\\\\server\\share\\challenge" };
		expectCode(
			() =>
				validatePreflightDescriptorBinding(
					completeRequest,
					{ ...driveBase, descriptorDigest: challengeDescriptorDigest(driveBase) },
					registeredManifest,
				),
			"invalid_manifest",
		);
		expectCode(
			() =>
				validatePreflightDescriptorBinding(
					completeRequest,
					{ ...uncBase, descriptorDigest: challengeDescriptorDigest(uncBase) },
					registeredManifest,
				),
			"invalid_manifest",
		);
	});
});
