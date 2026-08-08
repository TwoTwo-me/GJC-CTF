import { describe, expect, it } from "bun:test";
import { assertDigest, type Digest } from "../../src/ctf/contracts/digest";
import {
	type EvaluationAdapterV1,
	type EvaluationSpecV1,
	evaluationSpecDigest,
} from "../../src/ctf/contracts/evaluation";
import {
	type OperationalLimitsV1,
	operationalLimitsDigest,
	type SafetyMaximaV1,
	safetyPolicyDigest,
	validateScoredLimits,
} from "../../src/ctf/contracts/sandbox";
import {
	type EvaluationAggregatePreflightRequest,
	type EvaluationComponentExecutionInput,
	type EvaluationParentIsolationAttestation,
	evaluateLocalExecutionPolicy,
	type LocalRuntimeFacts,
	preflightAggregateEvaluation,
	preflightLocalExecution,
	validateArtifactPolicy,
	validateCleanRoomPolicy,
} from "../../src/ctf/runtime/policy";
import { DIGEST_A, DIGEST_B, DIGEST_C, FIXED_TIME } from "./fixtures";

type SafetyMaximaInput = Omit<SafetyMaximaV1, "policyDigest">;
type OperationalLimitsInput = Omit<OperationalLimitsV1, "limitsDigest">;
type EvaluationSpecInput = Omit<EvaluationSpecV1, "specDigest">;
type ArtifactDigest = EvaluationComponentExecutionInput["artifactDigest"];
type ImageDigest = EvaluationComponentExecutionInput["expectedImageDigest"];
type SeccompDigest = EvaluationComponentExecutionInput["expectedSeccompDigest"];
type AggregateEvaluationRequest = EvaluationAggregatePreflightRequest & {
	spec: EvaluationSpecV1;
	components: EvaluationComponentExecutionInput[];
	parent: EvaluationParentIsolationAttestation;
};

const safetyBase: SafetyMaximaInput = {
	schemaVersion: "ctf-safety-maxima-1",
	policyId: "safety-policy-1",
	wallMsMax: 10_000,
	cpuCoresMax: 2,
	memoryBytesMax: 4_096,
	pidsMax: 16,
	outputBytesMax: 4_096,
	fileDescriptorsMax: 64,
	tmpBytesMax: 4_096,
	networkMode: "off",
	capabilities: "none",
	devices: "none",
	hostMounts: "none",
	credentials: "none",
};
const safety: SafetyMaximaV1 = { ...safetyBase, policyDigest: safetyPolicyDigest(safetyBase) };

const runtime: LocalRuntimeFacts & Readonly<{ imageDigest: ImageDigest; seccompDigest: SeccompDigest }> = {
	rootless: true,
	userNamespace: "keep-id",
	networkMode: "off",
	capabilities: "none",
	devices: "none",
	hostMounts: "none",
	credentials: "none",
	seccompDigest: DIGEST_A,
	imageDigest: DIGEST_B,
};
const limitsBase: OperationalLimitsInput = {
	schemaVersion: "ctf-operational-limits-1",
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
	selectedFor: "benchmark",
};
const limits: OperationalLimitsV1 = { ...limitsBase, limitsDigest: operationalLimitsDigest(limitsBase) };

function evaluationSpec(adapters: EvaluationAdapterV1[]): EvaluationSpecV1 {
	const base: EvaluationSpecInput = {
		schemaVersion: "ctf-evaluation-spec-1",
		evaluationId: "evaluation-one",
		challengeId: "challenge-one",
		descriptorDigest: DIGEST_C,
		secretPolicy: "not-feasible",
		candidate: { encoding: "utf8", maxBytes: 1_024 },
		adapters,
	};
	return { ...base, specDigest: evaluationSpecDigest(base) };
}

function requireDigest(value: string, label: string): Digest {
	assertDigest(value, label);
	return value;
}

function adapterArtifactDigest(adapter: EvaluationAdapterV1): ArtifactDigest {
	switch (adapter.kind) {
		case "offline-checker":
			return requireDigest(adapter.checkerDigest, "offline checker digest");
		case "process-service":
			return requireDigest(adapter.serviceDigest, "process service digest");
		case "container-service":
			return requireDigest(adapter.imageDigest, "container service image digest");
		case "browser-session":
			return requireDigest(adapter.browserDigest, "browser session digest");
	}
}

function adapterImageDigest(adapter: EvaluationAdapterV1): ImageDigest {
	if (adapter.kind === "container-service")
		return requireDigest(adapter.imageDigest, "container service image digest");
	if (adapter.kind === "browser-session") return requireDigest(adapter.browserDigest, "browser session digest");
	return runtime.imageDigest;
}

function aggregateRequest(adapters: EvaluationAdapterV1[]): AggregateEvaluationRequest {
	const components: EvaluationComponentExecutionInput[] = adapters.map(adapter => ({
		adapterId: adapter.adapterId,
		roles: adapter.roles,
		artifactDigest: adapterArtifactDigest(adapter),
		backend: "rootless-podman",
		expectedImageDigest: adapterImageDigest(adapter),
		expectedSeccompDigest: runtime.seccompDigest,
		runtime: { ...runtime, imageDigest: adapterImageDigest(adapter) },
		safetyMaxima: safety,
		operationalLimits: limits,
	}));
	const parent: EvaluationParentIsolationAttestation = {
		backend: "rootless-podman",
		runNetworkNamespace: "net-run-one",
		pidNamespace: "pid-run-one",
		mountNamespace: "mount-run-one",
		ipcNamespace: "ipc-run-one",
		userNamespace: "user-run-one",
		hostPorts: "none",
		dns: "none",
		routing: "none",
		capabilities: "none",
		devices: "none",
		credentials: "none",
		cgroup: "challenge",
		aggregateLimits: limits,
	};
	return { spec: evaluationSpec(adapters), components, parent };
}

function expectCtfCode(operation: () => unknown, code: string): void {
	try {
		operation();
		throw new Error("expected operation to reject");
	} catch (error) {
		if (error instanceof Error && error.message === "expected operation to reject") throw error;
		expect(error).toMatchObject({ code });
	}
}

describe("CTF runtime and benchmark preflight", () => {
	it("rejects rootless benchmark execution when calibrated limits are absent", () => {
		expectCtfCode(
			() =>
				preflightLocalExecution({
					executionClass: "verified-local/rootless-podman-network-off",
					safetyMaxima: safety,
					runtime,
				}),
			"uncalibrated_limits",
		);
		const decision = evaluateLocalExecutionPolicy({
			executionClass: "verified-local/rootless-podman-network-off",
			safetyMaxima: safety,
			runtime,
		});
		expect(decision.allowed).toBe(false);
		if (!decision.allowed) expect(decision.error.code).toBe("uncalibrated_limits");
	});

	it("rejects execution requests that try to run a static fixture", () => {
		expectCtfCode(
			() =>
				preflightLocalExecution({
					executionClass: "fixture/static",
					safetyMaxima: safety,
					runtime: { ...runtime, rootless: false },
					executeRequested: true,
				}),
			"unsafe_sandbox",
		);
	});

	it("rejects fixture-calibrated limits from benchmark scoring", () => {
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
		expectCtfCode(() => validateScoredLimits(limits, safety), "uncalibrated_limits");
	});

	it("rejects Windows drive and UNC paths in clean-room and artifact policies", () => {
		expectCtfCode(
			() =>
				validateCleanRoomPolicy({
					challengeId: "challenge-one",
					rootDigest: DIGEST_A,
					visibleArtifacts: ["\\\\server\\share\\answer.txt"],
					writableArtifacts: [],
					network: "off",
					credentials: "none",
					preserveProvenance: true,
				}),
			"missing_provenance",
		);
		expectCtfCode(
			() =>
				validateArtifactPolicy({
					challengeId: "challenge-one",
					allowlist: ["C:answer.txt"],
					artifactDigests: {},
					provenanceDigest: DIGEST_B,
				}),
			"missing_provenance",
		);
		expectCtfCode(
			() =>
				validateArtifactPolicy({
					challengeId: "challenge-one",
					allowlist: ["answer.txt"],
					artifactDigests: {},
					provenanceDigest: DIGEST_B,
				}),
			"missing_provenance",
		);
	});
});

describe("aggregate evaluation preflight", () => {
	const adapters: EvaluationAdapterV1[] = [
		{
			kind: "offline-checker",
			adapterId: "offline",
			roles: ["checker"],
			checkerRef: "checker",
			checkerDigest: DIGEST_A,
			workingDirectory: "work",
			arguments: [],
		},
		{
			kind: "process-service",
			adapterId: "process",
			roles: ["service"],
			serviceRef: "service",
			serviceDigest: DIGEST_B,
			transport: "stdio",
			workingDirectory: "work",
			arguments: [],
		},
		{
			kind: "container-service",
			adapterId: "container",
			roles: ["service"],
			imageDigest: DIGEST_B,
			transport: "http",
			origin: "http://127.0.0.1:8080",
			entryPath: "index.html",
		},
		{
			kind: "browser-session",
			adapterId: "browser",
			roles: ["browser", "browser-bridge"],
			browserDigest: DIGEST_B,
			transport: "http",
			origin: "http://127.0.0.1:8081",
			entryPath: "index.html",
		},
	];

	it("accepts exact offline, process, container, and browser role coverage with a deterministic digest", () => {
		const input = aggregateRequest(adapters);
		const first = preflightAggregateEvaluation(input);
		const second = preflightAggregateEvaluation(input);
		expect(first.passed).toBe(true);
		expect(first.components.map(component => component.adapterId)).toEqual([
			"offline",
			"process",
			"container",
			"browser",
		]);
		expect(first.preflightDigest).toBe(second.preflightDigest);
	});

	it("rejects missing, duplicate, and extra components", () => {
		const missing = aggregateRequest(adapters);
		missing.components.pop();
		expectCtfCode(() => preflightAggregateEvaluation(missing), "unsafe_sandbox");
		const duplicate = aggregateRequest(adapters);
		duplicate.components[1] = { ...duplicate.components[1]!, adapterId: "offline" };
		expectCtfCode(() => preflightAggregateEvaluation(duplicate), "unsafe_sandbox");
		const extra = aggregateRequest(adapters);
		extra.components.push({ ...extra.components[0]!, adapterId: "extra" });
		expectCtfCode(() => preflightAggregateEvaluation(extra), "unsafe_sandbox");
		const wrongRoles = aggregateRequest(adapters);
		wrongRoles.components[3] = { ...wrongRoles.components[3]!, roles: ["browser"] };
		expectCtfCode(() => preflightAggregateEvaluation(wrongRoles), "unsafe_sandbox");
	});

	it("rejects image and seccomp fact mismatches", () => {
		const imageBase = aggregateRequest(adapters);
		const image = {
			...imageBase,
			components: imageBase.components.map((component, index) =>
				index === 0 ? { ...component, expectedImageDigest: DIGEST_C } : component,
			),
		};
		expectCtfCode(() => preflightAggregateEvaluation(image), "unsafe_sandbox");
		const seccompBase = aggregateRequest(adapters);
		const seccomp = {
			...seccompBase,
			components: seccompBase.components.map((component, index) =>
				index === 0 ? { ...component, expectedSeccompDigest: DIGEST_C } : component,
			),
		};
		expectCtfCode(() => preflightAggregateEvaluation(seccomp), "unsafe_sandbox");
	});

	it("rejects shared namespaces, host connectivity, absent cgroups, and aggregate overflow", () => {
		const sharedBase = aggregateRequest(adapters);
		const shared = {
			...sharedBase,
			parent: { ...sharedBase.parent, pidNamespace: sharedBase.parent.mountNamespace },
		};
		expectCtfCode(() => preflightAggregateEvaluation(shared), "unsafe_sandbox");
		for (const field of ["hostPorts", "dns", "routing"] as const) {
			const base = aggregateRequest(adapters);
			const input = { ...base, parent: { ...base.parent, [field]: "host" } };
			expectCtfCode(() => preflightAggregateEvaluation(input), "unsafe_sandbox");
		}
		const noCgroup = structuredClone(aggregateRequest(adapters));
		Reflect.set(noCgroup.parent, "cgroup", "none");
		expectCtfCode(() => preflightAggregateEvaluation(noCgroup), "unsafe_sandbox");
		const overflowBase = aggregateRequest(adapters);
		const tooLarge: OperationalLimitsInput = { ...limitsBase, memoryBytes: safety.memoryBytesMax + 1 };
		const overflow = {
			...overflowBase,
			parent: {
				...overflowBase.parent,
				aggregateLimits: { ...tooLarge, limitsDigest: operationalLimitsDigest(tooLarge) },
			},
		};
		expectCtfCode(() => preflightAggregateEvaluation(overflow), "unsafe_sandbox");
	});
});
