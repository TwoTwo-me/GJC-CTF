import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type EvaluationAdapterRole,
	type EvaluationAdapterV1,
	type EvaluationPreflightV1,
	evaluationPreflightDigest,
	validateEvaluationPreflight,
	validateEvaluationSpec,
} from "../contracts/evaluation";
import { type ChallengeDescriptor, validateChallengeDescriptor, validateManifest } from "../contracts/manifest";
import { oracleEntryDigest } from "../contracts/oracle";
import {
	isSafeRelativePath,
	type OperationalLimitsV1,
	type PreflightReportInput,
	type PreflightReportV1,
	preflightReportDigest,
	type SafetyMaximaV1,
	type SandboxPreflightV1,
	validateOperationalLimits,
	validatePreflightReport,
	validateSafetyMaxima,
	validateVisibleArtifactAllowlist,
} from "../contracts/sandbox";
import { type TrustedOracleRegistry, validateTrustedOracleRegistry } from "./oracle";

/**
 * Numeric calibration metadata is a benchmark input, not a runtime default.
 * Keep it content addressed so a caller cannot silently change the denominator
 * or thresholds after preflight.
 */
export type BenchmarkCalibrationPolicy = Readonly<{
	schemaVersion: "ctf-benchmark-calibration-1";
	calibrationId: string;
	operationalLimitsDigest: Digest;
	selectedFor: "fixture" | "benchmark";
	eligibleDenominator: number;
	thresholds: Readonly<Record<string, number>>;
	calibrationDigest: Digest;
}>;

function calibrationReject(message: string): never {
	throw new CtfError("uncalibrated_limits", message);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validate immutable numeric denominator and threshold calibration metadata. */
export function validateBenchmarkCalibration(
	value: unknown,
	options: Readonly<{ requireBenchmark?: boolean }> = {},
): BenchmarkCalibrationPolicy {
	if (!isPlainRecord(value) || value.schemaVersion !== "ctf-benchmark-calibration-1") {
		calibrationReject("benchmark calibration metadata is missing or has an unsupported schema version");
	}
	const allowedKeys = new Set([
		"schemaVersion",
		"calibrationId",
		"operationalLimitsDigest",
		"selectedFor",
		"eligibleDenominator",
		"thresholds",
		"calibrationDigest",
	]);
	if (Object.keys(value).some(key => !allowedKeys.has(key))) {
		calibrationReject("benchmark calibration contains unsupported fields");
	}
	const calibrationId =
		typeof value.calibrationId === "string" && value.calibrationId.length > 0
			? value.calibrationId
			: calibrationReject("benchmark calibration id is missing");
	const operationalLimitsDigest = isDigest(value.operationalLimitsDigest)
		? value.operationalLimitsDigest
		: calibrationReject("benchmark calibration operational-limits digest is missing or invalid");
	if (value.selectedFor !== "fixture" && value.selectedFor !== "benchmark") {
		calibrationReject("benchmark calibration selection is missing or unsupported");
	}
	if (options.requireBenchmark === true && value.selectedFor !== "benchmark") {
		calibrationReject("benchmark scoring requires benchmark-selected calibration");
	}
	const selectedFor: BenchmarkCalibrationPolicy["selectedFor"] = value.selectedFor;
	const eligibleDenominator =
		typeof value.eligibleDenominator === "number" &&
		Number.isSafeInteger(value.eligibleDenominator) &&
		value.eligibleDenominator > 0
			? value.eligibleDenominator
			: calibrationReject("benchmark eligible denominator must be a positive integer");
	if (!isPlainRecord(value.thresholds) || Object.keys(value.thresholds).length === 0) {
		calibrationReject("benchmark threshold calibration is missing");
	}
	const thresholds: Record<string, number> = {};
	for (const [name, threshold] of Object.entries(value.thresholds)) {
		if (
			name.length === 0 ||
			name === "__proto__" ||
			name === "constructor" ||
			name === "prototype" ||
			typeof threshold !== "number" ||
			!Number.isFinite(threshold)
		) {
			calibrationReject(`benchmark threshold ${name || "<empty>"} must be finite numeric data`);
		}
		thresholds[name] = threshold;
	}
	const calibrationDigest = isDigest(value.calibrationDigest)
		? value.calibrationDigest
		: calibrationReject("benchmark calibration digest is missing or invalid");
	const unsigned = {
		schemaVersion: "ctf-benchmark-calibration-1" as const,
		calibrationId,
		operationalLimitsDigest,
		selectedFor,
		eligibleDenominator,
		thresholds,
	};
	if (!digestsEqual(canonicalDigest(unsigned), calibrationDigest)) {
		throw new CtfError("digest_mismatch", "benchmark calibration digest mismatch");
	}
	return Object.freeze({
		...unsigned,
		calibrationDigest,
		thresholds: Object.freeze({ ...thresholds }),
	});
}

export function benchmarkCalibrationDigest(
	value: Omit<BenchmarkCalibrationPolicy, "calibrationDigest"> | BenchmarkCalibrationPolicy,
): Digest {
	return canonicalDigest(value, ["calibrationDigest"]);
}

export const parseBenchmarkCalibration = validateBenchmarkCalibration;
export const validateBenchmarkCalibrationPolicy = validateBenchmarkCalibration;
/**
 * Facts supplied by a trusted runtime probe.  A caller must provide every
 * field; an absent fact is not interpreted as a safe default.
 */
export type LocalRuntimeFacts = Readonly<{
	rootless: boolean;
	userNamespace: "keep-id" | "host" | "unknown";
	networkMode: "off" | "host" | "bridge" | "unknown";
	capabilities: "none" | "default" | "elevated" | "unknown";
	devices: "none" | "mapped" | "unknown";
	hostMounts: "none" | "mapped" | "unknown";
	credentials: "none" | "inherited" | "mounted" | "unknown";
	seccompDigest: Digest;
	imageDigest?: Digest;
	podmanVersion?: string;
}>;

/**
 * Registered authority required to construct a scoreable complete report.
 * Both values are validated and the descriptor must be present in the manifest
 * under its exact content digest.
 */
export type CompletePreflightReportInput = PreflightReportInput &
	Readonly<{
		registeredDescriptor: unknown;
		registeredManifest: unknown;
	}>;

/**
 * A fixture probe is intentionally unavailable to score and production
 * consumers. It does not carry provenance, oracle, or report-digest fields.
 */
export type FixturePreflightReportInput = Readonly<{
	executionClass: "fixture/static";
	safetyMaxima: unknown;
	operationalLimits: unknown;
	runtime: unknown;
	executeRequested?: boolean;
	expectedImageDigest?: Digest;
}>;

export type FixturePreflightReportV1 = Readonly<{
	schemaVersion: "ctf-fixture-preflight-1";
	availability: "unavailable";
	scoreable: false;
	preflight: SandboxPreflightV1;
	passed: boolean;
	reason: string;
}>;
/** Optional local-policy descriptor binding; never sufficient for complete reports. */
export type LocalPreflightDescriptorBinding = Readonly<{
	descriptor: unknown;
}>;

export type LocalExecutionRequest = Readonly<{
	executionClass: "fixture/static" | "static" | "verified-local/rootless-podman-network-off";
	safetyMaxima: unknown;
	operationalLimits?: unknown;
	runtime: unknown;
	/** Static fixtures are never executable. */
	executeRequested?: boolean;
	expectedImageDigest?: Digest;
	/** Optional registered descriptor used to bind local policy metadata. */
	descriptor?: unknown;
	registeredDescriptor?: unknown;
	descriptorBinding?: LocalPreflightDescriptorBinding;
}>;

export type LocalExecutionPreflight = Readonly<{
	preflight: SandboxPreflightV1;
	safety: SafetyMaximaV1;
	limits?: OperationalLimitsV1;
}>;

function descriptorMismatch(message: string): never {
	throw new CtfError("invalid_manifest", message);
}

function descriptorExecutionClass(
	descriptor: ChallengeDescriptor,
): "fixture/static" | "verified-local/rootless-podman-network-off" | "external-untrusted/proxmox-deferred" {
	if (descriptor.executionClass === "static") return "fixture/static";
	if (descriptor.executionClass === "rootless-podman-network-off") return "verified-local/rootless-podman-network-off";
	return "external-untrusted/proxmox-deferred";
}

function assertLocalDescriptorBinding(
	request: LocalExecutionRequest,
	descriptor: ChallengeDescriptor | undefined,
	safety: SafetyMaximaV1,
	limits: OperationalLimitsV1 | undefined,
): void {
	if (descriptor === undefined) return;
	if (
		descriptorExecutionClass(descriptor) !== request.executionClass &&
		!(descriptor.executionClass === "static" && request.executionClass === "static")
	) {
		throw new CtfError("unsafe_sandbox", `execution class does not match registered descriptor for ${descriptor.id}`);
	}
	if (!digestsEqual(descriptor.safetyPolicyDigest, safety.policyDigest)) {
		throw new CtfError("unsafe_sandbox", `safety policy does not match registered descriptor for ${descriptor.id}`);
	}
	if (
		limits === undefined ||
		!digestsEqual(descriptor.limits.limitsDigest, limits.limitsDigest) ||
		limits.calibrationId !== descriptor.calibrationId
	) {
		throw new CtfError(
			"uncalibrated_limits",
			`operational limits do not match registered descriptor for ${descriptor.id}`,
		);
	}
}
function reject(message: string, details?: Record<string, unknown>): never {
	throw new CtfError("unsafe_sandbox", message, { details });
}
function requireDigest(value: unknown, field: string): Digest {
	if (!isDigest(value)) reject(`${field} is missing or invalid`);
	return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every(item => typeof item === "string");
}

function parseRuntimeFacts(value: unknown): LocalRuntimeFacts {
	if (!isRecord(value)) reject("runtime probe facts are missing");
	const facts = value;
	const isEnumValue = <T extends string>(candidate: unknown, values: readonly T[]): candidate is T =>
		typeof candidate === "string" && values.some(value => value === candidate);
	const enumValue = <T extends string>(field: string, values: readonly T[]): T => {
		const candidate = facts[field];
		if (!isEnumValue(candidate, values)) reject(`runtime probe field ${field} is absent or unsupported`);
		return candidate;
	};
	if (typeof facts.rootless !== "boolean") reject("runtime probe rootless fact is missing");
	const seccompDigest = facts.seccompDigest;
	if (!isDigest(seccompDigest)) reject("runtime probe seccomp digest is missing or invalid");
	const imageDigest = facts.imageDigest;
	if (imageDigest !== undefined && !isDigest(imageDigest)) reject("runtime probe image digest is invalid");
	return {
		rootless: facts.rootless,
		userNamespace: enumValue("userNamespace", ["keep-id", "host", "unknown"]),
		networkMode: enumValue("networkMode", ["off", "host", "bridge", "unknown"]),
		capabilities: enumValue("capabilities", ["none", "default", "elevated", "unknown"]),
		devices: enumValue("devices", ["none", "mapped", "unknown"]),
		hostMounts: enumValue("hostMounts", ["none", "mapped", "unknown"]),
		credentials: enumValue("credentials", ["none", "inherited", "mounted", "unknown"]),
		seccompDigest,
		...(imageDigest === undefined ? {} : { imageDigest }),
		...(typeof facts.podmanVersion === "string" ? { podmanVersion: facts.podmanVersion } : {}),
	};
}

/**
 * Validate a local execution request without ever selecting an unsafe fallback.
 * In particular, a rootless request with an unavailable Podman probe is
 * rejected rather than being run directly on the host.
 */
export function preflightLocalExecution(request: LocalExecutionRequest): LocalExecutionPreflight {
	if (!request || typeof request !== "object") reject("execution request is missing");
	const safety = validateSafetyMaxima(request.safetyMaxima);
	const runtime = parseRuntimeFacts(request.runtime);
	const executionClass = request.executionClass;
	if (
		executionClass !== "fixture/static" &&
		executionClass !== "static" &&
		executionClass !== "verified-local/rootless-podman-network-off"
	) {
		reject("unsupported execution class");
	}
	if ((executionClass === "fixture/static" || executionClass === "static") && request.executeRequested === true) {
		reject("static fixtures cannot execute challenge artifacts");
	}

	const rootless = executionClass === "verified-local/rootless-podman-network-off";
	let limits: OperationalLimitsV1 | undefined;
	if (request.operationalLimits !== undefined) limits = validateOperationalLimits(request.operationalLimits, safety);
	let descriptor: ChallengeDescriptor | undefined;
	const candidates = [request.descriptor, request.registeredDescriptor, request.descriptorBinding?.descriptor].filter(
		value => value !== undefined,
	);
	if (candidates.length > 0) {
		const checked = candidates.map(value => validateChallengeDescriptor(value));
		if (checked.some(value => !digestsEqual(value.descriptorDigest, checked[0].descriptorDigest))) {
			descriptorMismatch("local preflight descriptor bindings disagree");
		}
		descriptor = checked[0];
	}
	assertLocalDescriptorBinding(request, descriptor, safety, limits);
	if (rootless) {
		if (request.operationalLimits === undefined) {
			throw new CtfError("uncalibrated_limits", "rootless execution requires calibrated operational limits");
		}
		if (runtime.rootless !== true) reject("rootless Podman runtime is not available");
		if (runtime.userNamespace !== "keep-id") reject("rootless runtime must use the keep-id user namespace");
		if (runtime.networkMode !== "off") reject("network isolation is not disabled");
		if (runtime.capabilities !== "none") reject("container capabilities are not empty");
		if (runtime.devices !== "none") reject("container devices are not empty");
		if (runtime.hostMounts !== "none") reject("host mounts are not empty");
		if (runtime.credentials !== "none") reject("host credentials are not present");
		if (runtime.imageDigest === undefined) reject("rootless runtime image digest is not pinned");
		if (
			request.expectedImageDigest !== undefined &&
			(!isDigest(request.expectedImageDigest) || runtime.imageDigest !== request.expectedImageDigest)
		) {
			reject("runtime image digest does not match the pinned policy");
		}
	}
	const preflight: SandboxPreflightV1 = {
		schemaVersion: "ctf-sandbox-preflight-1",
		executionClass: rootless ? "verified-local/rootless-podman-network-off" : "fixture/static",
		rootless,
		userNamespace: "keep-id",
		networkMode: "off",
		capabilities: "none",
		devices: "none",
		hostMounts: "none",
		credentials: "none",
		seccompDigest: runtime.seccompDigest,
		...(runtime.imageDigest === undefined ? {} : { imageDigest: runtime.imageDigest }),
		...(limits === undefined ? {} : { limitsDigest: limits.limitsDigest }),
		passed: true,
		reason: rootless ? "rootless Podman policy validated" : "static fixture policy validated; no execution permitted",
	};
	return { preflight, safety, ...(limits === undefined ? {} : { limits }) };
}

export type LocalExecutionPolicyDecision =
	| Readonly<{ allowed: true; value: LocalExecutionPreflight }>
	| Readonly<{ allowed: false; error: CtfError }>;

/** Non-throwing inspection form; it still fails closed (`allowed: false`). */
export function evaluateLocalExecutionPolicy(request: LocalExecutionRequest): LocalExecutionPolicyDecision {
	try {
		return { allowed: true, value: preflightLocalExecution(request) };
	} catch (error) {
		const ctfError = error instanceof CtfError ? error : new CtfError("unsafe_sandbox", "sandbox preflight failed");
		return { allowed: false, error: ctfError };
	}
}
export type EvaluationComponentExecutionInput = Readonly<{
	adapterId: string;
	roles: readonly EvaluationAdapterRole[];
	artifactDigest: Digest;
	backend: "rootless-podman";
	expectedImageDigest: Digest;
	expectedSeccompDigest: Digest;
	runtime: unknown;
	safetyMaxima: unknown;
	operationalLimits: unknown;
}>;

export type EvaluationParentIsolationAttestation = Readonly<{
	backend: "rootless-podman";
	runNetworkNamespace: string;
	pidNamespace: string;
	mountNamespace: string;
	ipcNamespace: string;
	userNamespace: string;
	hostPorts: "none";
	dns: "none";
	routing: "none";
	capabilities: "none";
	devices: "none";
	credentials: "none";
	cgroup: "challenge";
	aggregateLimits: unknown;
}>;

export type EvaluationAggregatePreflightRequest = Readonly<{
	spec: unknown;
	components: readonly EvaluationComponentExecutionInput[];
	parent: EvaluationParentIsolationAttestation;
}>;

function evaluationAdapterArtifactDigest(adapter: EvaluationAdapterV1): Digest {
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
function evaluationAdapterImageDigest(adapter: EvaluationAdapterV1): Digest | undefined {
	if (adapter.kind === "container-service")
		return requireDigest(adapter.imageDigest, "container service image digest");
	if (adapter.kind === "browser-session") return requireDigest(adapter.browserDigest, "browser session digest");
	return undefined;
}

function sameRoles(actual: readonly EvaluationAdapterRole[], expected: readonly EvaluationAdapterRole[]): boolean {
	return actual.length === expected.length && actual.every((role, index) => role === expected[index]);
}

function requireNamespace(value: unknown, field: string): string {
	if (typeof value !== "string" || value.length === 0 || value.length > 256) reject(`parent ${field} is missing`);
	return value;
}

function assertParentIsolation(
	parent: EvaluationParentIsolationAttestation,
	aggregateSafety: SafetyMaximaV1,
	aggregateLimits: OperationalLimitsV1,
): void {
	if (!isRecord(parent) || parent.backend !== "rootless-podman") reject("parent backend is not rootless Podman");
	const namespaces = [
		requireNamespace(parent.runNetworkNamespace, "network namespace"),
		requireNamespace(parent.pidNamespace, "PID namespace"),
		requireNamespace(parent.mountNamespace, "mount namespace"),
		requireNamespace(parent.ipcNamespace, "IPC namespace"),
		requireNamespace(parent.userNamespace, "user namespace"),
	];
	if (new Set(namespaces).size !== namespaces.length) reject("parent namespaces must be separate and run-private");
	if (
		parent.hostPorts !== "none" ||
		parent.dns !== "none" ||
		parent.routing !== "none" ||
		parent.capabilities !== "none" ||
		parent.devices !== "none" ||
		parent.credentials !== "none"
	) {
		reject("parent isolation attestation permits host connectivity or privileges");
	}
	if (parent.cgroup !== "challenge") reject("parent challenge-level cgroup is absent");
	const checkedLimits = validateOperationalLimits(parent.aggregateLimits, aggregateSafety);
	if (!digestsEqual(checkedLimits.limitsDigest, aggregateLimits.limitsDigest)) {
		reject("parent aggregate limits do not bind every component");
	}
}

/**
 * Fail-closed evaluation preflight. Every adapter is represented exactly once;
 * the parent cgroup, rather than per-component limits, owns aggregate resource
 * enforcement for the run.
 */
function isEvaluationAdapterRole(value: unknown): value is EvaluationAdapterRole {
	return (
		value === "solver" ||
		value === "service" ||
		value === "checker" ||
		value === "browser" ||
		value === "browser-bridge"
	);
}
function isEvaluationComponentExecutionInput(value: unknown): value is EvaluationComponentExecutionInput {
	return (
		isRecord(value) &&
		typeof value.adapterId === "string" &&
		Array.isArray(value.roles) &&
		value.roles.every(isEvaluationAdapterRole) &&
		value.backend === "rootless-podman" &&
		isDigest(value.artifactDigest) &&
		isDigest(value.expectedImageDigest) &&
		isDigest(value.expectedSeccompDigest) &&
		Object.hasOwn(value, "runtime") &&
		Object.hasOwn(value, "safetyMaxima") &&
		Object.hasOwn(value, "operationalLimits")
	);
}

export function preflightAggregateEvaluation(request: EvaluationAggregatePreflightRequest): EvaluationPreflightV1 {
	if (!isRecord(request)) reject("evaluation preflight request is missing");
	const spec = validateEvaluationSpec(request.spec);
	if (!Array.isArray(request.components) || request.components.length !== spec.adapters.length) {
		reject("evaluation components do not exactly cover the evaluation specification");
	}
	if (!isRecord(request.parent)) reject("parent isolation attestation is missing");

	const componentsById = new Map<string, EvaluationComponentExecutionInput>();
	for (const component of request.components) {
		if (
			!isEvaluationComponentExecutionInput(component) ||
			component.adapterId.length === 0 ||
			componentsById.has(component.adapterId)
		) {
			reject("evaluation component IDs must be unique");
		}
		componentsById.set(component.adapterId, component);
	}

	let aggregateSafety: SafetyMaximaV1 | undefined;
	let aggregateLimits: OperationalLimitsV1 | undefined;
	const components: EvaluationPreflightV1["components"] = [];
	for (const adapter of spec.adapters) {
		const component = componentsById.get(adapter.adapterId);
		if (component === undefined || !sameRoles(component.roles, adapter.roles)) {
			reject(`evaluation component roles do not match adapter ${adapter.adapterId}`);
		}
		const adapterImageDigest = evaluationAdapterImageDigest(adapter);
		if (
			component.backend !== "rootless-podman" ||
			!digestsEqual(component.artifactDigest, evaluationAdapterArtifactDigest(adapter)) ||
			(adapterImageDigest !== undefined && !digestsEqual(component.expectedImageDigest, adapterImageDigest))
		) {
			reject(`evaluation component facts do not match adapter ${adapter.adapterId}`);
		}
		const local = preflightLocalExecution({
			executionClass: "verified-local/rootless-podman-network-off",
			safetyMaxima: component.safetyMaxima,
			operationalLimits: component.operationalLimits,
			runtime: component.runtime,
			expectedImageDigest: component.expectedImageDigest,
		});
		if (
			local.limits === undefined ||
			!digestsEqual(local.preflight.seccompDigest, component.expectedSeccompDigest) ||
			!digestsEqual(local.preflight.imageDigest ?? "", component.expectedImageDigest)
		) {
			reject(`evaluation component runtime facts do not match adapter ${adapter.adapterId}`);
		}
		if (aggregateSafety === undefined || aggregateLimits === undefined) {
			aggregateSafety = local.safety;
			aggregateLimits = local.limits;
		} else if (
			!digestsEqual(aggregateSafety.policyDigest, local.safety.policyDigest) ||
			!digestsEqual(aggregateLimits.limitsDigest, local.limits.limitsDigest)
		) {
			reject("evaluation components must share challenge-level safety and limits");
		}
		components.push({ adapterId: adapter.adapterId, preflight: local.preflight });
	}
	if (componentsById.size !== spec.adapters.length || aggregateSafety === undefined || aggregateLimits === undefined) {
		reject("evaluation components do not exactly cover the evaluation specification");
	}
	assertParentIsolation(request.parent, aggregateSafety, aggregateLimits);
	const unsigned = {
		schemaVersion: "ctf-evaluation-preflight-1" as const,
		components,
		passed: true,
	};
	return validateEvaluationPreflight({
		...unsigned,
		preflightDigest: evaluationPreflightDigest(unsigned),
	});
}

export const preflightEvaluation = preflightAggregateEvaluation;

export type CleanRoomPolicy = Readonly<{
	challengeId: string;
	rootDigest: Digest;
	visibleArtifacts: readonly string[];
	writableArtifacts: readonly string[];
	network: "off";
	credentials: "none";
	preserveProvenance: true;
}>;

export type ArtifactPolicy = Readonly<{
	challengeId: string;
	allowlist: readonly string[];
	artifactDigests: Readonly<Record<string, Digest>>;
	provenanceDigest: Digest;
}>;

function validateArtifactPath(value: string): void {
	if (!isSafeRelativePath(value)) {
		throw new CtfError(
			"missing_provenance",
			`artifact path is not confined to the clean room: ${value || "<empty>"}`,
		);
	}
}

/** Validate clean-room policy metadata; this function never touches the filesystem. */
export function validateCleanRoomPolicy(policy: unknown): CleanRoomPolicy {
	if (
		!isRecord(policy) ||
		typeof policy.challengeId !== "string" ||
		!isDigest(policy.rootDigest) ||
		policy.network !== "off" ||
		policy.credentials !== "none" ||
		policy.preserveProvenance !== true
	) {
		throw new CtfError("unsafe_sandbox", "clean-room policy is incomplete or unsafe");
	}
	const visible = policy.visibleArtifacts;
	const writable = policy.writableArtifacts;
	if (!isStringArray(visible) || !isStringArray(writable)) {
		throw new CtfError("unsafe_sandbox", "clean-room artifact policy is invalid");
	}
	for (const path of [...visible, ...writable]) validateArtifactPath(path);
	if (new Set(visible).size !== visible.length || new Set(writable).size !== writable.length) {
		throw new CtfError("unsafe_sandbox", "clean-room artifact policy contains duplicate paths");
	}
	if (visible.some(path => writable.includes(path)))
		throw new CtfError("unsafe_sandbox", "clean-room artifacts cannot be both visible and writable");
	return {
		challengeId: policy.challengeId,
		rootDigest: policy.rootDigest,
		visibleArtifacts: [...visible],
		writableArtifacts: [...writable],
		network: "off",
		credentials: "none",
		preserveProvenance: true,
	};
}

/**
 * Bind every provenance field in a preflight request to its registered,
 * content-addressed descriptor and manifest.
 */
export function validatePreflightDescriptorBinding(
	input: PreflightReportInput,
	descriptorValue: unknown,
	manifestValue: unknown,
): ChallengeDescriptor {
	if (!input || typeof input !== "object") {
		throw new CtfError("missing_provenance", "preflight report input is missing");
	}
	const descriptor = validateChallengeDescriptor(descriptorValue);
	const manifest = validateManifest(manifestValue);
	const registered = manifest.challenges.find(candidate => candidate.id === descriptor.id);
	if (registered === undefined || !digestsEqual(registered.descriptorDigest, descriptor.descriptorDigest)) {
		descriptorMismatch(`descriptor ${descriptor.id} is not the descriptor registered in the manifest`);
	}
	if (
		typeof input.challengeId !== "string" ||
		typeof input.sourceRevision !== "string" ||
		typeof input.oracleId !== "string"
	) {
		throw new CtfError("missing_provenance", "preflight challenge identity and source revision are required");
	}
	if (!isDigest(input.sourceSha256) || !isDigest(input.backendDigest) || !isDigest(input.imageDigest)) {
		throw new CtfError("missing_provenance", "preflight source, backend, and image digests are required");
	}
	const visibleArtifactAllowlist = validateVisibleArtifactAllowlist(input.visibleArtifactAllowlist);
	if (input.challengeId !== descriptor.id) {
		throw new CtfError("missing_provenance", "preflight challenge id does not match the registered descriptor");
	}
	if (
		input.sourceRevision !== descriptor.sourceRevision ||
		!digestsEqual(input.sourceSha256, descriptor.sourceSha256)
	) {
		throw new CtfError(
			"digest_mismatch",
			`preflight source does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	if (!digestsEqual(input.backendDigest, canonicalDigest(descriptor.backend))) {
		throw new CtfError(
			"digest_mismatch",
			`preflight backend does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	if (input.oracleId !== descriptor.oracleId) {
		throw new CtfError(
			"oracle_integrity_error",
			`preflight oracle does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	if (
		visibleArtifactAllowlist.length !== descriptor.visibleArtifactAllowlist.length ||
		visibleArtifactAllowlist.some((value, index) => value !== descriptor.visibleArtifactAllowlist[index])
	) {
		throw new CtfError(
			"missing_provenance",
			`preflight artifact allowlist does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	const safety = validateSafetyMaxima(input.safetyMaxima);
	const limits = validateOperationalLimits(input.operationalLimits, safety);
	if (!digestsEqual(safety.policyDigest, descriptor.safetyPolicyDigest)) {
		throw new CtfError(
			"unsafe_sandbox",
			`preflight safety policy does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	if (
		limits.calibrationId !== descriptor.calibrationId ||
		!digestsEqual(limits.limitsDigest, descriptor.limits.limitsDigest)
	) {
		throw new CtfError(
			"uncalibrated_limits",
			`preflight calibration does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	if (descriptorExecutionClass(descriptor) !== input.executionClass) {
		throw new CtfError(
			"unsafe_sandbox",
			`preflight execution class does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	if (
		descriptor.backend.imageDigest !== undefined &&
		!digestsEqual(input.imageDigest, descriptor.backend.imageDigest)
	) {
		throw new CtfError(
			"digest_mismatch",
			`preflight image does not match the registered descriptor for ${descriptor.id}`,
		);
	}
	return descriptor;
}
export function validateArtifactPolicy(policy: unknown): ArtifactPolicy {
	if (
		!isRecord(policy) ||
		typeof policy.challengeId !== "string" ||
		!isDigest(policy.provenanceDigest) ||
		!isStringArray(policy.allowlist) ||
		!isRecord(policy.artifactDigests)
	) {
		throw new CtfError("missing_provenance", "artifact policy provenance is missing");
	}
	const allowlist = policy.allowlist;
	const rawDigests = policy.artifactDigests;
	for (const path of allowlist) validateArtifactPath(path);
	if (new Set(allowlist).size !== allowlist.length)
		throw new CtfError("missing_provenance", "artifact allowlist contains duplicate paths");
	for (const artifactPath of allowlist) {
		if (!Object.hasOwn(rawDigests, artifactPath)) {
			throw new CtfError("missing_provenance", `artifact digest is missing: ${artifactPath}`);
		}
	}
	const artifactDigests: Record<string, Digest> = {};
	for (const [path, digest] of Object.entries(rawDigests)) {
		validateArtifactPath(path);
		if (!isDigest(digest) || !allowlist.includes(path))
			throw new CtfError("missing_provenance", `artifact digest is not authorized: ${path}`);
		artifactDigests[path] = digest;
	}
	return {
		challengeId: policy.challengeId,
		allowlist: [...allowlist],
		artifactDigests,
		provenanceDigest: policy.provenanceDigest,
	};
}

export function assertArtifactAllowed(policy: ArtifactPolicy, path: string, digest: Digest): void {
	const checked = validateArtifactPolicy(policy);
	validateArtifactPath(path);
	if (!checked.allowlist.includes(path) || checked.artifactDigests[path] !== digest) {
		throw new CtfError("missing_provenance", `artifact is not present in the authorized clean-room set: ${path}`);
	}
}
/**
 * Build a scoreable, complete, content-addressed preflight report from exact
 * registered descriptor and manifest authority.
 */
export function buildCompletePreflightReport(input: CompletePreflightReportInput): PreflightReportV1 {
	if (!input || typeof input !== "object") {
		throw new CtfError("missing_provenance", "preflight report input is missing");
	}
	const descriptor = validatePreflightDescriptorBinding(input, input.registeredDescriptor, input.registeredManifest);
	if (input.executionClass === "external-untrusted/proxmox-deferred") {
		throw new CtfError("unsafe_sandbox", "deferred external execution cannot pass local preflight");
	}
	if (input.networkMode !== "off") {
		throw new CtfError("unsafe_sandbox", "preflight report network mode must be off");
	}
	if (
		typeof input.challengeId !== "string" ||
		input.challengeId.length === 0 ||
		typeof input.sourceRevision !== "string" ||
		input.sourceRevision.length === 0 ||
		typeof input.oracleId !== "string" ||
		input.oracleId.length === 0
	) {
		throw new CtfError("missing_provenance", "preflight report challenge identity and source revision are required");
	}
	if (!isDigest(input.sourceSha256) || !isDigest(input.backendDigest) || !isDigest(input.imageDigest)) {
		throw new CtfError("missing_provenance", "preflight report source, backend, and image digests are required");
	}
	const toolDigests = input.toolDigests;
	if (
		!isRecord(toolDigests) ||
		Object.keys(toolDigests).length === 0 ||
		Object.entries(toolDigests).some(([name, digest]) => name.length === 0 || !isDigest(digest))
	) {
		throw new CtfError("missing_provenance", "preflight report tool digests are missing or invalid");
	}
	const visibleArtifactAllowlist = validateVisibleArtifactAllowlist(input.visibleArtifactAllowlist);
	const safety = validateSafetyMaxima(input.safetyMaxima);
	const limits = validateOperationalLimits(input.operationalLimits, safety);
	const trustedRegistry: TrustedOracleRegistry = validateTrustedOracleRegistry(input.oracleRegistry);
	const registry = trustedRegistry.registry;
	const entry = registry.entries.find(candidate => candidate.oracleId === input.oracleId);
	if (entry === undefined || !entry.allowedChallengeIds.includes(input.challengeId)) {
		throw new CtfError("oracle_integrity_error", `oracle is not authorized for challenge: ${input.challengeId}`);
	}
	if (input.oracleRegistryDigest !== undefined && !digestsEqual(registry.registryDigest, input.oracleRegistryDigest)) {
		throw new CtfError("digest_mismatch", "preflight report oracle registry digest mismatch");
	}
	if (input.oracleDigest !== undefined && !digestsEqual(oracleEntryDigest(entry), input.oracleDigest)) {
		throw new CtfError("digest_mismatch", "preflight report oracle digest mismatch");
	}

	const preflight = preflightLocalExecution({
		executionClass: input.executionClass,
		safetyMaxima: safety,
		operationalLimits: limits,
		runtime: input.runtime,
		executeRequested: input.executeRequested,
		expectedImageDigest: input.expectedImageDigest ?? input.imageDigest,
		descriptor,
	}).preflight;
	if (preflight.imageDigest === undefined || !digestsEqual(preflight.imageDigest, input.imageDigest)) {
		throw new CtfError("digest_mismatch", "preflight report image digest does not match runtime preflight");
	}
	if (preflight.executionClass !== input.executionClass) {
		throw new CtfError("unsafe_sandbox", "preflight report execution class does not match runtime preflight");
	}
	const unsigned: Omit<PreflightReportV1, "reportDigest"> = {
		schemaVersion: "ctf-preflight-report-1",
		challengeId: input.challengeId,
		sourceRevision: input.sourceRevision,
		sourceSha256: input.sourceSha256,
		visibleArtifactAllowlist: [...visibleArtifactAllowlist],
		executionClass: input.executionClass,
		backendDigest: input.backendDigest,
		imageDigest: input.imageDigest,
		toolDigests: { ...toolDigests },
		networkMode: "off",
		oracleId: input.oracleId,
		oracleRegistry: trustedRegistry,
		oracleRegistryDigest: registry.registryDigest,
		oracleDigest: oracleEntryDigest(entry),
		safetyMaxima: safety,
		operationalLimits: limits,
		preflight,
		passed: preflight.passed,
		reason: preflight.reason,
	};
	const report = {
		...unsigned,
		reportDigest: preflightReportDigest(unsigned),
	};
	return validatePreflightReport(report);
}

/**
 * Build a fixture-local probe without creating a production report. Fixture
 * results deliberately cannot be passed to scoreable report consumers.
 */
export function buildFixturePreflightReport(input: FixturePreflightReportInput): FixturePreflightReportV1 {
	const safety = validateSafetyMaxima(input.safetyMaxima);
	const limits = validateOperationalLimits(input.operationalLimits, safety);
	const preflight = preflightLocalExecution({
		executionClass: "fixture/static",
		safetyMaxima: safety,
		operationalLimits: limits,
		runtime: input.runtime,
		executeRequested: input.executeRequested,
		expectedImageDigest: input.expectedImageDigest,
	}).preflight;
	return {
		schemaVersion: "ctf-fixture-preflight-1",
		availability: "unavailable",
		scoreable: false,
		preflight,
		passed: preflight.passed,
		reason: preflight.reason,
	};
}

export type { PreflightReportInput, PreflightReportV1 };
export { preflightReportDigest, validatePreflightReport };

export const validateSandboxPolicy = preflightLocalExecution;
export const sandboxPreflight = preflightLocalExecution;
export type SafetyMaxima = SafetyMaximaV1;
export type OperationalLimits = OperationalLimitsV1;
export const parseSafetyMaxima = validateSafetyMaxima;
export const parseOperationalLimits = validateOperationalLimits;
export const validateLocalPreflight = preflightLocalExecution;
