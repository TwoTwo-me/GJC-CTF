import * as z from "zod/v4";
import { validateTrustedOracleRegistry } from "../runtime/oracle";
import { CtfIdSchema, DigestSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { oracleEntryDigest, TrustedOracleRegistryV1Schema } from "./oracle";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";
export const SandboxExecutionClassSchema = z.enum([
	"fixture/static",
	"verified-local/rootless-podman-network-off",
	"external-untrusted/proxmox-deferred",
]);
export type SandboxExecutionClass = z.infer<typeof SandboxExecutionClassSchema>;

export const SafetyMaximaV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.safetyMaxima),
		policyId: CtfIdSchema,
		wallMsMax: PositiveIntegerSchema,
		cpuCoresMax: PositiveIntegerSchema,
		memoryBytesMax: PositiveIntegerSchema,
		pidsMax: PositiveIntegerSchema,
		outputBytesMax: PositiveIntegerSchema,
		fileDescriptorsMax: PositiveIntegerSchema,
		tmpBytesMax: PositiveIntegerSchema,
		networkMode: z.literal("off"),
		capabilities: z.literal("none"),
		devices: z.literal("none"),
		hostMounts: z.literal("none"),
		credentials: z.literal("none"),
		policyDigest: DigestSchema,
	})
	.strict();
export type SafetyMaximaV1 = z.infer<typeof SafetyMaximaV1Schema>;

export const OperationalLimitsV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.operationalLimits),
		calibrationId: CtfIdSchema,
		measuredAt: TimestampSchema,
		evidenceDigest: DigestSchema,
		wallMs: PositiveIntegerSchema,
		cpuCores: PositiveIntegerSchema,
		memoryBytes: PositiveIntegerSchema,
		pids: PositiveIntegerSchema,
		outputBytes: PositiveIntegerSchema,
		fileDescriptors: PositiveIntegerSchema,
		tmpBytes: PositiveIntegerSchema,
		safetyPolicyId: CtfIdSchema,
		safetyPolicyDigest: DigestSchema,
		limitsDigest: DigestSchema,
		selectedFor: z.enum(["fixture", "benchmark"]),
	})
	.strict();
export type OperationalLimitsV1 = z.infer<typeof OperationalLimitsV1Schema>;

export const SandboxPreflightV1Schema = z
	.object({
		schemaVersion: z.literal("ctf-sandbox-preflight-1"),
		executionClass: SandboxExecutionClassSchema,
		rootless: z.boolean(),
		userNamespace: z.literal("keep-id"),
		networkMode: z.literal("off"),
		capabilities: z.literal("none"),
		devices: z.literal("none"),
		hostMounts: z.literal("none"),
		credentials: z.literal("none"),
		seccompDigest: DigestSchema,
		imageDigest: DigestSchema.optional(),
		limitsDigest: DigestSchema.optional(),
		passed: z.boolean(),
		reason: z.string().min(1),
	})
	.strict();
export type SandboxPreflightV1 = z.infer<typeof SandboxPreflightV1Schema>;

export const PreflightReportV1Schema = z
	.object({
		schemaVersion: z.literal("ctf-preflight-report-1"),
		challengeId: CtfIdSchema,
		sourceRevision: z.string().min(1).max(256),
		sourceSha256: DigestSchema,
		visibleArtifactAllowlist: z.array(z.string().min(1)).min(1).max(4096),
		executionClass: SandboxExecutionClassSchema,
		backendDigest: DigestSchema,
		imageDigest: DigestSchema,
		toolDigests: z.record(z.string().min(1), DigestSchema),
		networkMode: z.literal("off"),
		oracleId: CtfIdSchema,
		oracleRegistry: TrustedOracleRegistryV1Schema,
		oracleRegistryDigest: DigestSchema,
		oracleDigest: DigestSchema,
		safetyMaxima: SafetyMaximaV1Schema,
		operationalLimits: OperationalLimitsV1Schema,
		preflight: SandboxPreflightV1Schema,
		passed: z.boolean(),
		reason: z.string().min(1),
		reportDigest: DigestSchema,
	})
	.strict();
export type PreflightReportV1 = z.infer<typeof PreflightReportV1Schema>;

export type PreflightReportInput = Readonly<{
	challengeId: string;
	sourceRevision: string;
	sourceSha256: Digest;
	visibleArtifactAllowlist: readonly string[];
	executionClass: SandboxExecutionClass;
	backendDigest: Digest;
	imageDigest: Digest;
	toolDigests: Readonly<Record<string, Digest>>;
	networkMode: "off";
	oracleId: string;
	oracleRegistry: unknown;
	oracleRegistryDigest?: Digest;
	oracleDigest?: Digest;
	safetyMaxima: unknown;
	operationalLimits: unknown;
	runtime: unknown;
	executeRequested?: boolean;
	expectedImageDigest?: Digest;
}>;

export function isSafeRelativePath(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		!value.includes("\0") &&
		!/^[\\/]/.test(value) &&
		!/^[A-Za-z]:/.test(value) &&
		!value.split(/[\\/]+/).includes("..")
	);
}

export function safetyPolicyDigest(policy: SafetyMaximaV1 | Omit<SafetyMaximaV1, "policyDigest">): Digest {
	return canonicalDigest(policy, ["policyDigest"]);
}

export function operationalLimitsDigest(
	limits: OperationalLimitsV1 | Omit<OperationalLimitsV1, "limitsDigest">,
): Digest {
	return canonicalDigest(limits, ["limitsDigest"]);
}

export function validateSafetyMaxima(value: unknown): SafetyMaximaV1 {
	const parsed = SafetyMaximaV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("unsafe_sandbox", "safety maxima are invalid", { details: { issues: parsed.error.issues } });
	const policy = parsed.data;
	assertKnownMajor(policy.schemaVersion, "safetyMaxima");
	if (!digestsEqual(safetyPolicyDigest(policy), policy.policyDigest))
		throw new CtfError("digest_mismatch", "safety policy digest mismatch");
	return policy;
}

export function validateOperationalLimits(value: unknown, safety?: SafetyMaximaV1): OperationalLimitsV1 {
	const parsed = OperationalLimitsV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("uncalibrated_limits", "operational limits are invalid", {
			details: { issues: parsed.error.issues },
		});
	const limits = parsed.data;
	assertKnownMajor(limits.schemaVersion, "operationalLimits");
	if (!digestsEqual(operationalLimitsDigest(limits), limits.limitsDigest))
		throw new CtfError("digest_mismatch", "operational limits digest mismatch");
	if (safety !== undefined) {
		validateSafetyMaxima(safety);
		const checks: [number, number, string][] = [
			[limits.wallMs, safety.wallMsMax, "wallMs"],
			[limits.cpuCores, safety.cpuCoresMax, "cpuCores"],
			[limits.memoryBytes, safety.memoryBytesMax, "memoryBytes"],
			[limits.pids, safety.pidsMax, "pids"],
			[limits.outputBytes, safety.outputBytesMax, "outputBytes"],
			[limits.fileDescriptors, safety.fileDescriptorsMax, "fileDescriptors"],
			[limits.tmpBytes, safety.tmpBytesMax, "tmpBytes"],
		];
		for (const [actual, maximum, field] of checks) {
			if (actual > maximum) throw new CtfError("unsafe_sandbox", `${field} exceeds immutable safety maximum`);
		}
		if (limits.safetyPolicyId !== safety.policyId || !digestsEqual(limits.safetyPolicyDigest, safety.policyDigest)) {
			throw new CtfError("unsafe_sandbox", "operational limits reference a different safety policy");
		}
	}
	return limits;
}
export function preflightReportDigest(report: PreflightReportV1 | Omit<PreflightReportV1, "reportDigest">): Digest {
	return canonicalDigest(report, ["reportDigest"]);
}

export function validateSandboxPreflight(value: unknown): SandboxPreflightV1 {
	const parsed = SandboxPreflightV1Schema.safeParse(value);
	if (!parsed.success) {
		throw new CtfError("unsafe_sandbox", "sandbox preflight is invalid", {
			details: { issues: parsed.error.issues },
		});
	}
	return parsed.data;
}

export function validateVisibleArtifactAllowlist(value: unknown): readonly string[] {
	if (
		!Array.isArray(value) ||
		value.length === 0 ||
		!value.every(item => typeof item === "string" && item.length > 0)
	) {
		throw new CtfError("missing_provenance", "visible artifact allowlist is missing or invalid");
	}
	const paths = value as string[];
	if (new Set(paths).size !== paths.length) {
		throw new CtfError("missing_provenance", "visible artifact allowlist contains duplicate paths");
	}
	for (const path of paths) {
		if (!isSafeRelativePath(path)) {
			throw new CtfError("missing_provenance", `visible artifact path is not confined to the clean room: ${path}`);
		}
	}
	return [...paths];
}

export function validatePreflightReport(value: unknown): PreflightReportV1 {
	const parsed = PreflightReportV1Schema.safeParse(value);
	if (!parsed.success) {
		const oracleRegistryIssue =
			typeof value === "object" &&
			value !== null &&
			!Array.isArray(value) &&
			Object.hasOwn(value, "oracleRegistry") &&
			parsed.error.issues.some(issue => issue.path[0] === "oracleRegistry");
		throw new CtfError(
			oracleRegistryIssue ? "oracle_integrity_error" : "missing_provenance",
			oracleRegistryIssue
				? "preflight report trusted oracle registry is incomplete or invalid"
				: "preflight report is incomplete or invalid",
			{ details: { issues: parsed.error.issues } },
		);
	}
	const report = parsed.data;
	if (Object.keys(report.toolDigests).length === 0) {
		throw new CtfError("missing_provenance", "preflight report tool digests are missing");
	}
	validateVisibleArtifactAllowlist(report.visibleArtifactAllowlist);
	const safety = validateSafetyMaxima(report.safetyMaxima);
	const limits = validateOperationalLimits(report.operationalLimits, safety);
	const preflight = validateSandboxPreflight(report.preflight);
	const trustedRegistry = validateTrustedOracleRegistry(report.oracleRegistry);
	const registry = trustedRegistry.registry;
	if (!digestsEqual(registry.registryDigest, report.oracleRegistryDigest)) {
		throw new CtfError("digest_mismatch", "preflight report oracle registry digest mismatch");
	}
	const entry = registry.entries.find(candidate => candidate.oracleId === report.oracleId);
	if (entry === undefined || !entry.allowedChallengeIds.includes(report.challengeId)) {
		throw new CtfError(
			"oracle_integrity_error",
			`preflight report oracle is not authorized for challenge: ${report.challengeId}`,
		);
	}
	if (!digestsEqual(oracleEntryDigest(entry), report.oracleDigest)) {
		throw new CtfError("digest_mismatch", "preflight report oracle digest mismatch");
	}
	if (report.executionClass !== preflight.executionClass) {
		throw new CtfError("unsafe_sandbox", "preflight report execution class does not match sandbox preflight");
	}
	if (preflight.rootless && report.executionClass !== "verified-local/rootless-podman-network-off") {
		throw new CtfError("unsafe_sandbox", "rootless sandbox preflight requires the rootless execution class");
	}
	if (report.executionClass === "verified-local/rootless-podman-network-off" && !preflight.rootless) {
		throw new CtfError("unsafe_sandbox", "rootless execution class requires rootless sandbox preflight");
	}
	if (report.networkMode !== preflight.networkMode || report.networkMode !== safety.networkMode) {
		throw new CtfError("unsafe_sandbox", "preflight report network mode is not isolated");
	}
	if (preflight.imageDigest === undefined || !digestsEqual(report.imageDigest, preflight.imageDigest)) {
		throw new CtfError("digest_mismatch", "preflight report image digest does not match sandbox preflight");
	}
	if (preflight.limitsDigest !== limits.limitsDigest) {
		throw new CtfError(
			"digest_mismatch",
			"preflight report operational limits digest does not match sandbox preflight",
		);
	}
	if (report.passed !== preflight.passed) {
		throw new CtfError("unsafe_sandbox", "preflight report pass status does not match sandbox preflight");
	}
	if (report.passed && report.executionClass === "external-untrusted/proxmox-deferred") {
		throw new CtfError("unsafe_sandbox", "deferred external execution cannot pass local preflight");
	}
	if (!digestsEqual(preflightReportDigest(report), report.reportDigest)) {
		throw new CtfError("digest_mismatch", "preflight report digest mismatch");
	}
	return Object.freeze({
		...report,
		visibleArtifactAllowlist: [...report.visibleArtifactAllowlist],
		toolDigests: { ...report.toolDigests },
	});
}

export const parsePreflightReport = validatePreflightReport;
export const validatePreflightReportV1 = validatePreflightReport;
export const PreflightReportSchema = PreflightReportV1Schema;

export function validateScoredLimits(limits: OperationalLimitsV1, safety: SafetyMaximaV1): OperationalLimitsV1 {
	const validated = validateOperationalLimits(limits, safety);
	if (validated.selectedFor !== "benchmark")
		throw new CtfError("uncalibrated_limits", "benchmark scoring requires calibrated benchmark limits");
	return validated;
}
export const SafetyMaximaSchema = SafetyMaximaV1Schema;
export const OperationalLimitsSchema = OperationalLimitsV1Schema;
export const parseSafetyMaxima = validateSafetyMaxima;
export const parseOperationalLimits = validateOperationalLimits;
