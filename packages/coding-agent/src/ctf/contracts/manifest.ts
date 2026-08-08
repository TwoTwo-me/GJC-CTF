import * as path from "node:path";
import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual, isDigest } from "./digest";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const TrustLevelSchema = z.enum(["fixture", "verified-local", "external-untrusted"]);
export type TrustLevel = z.infer<typeof TrustLevelSchema>;
export const ExecutionClassSchema = z.enum(["static", "rootless-podman-network-off", "proxmox-deferred"]);
export type ExecutionClass = z.infer<typeof ExecutionClassSchema>;

export const SkillRefSchema = z
	.object({
		id: CtfIdSchema,
		version: z.string().regex(/^\d+\.\d+\.\d+$/),
		digest: DigestSchema,
	})
	.strict();
export type SkillRef = z.infer<typeof SkillRefSchema>;

export const OperationalLimitsRefSchema = z
	.object({
		calibrationId: CtfIdSchema,
		limitsDigest: DigestSchema,
		wallMs: PositiveIntegerSchema,
		cpuCores: PositiveIntegerSchema,
		memoryBytes: PositiveIntegerSchema,
		pids: PositiveIntegerSchema,
		outputBytes: PositiveIntegerSchema,
		fileDescriptors: PositiveIntegerSchema,
		tmpBytes: PositiveIntegerSchema,
		safetyPolicyDigest: DigestSchema,
	})
	.strict();
export type OperationalLimitsRef = z.infer<typeof OperationalLimitsRefSchema>;

export const BackendRefSchema = z
	.object({
		kind: z.string().min(1).max(128),
		version: z.string().min(1).max(128),
		imageRef: z.string().min(1).max(512).optional(),
		imageDigest: DigestSchema.optional(),
		toolVersions: z.record(z.string().min(1), z.string().min(1)),
	})
	.strict();
export type BackendRef = z.infer<typeof BackendRefSchema>;

export const ChallengeDescriptorSchema = z
	.object({
		id: CtfIdSchema,
		category: z.string().min(1).max(128),
		sourcePath: z.string().min(1).max(1024),
		sourceRevision: z.string().min(1).max(256),
		sourceSha256: DigestSchema,
		trustLevel: TrustLevelSchema,
		executionClass: ExecutionClassSchema,
		visibleArtifactAllowlist: z.array(z.string().min(1)).max(4096),
		backend: BackendRefSchema,
		networkMode: z.literal("off"),
		limits: OperationalLimitsRefSchema,
		safetyPolicyDigest: DigestSchema,
		calibrationId: CtfIdSchema,
		oracleId: CtfIdSchema,
		oracleRegistryDigest: DigestSchema.optional(),
		oracleEntryDigest: DigestSchema.optional(),
		oracleDigest: DigestSchema.optional(),
		backendDigest: DigestSchema.optional(),
		registeredAt: TimestampSchema,
		descriptorDigest: DigestSchema,
	})
	.strict();
export type ChallengeDescriptor = z.infer<typeof ChallengeDescriptorSchema>;

export const ManifestV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.manifest),
		competitionId: CtfIdSchema,
		manifestRevision: PositiveIntegerSchema,
		createdAt: TimestampSchema,
		toolVersion: z.string().min(1).max(128),
		skill: SkillRefSchema,
		challenges: z.array(ChallengeDescriptorSchema),
		activeBenchmarkLockId: CtfIdSchema.optional(),
		manifestDigest: DigestSchema,
	})
	.strict();
export type ManifestV1 = z.infer<typeof ManifestV1Schema>;

export function challengeDescriptorDigest(
	descriptor: ChallengeDescriptor | Omit<ChallengeDescriptor, "descriptorDigest">,
): Digest {
	return canonicalDigest(descriptor, ["descriptorDigest"]);
}

export function manifestDigest(manifest: ManifestV1 | Omit<ManifestV1, "manifestDigest">): Digest {
	return canonicalDigest(manifest, ["manifestDigest"]);
}
export function isUnsafeRelativePath(value: string): boolean {
	return (
		value.includes("\0") ||
		path.posix.isAbsolute(value) ||
		path.win32.isAbsolute(value) ||
		/^[A-Za-z]:/.test(value) ||
		/^[\\/]/.test(value) ||
		value.split(/[\\/]+/).includes("..")
	);
}
export function validateChallengeDescriptor(descriptor: unknown): ChallengeDescriptor {
	const parsed = ChallengeDescriptorSchema.safeParse(descriptor);
	if (!parsed.success)
		throw new CtfError("invalid_manifest", "challenge descriptor is invalid", {
			details: { issues: parsed.error.issues },
		});
	const value = parsed.data;
	for (const artifactPath of value.visibleArtifactAllowlist) {
		if (isUnsafeRelativePath(artifactPath)) {
			throw new CtfError(
				"missing_provenance",
				`visible artifact path is not confined to the clean room: ${artifactPath}`,
			);
		}
	}
	if (!digestsEqual(challengeDescriptorDigest(value), value.descriptorDigest)) {
		throw new CtfError("digest_mismatch", `descriptor digest mismatch for ${value.id}`);
	}
	if (isUnsafeRelativePath(value.sourcePath)) {
		throw new CtfError("invalid_manifest", `challenge source path escapes competition root: ${value.sourcePath}`);
	}
	if (value.limits.calibrationId !== value.calibrationId) {
		throw new CtfError("invalid_manifest", `calibration reference mismatch for ${value.id}`);
	}
	if (!digestsEqual(value.limits.safetyPolicyDigest, value.safetyPolicyDigest)) {
		throw new CtfError(
			"invalid_manifest",
			`safety policy reference does not match calibrated limits for ${value.id}`,
		);
	}
	if (value.executionClass === "rootless-podman-network-off" && value.backend.imageDigest === undefined) {
		throw new CtfError("invalid_manifest", `rootless challenge ${value.id} requires a pinned image digest`);
	}
	return value;
}

export function validateManifest(value: unknown): ManifestV1 {
	const parsed = ManifestV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_manifest", "manifest is invalid", { details: { issues: parsed.error.issues } });
	const manifest = parsed.data;
	assertKnownMajor(manifest.schemaVersion, "manifest");
	const ids = new Set<string>();
	for (const descriptor of manifest.challenges) {
		if (ids.has(descriptor.id)) throw new CtfError("invalid_manifest", `duplicate challenge id: ${descriptor.id}`);
		ids.add(descriptor.id);
		validateChallengeDescriptor(descriptor);
	}
	if (!isDigest(manifest.manifestDigest) || !digestsEqual(manifestDigest(manifest), manifest.manifestDigest)) {
		throw new CtfError("digest_mismatch", "manifest digest mismatch");
	}
	return manifest;
}

export function parseManifest(value: unknown): ManifestV1 {
	return validateManifest(value);
}
export const ManifestSchema = ManifestV1Schema;
export const ChallengeDescriptorSchemaV1 = ChallengeDescriptorSchema;
export const parseManifestV1 = parseManifest;
