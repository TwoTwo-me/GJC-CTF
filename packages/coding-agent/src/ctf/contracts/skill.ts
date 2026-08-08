import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual, sha256Hex } from "./digest";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const SkillSourceSchema = z.enum(["embedded", "workspace-override"]);
export type SkillSource = z.infer<typeof SkillSourceSchema>;

export const EffectiveSkillV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.skill),
		id: CtfIdSchema,
		version: z.string().regex(/^\d+\.\d+\.\d+$/),
		contentDigest: DigestSchema,
		loaderDigest: DigestSchema,
		buildDigest: DigestSchema,
		workspaceOverrideDigest: DigestSchema.nullable(),
		source: SkillSourceSchema,
		resolvedAt: TimestampSchema,
	})
	.strict();
export type EffectiveSkillV1 = z.infer<typeof EffectiveSkillV1Schema>;

export const SkillArtifactV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.skill),
		id: CtfIdSchema,
		version: z.string().regex(/^\d+\.\d+\.\d+$/),
		content: z.string().min(1),
		contentDigest: DigestSchema,
		loaderDigest: DigestSchema,
		buildDigest: DigestSchema,
	})
	.strict();
export type SkillArtifactV1 = z.infer<typeof SkillArtifactV1Schema>;

export function skillContentDigest(content: string): Digest {
	return sha256Hex(content);
}

export function effectiveSkillDigest(skill: EffectiveSkillV1): Digest {
	return canonicalDigest({
		schemaVersion: skill.schemaVersion,
		id: skill.id,
		version: skill.version,
		contentDigest: skill.contentDigest,
		loaderDigest: skill.loaderDigest,
		buildDigest: skill.buildDigest,
		workspaceOverrideDigest: skill.workspaceOverrideDigest,
		source: skill.source,
		resolvedAt: skill.resolvedAt,
	});
}

export function validateSkillArtifact(value: unknown): SkillArtifactV1 {
	const parsed = SkillArtifactV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_manifest", "skill artifact is invalid", { details: { issues: parsed.error.issues } });
	const artifact = parsed.data;
	assertKnownMajor(artifact.schemaVersion, "skill");
	if (!digestsEqual(skillContentDigest(artifact.content), artifact.contentDigest))
		throw new CtfError("digest_mismatch", "skill content digest mismatch");
	return artifact;
}

export function validateEffectiveSkill(value: unknown): EffectiveSkillV1 {
	const parsed = EffectiveSkillV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_manifest", "effective skill identity is invalid", {
			details: { issues: parsed.error.issues },
		});
	const skill = parsed.data;
	assertKnownMajor(skill.schemaVersion, "skill");
	if (skill.source === "workspace-override" && skill.workspaceOverrideDigest === null)
		throw new CtfError("invalid_manifest", "workspace override source requires an override digest");
	if (skill.source === "embedded" && skill.workspaceOverrideDigest !== null)
		throw new CtfError("invalid_manifest", "embedded skill cannot carry an override digest");
	return skill;
}

export function skillFieldsEqual(left: EffectiveSkillV1, right: EffectiveSkillV1): boolean {
	return (
		left.id === right.id &&
		left.version === right.version &&
		left.contentDigest === right.contentDigest &&
		left.loaderDigest === right.loaderDigest &&
		left.buildDigest === right.buildDigest &&
		left.workspaceOverrideDigest === right.workspaceOverrideDigest
	);
}
export const EffectiveSkillSchema = EffectiveSkillV1Schema;
export const SkillArtifactSchema = SkillArtifactV1Schema;
export const parseEffectiveSkill = validateEffectiveSkill;
export const parseSkillArtifact = validateSkillArtifact;
