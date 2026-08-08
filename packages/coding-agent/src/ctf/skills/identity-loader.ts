import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { parseFrontmatter } from "@gajae-code/utils";
import { resolveRootedPath } from "../../gjc-runtime/storage/rooted-store";
import {
	CTF_SCHEMA_VERSIONS,
	CtfError,
	canonicalDigest,
	digestsEqual,
	type EffectiveSkillV1,
	effectiveSkillDigest,
	type SkillArtifactV1,
	type SkillRef,
	sha256Hex,
	skillContentDigest,
	validateEffectiveSkill,
	validateSkillArtifact,
} from "../contracts";
import embeddedContent from "./ctf.md" with { type: "text" };

export const CTF_SKILL_ID = "ctf";
export const CTF_SKILL_VERSION = "1.1.0";
export const CTF_SKILL_OVERRIDE_RELATIVE_PATH = `.gjc-ctf/skills/overrides/${CTF_SKILL_ID}/SKILL.md`;
const CTF_SKILL_LEGACY_OVERRIDE_RELATIVE_PATH = `skills/${CTF_SKILL_ID}/SKILL.md`;

/* Generated-loader inputs are content-addressed, so replacing the generated
 * file changes the loader/build identities instead of silently changing a run. */
const GENERATED_LOADER_SOURCE = "gjc-ctf-skill-identity-loader/v1";
export const CTF_SKILL_LOADER_DIGEST = sha256Hex(GENERATED_LOADER_SOURCE);
export const CTF_SKILL_BUILD_DIGEST = sha256Hex(`${GENERATED_LOADER_SOURCE}:${CTF_SKILL_VERSION}`);
export const CTF_SKILL_RESOLUTION_TIME = "2026-01-01T00:00:00.000Z";

export interface CtfSkillResolution extends EffectiveSkillV1 {
	content: string;
}

export interface CtfSkillIdentityLoader {
	readonly artifact: SkillArtifactV1;
	load(options?: CtfSkillLoadOptions): Promise<CtfSkillResolution>;
}

export interface CtfSkillLoadOptions {
	/** The competition root. Overrides are read only below this directory. */
	competitionRoot?: string;
	workspaceRoot?: string;
	/** Relative path under competitionRoot; defaults to the canonical .gjc-ctf override. */
	overridePath?: string;
	expected?: SkillRef;
	expectedEffective?: EffectiveSkillV1;
	expectedWorkspaceOverrideDigest?: string;
	resolvedAt?: string;
}

function assertSkillFrontmatter(content: string, source: string): void {
	let frontmatter: Record<string, unknown>;
	try {
		frontmatter = parseFrontmatter(content, { source, level: "fatal" }).frontmatter;
	} catch {
		throw new CtfError("invalid_manifest", "CTF skill frontmatter is invalid");
	}
	if (frontmatter.name !== CTF_SKILL_ID || frontmatter.version !== CTF_SKILL_VERSION) {
		throw new CtfError("invalid_manifest", "CTF skill ID or version does not match the generated identity");
	}
}

function embeddedArtifact(): SkillArtifactV1 {
	assertSkillFrontmatter(embeddedContent, "embedded:gjc/ctf/skills/ctf.md");
	return validateSkillArtifact({
		schemaVersion: CTF_SCHEMA_VERSIONS.skill,
		id: CTF_SKILL_ID,
		version: CTF_SKILL_VERSION,
		content: embeddedContent,
		contentDigest: skillContentDigest(embeddedContent),
		loaderDigest: CTF_SKILL_LOADER_DIGEST,
		buildDigest: CTF_SKILL_BUILD_DIGEST,
	});
}

export const GENERATED_CTF_SKILL_ARTIFACT = embeddedArtifact();
function isUnsafeRelativePath(value: string): boolean {
	return (
		value.includes("\0") ||
		path.posix.isAbsolute(value) ||
		path.win32.isAbsolute(value) ||
		/^[A-Za-z]:/.test(value) ||
		value.split(/[\\/]+/).includes("..")
	);
}
function overrideTarget(root: string, relativePath: string): string {
	if (isUnsafeRelativePath(relativePath)) {
		throw new CtfError("invalid_manifest", "CTF skill override must remain below the competition root");
	}
	try {
		return resolveRootedPath(root, relativePath);
	} catch {
		throw new CtfError("invalid_manifest", "CTF skill override escapes the competition root");
	}
}

async function readOverride(
	root: string,
	relativePath: string,
): Promise<{ content: string; artifact?: SkillArtifactV1 } | undefined> {
	const target = overrideTarget(root, relativePath);
	let text: string;
	try {
		text = await readFile(target, "utf8");
	} catch (error) {
		if (typeof error === "object" && error !== null && (error as NodeJS.ErrnoException).code === "ENOENT")
			return undefined;
		throw new CtfError("integrity_error", "unable to read the CTF skill workspace override");
	}
	if (!text.trim()) throw new CtfError("invalid_manifest", "CTF skill workspace override is empty");
	try {
		const parsed: unknown = JSON.parse(text);
		if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) && "content" in parsed) {
			const artifact = validateSkillArtifact(parsed);
			return { content: artifact.content, artifact };
		}
	} catch (error) {
		if (error instanceof CtfError) throw error;
		// Plain Markdown is the normal workspace override format.
	}
	assertSkillFrontmatter(text, target);
	return { content: text, artifact: undefined };
}

async function readCompetitionOverride(
	root: string,
	overridePath?: string,
): Promise<{ content: string; artifact?: SkillArtifactV1 } | undefined> {
	const override = await readOverride(root, overridePath ?? CTF_SKILL_OVERRIDE_RELATIVE_PATH);
	if (override !== undefined || overridePath !== undefined) return override;
	// Legacy compatibility is consulted only when the canonical path is absent.
	return readOverride(root, CTF_SKILL_LEGACY_OVERRIDE_RELATIVE_PATH);
}

function assertArtifactCompatibility(artifact: SkillArtifactV1, embedded: SkillArtifactV1): void {
	if (artifact.id !== embedded.id || artifact.version !== embedded.version) {
		throw new CtfError("invalid_manifest", "CTF skill workspace artifact ID or version mismatch");
	}
	if (
		!digestsEqual(artifact.loaderDigest, embedded.loaderDigest) ||
		!digestsEqual(artifact.buildDigest, embedded.buildDigest)
	) {
		throw new CtfError("digest_mismatch", "CTF skill workspace artifact loader or build digest mismatch");
	}
}

function assertExpected(identity: EffectiveSkillV1, options: CtfSkillLoadOptions): void {
	if (options.expected) {
		if (options.expected.id !== identity.id || options.expected.version !== identity.version) {
			throw new CtfError("invalid_manifest", "CTF skill ID or version does not match the competition manifest");
		}
		if (!digestsEqual(options.expected.digest, effectiveSkillDigest(identity))) {
			throw new CtfError("digest_mismatch", "CTF effective skill digest does not match the competition manifest");
		}
	}
	if (
		options.expectedWorkspaceOverrideDigest !== undefined &&
		!digestsEqual(options.expectedWorkspaceOverrideDigest, identity.workspaceOverrideDigest ?? "")
	) {
		throw new CtfError("digest_mismatch", "CTF workspace override digest does not match the expected digest");
	}
	if (options.expectedEffective) {
		const expected = validateEffectiveSkill(options.expectedEffective);
		if (canonicalDigest(expected) !== canonicalDigest(identity))
			throw new CtfError("digest_mismatch", "CTF effective skill identity is stale");
	}
}

/** Resolve generated embedded content, optionally replacing it with a checked workspace override. */
export function createCtfSkillIdentityLoader(): CtfSkillIdentityLoader {
	return {
		artifact: GENERATED_CTF_SKILL_ARTIFACT,
		async load(options = {}) {
			const embedded = GENERATED_CTF_SKILL_ARTIFACT;
			const competitionRoot = options.competitionRoot ?? options.workspaceRoot;
			const override = competitionRoot
				? await readCompetitionOverride(competitionRoot, options.overridePath)
				: undefined;
			if (options.expectedWorkspaceOverrideDigest !== undefined && override === undefined) {
				throw new CtfError("digest_mismatch", "expected CTF workspace override is missing");
			}
			if (override?.artifact) assertArtifactCompatibility(override.artifact, embedded);
			const content = override?.content ?? embedded.content;
			const contentDigest = skillContentDigest(content);
			if (override?.artifact && !digestsEqual(contentDigest, override.artifact.contentDigest)) {
				throw new CtfError("digest_mismatch", "CTF workspace artifact content digest mismatch");
			}
			const identity: EffectiveSkillV1 = validateEffectiveSkill({
				schemaVersion: CTF_SCHEMA_VERSIONS.skill,
				id: embedded.id,
				version: embedded.version,
				contentDigest,
				loaderDigest: embedded.loaderDigest,
				buildDigest: embedded.buildDigest,
				workspaceOverrideDigest: override ? contentDigest : null,
				source: override ? "workspace-override" : "embedded",
				resolvedAt: options.resolvedAt ?? CTF_SKILL_RESOLUTION_TIME,
			});
			assertExpected(identity, options);
			return { ...identity, content };
		},
	};
}

export const ctfSkillIdentityLoader = createCtfSkillIdentityLoader();
export const loadCtfSkillIdentity = (options?: CtfSkillLoadOptions) => ctfSkillIdentityLoader.load(options);
export const loadGeneratedCtfSkill = loadCtfSkillIdentity;
