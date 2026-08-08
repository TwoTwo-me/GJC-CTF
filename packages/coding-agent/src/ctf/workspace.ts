import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ensureRootedArtifact, readRootedArtifact } from "@gajae-code/natives";
import { withFileLock } from "../config/file-lock";
import { createRootedStore, type RootedStore } from "../gjc-runtime/storage/rooted-store";
import {
	type ChallengeDescriptor,
	CTF_SCHEMA_VERSIONS,
	CtfIdSchema,
	canonicalDigest,
	challengeDescriptorDigest,
	DigestSchema,
	digestsEqual,
	type EventV1,
	effectiveSkillDigest,
	eventDigest,
	eventPayloadDigest,
	type ManifestV1,
	oracleEntryDigest,
	parseEvent,
	type RegistrationTxnV1,
	type SkillRef,
	SkillRefSchema,
	TimestampSchema,
	validateChallengeDescriptor,
	validateManifest as validateContractManifest,
	validateRegistrationTxn,
} from "./contracts";
import { type TrustedOracleRegistry, validateTrustedOracleRegistry } from "./runtime/oracle";
import {
	GENERATED_CTF_SKILL_ARTIFACT,
	generatedCtfSkillArtifactRelativePath,
	generatedCtfSkillInstalledIdentity,
	loadCtfSkillIdentity,
} from "./skills/identity-loader";

export const CTF_MANIFEST_FILENAME = "gjc-ctf.manifest.json";
export const CTF_STATE_DIRNAME = ".gjc-ctf";
export const CTF_MANIFEST_SCHEMA = CTF_SCHEMA_VERSIONS.manifest;
const CTF_INIT_RECEIPT_FILENAME = ".gjc-ctf-init.json";

const COMPETITION_DIRNAME = "competition";
const REGISTRATION_DIRNAME = "registration";
const EVENTS_DIRNAME = "events";
const CHECKPOINTS_DIRNAME = "checkpoints";
const EVENT_HEAD_FILENAME = "event-head.json";
const REGISTRATION_JOURNAL_FILENAME = "registration-journal.jsonl";
const ZERO_EVENT_DIGEST = createHash("sha256").update("").digest("hex");

/** A manifest without a skill is retained solely for backwards-compatible init. Registration requires one. */
export type CtfManifest = Omit<ManifestV1, "skill"> & { skill?: SkillRef };
export type CtfChallengeDescriptor = ChallengeDescriptor;
export type CtfRegistrationMode = "fixture" | "unavailable" | "competition" | "scored" | "benchmark";
export type CtfTrustedRegistrationAuthority = {
	trustedRegistry?: TrustedOracleRegistry;
	trustedOracleRegistry?: TrustedOracleRegistry;
	oracleRegistry?: TrustedOracleRegistry;
	registry?: TrustedOracleRegistry;
	oracleId?: string;
	selectedOracleId?: string;
	registryDigest?: string;
	oracleRegistryDigest?: string;
	oracleEntryDigest?: string;
	entryDigest?: string;
	oracleDigest?: string;
	backendDigest?: string;
	imageDigest?: string;
};
export type CtfRegistrationOptions = CtfTrustedRegistrationAuthority & {
	mode?: CtfRegistrationMode;
	authority?: CtfTrustedRegistrationAuthority;
	trustedAuthority?: CtfTrustedRegistrationAuthority;
	registrationAuthority?: CtfTrustedRegistrationAuthority;
};

export interface CtfWorkspace {
	root: string;
	stateRoot: string;
	stateStore: RootedStore;
	manifestPath: string;
	manifest: CtfManifest;
}

export type CtfWorkspaceErrorCode =
	| "manifest_missing"
	| "unmarked_directory"
	| "invalid_manifest"
	| "unknown_manifest_version"
	| "manifest_digest_mismatch"
	| "digest_mismatch"
	| "unknown_schema_major"
	| "challenge_conflict"
	| "idempotency_conflict"
	| "revision_conflict"
	| "invalid_registration"
	| "registration_repair_required"
	| "oracle_integrity_error"
	| "integrity_error";

/** Errors are deliberately typed so callers cannot mistake a refused mutation for success. */
export class CtfWorkspaceError extends Error {
	readonly code: CtfWorkspaceErrorCode;
	readonly retryable: boolean;
	readonly details: Record<string, unknown> | undefined;

	constructor(code: CtfWorkspaceErrorCode, message: string, retryable = false, details?: Record<string, unknown>) {
		super(message);
		this.name = "CtfWorkspaceError";
		this.code = code;
		this.retryable = retryable;
		this.details = details;
	}
}

function errorFrom(
	error: unknown,
	fallback: CtfWorkspaceErrorCode,
	message: string,
	retryable = false,
): CtfWorkspaceError {
	if (error instanceof CtfWorkspaceError) return error;
	const source = error as { code?: unknown; message?: unknown; details?: unknown };
	const code =
		typeof source.code === "string" &&
		[
			"invalid_manifest",
			"unknown_manifest_version",
			"manifest_digest_mismatch",
			"digest_mismatch",
			"unknown_schema_major",
			"idempotency_conflict",
			"revision_conflict",
			"invalid_registration",
			"registration_repair_required",
			"oracle_integrity_error",
			"integrity_error",
		].includes(source.code)
			? (source.code as CtfWorkspaceErrorCode)
			: fallback;
	return new CtfWorkspaceError(
		code,
		typeof source.message === "string" ? source.message : message,
		retryable,
		typeof source.details === "object" && source.details !== null
			? (source.details as Record<string, unknown>)
			: undefined,
	);
}

function canonical(value: unknown, omit: readonly string[] = []): string {
	return canonicalDigest(value, omit);
}

function computeManifestDigest(manifest: Omit<CtfManifest, "manifestDigest">): string {
	return canonical(manifest, ["manifestDigest"]);
}

function computeDescriptorDigest(descriptor: Omit<CtfChallengeDescriptor, "descriptorDigest">): string {
	return challengeDescriptorDigest(descriptor);
}

function computeEventDigest(event: EventV1): string {
	return eventDigest(event);
}

function isObject(value: unknown): value is Record<string, unknown> {
	return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isErrno(error: unknown, code: string): boolean {
	return Boolean(error && typeof error === "object" && (error as NodeJS.ErrnoException).code === code);
}

async function readBytes(target: string): Promise<Buffer | undefined> {
	try {
		return await fs.readFile(target);
	} catch (error) {
		if (isErrno(error, "ENOENT")) return undefined;
		throw error;
	}
}

async function writeBytesAtomic(target: string, bytes: Uint8Array): Promise<void> {
	await fs.mkdir(path.dirname(target), { recursive: true });
	const temporary = `${target}.tmp-${process.pid}-${randomUUID()}`;
	try {
		const handle = await fs.open(temporary, "wx", 0o600);
		try {
			await handle.writeFile(bytes);
			await handle.sync();
		} finally {
			await handle.close();
		}
		await fs.rename(temporary, target);
		const directory = await fs.open(path.dirname(target), "r");
		try {
			await directory.sync();
		} finally {
			await directory.close();
		}
	} catch (error) {
		await fs.rm(temporary, { force: true }).catch(() => undefined);
		throw error;
	}
}

function jsonBytes(value: unknown): Buffer {
	return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

async function readJson(target: string): Promise<unknown | undefined> {
	const bytes = await readBytes(target);
	if (bytes === undefined) return undefined;
	try {
		return JSON.parse(bytes.toString("utf8"));
	} catch {
		throw new CtfWorkspaceError("integrity_error", `Invalid JSON state: ${target}`);
	}
}

async function writeJsonAtomic(target: string, value: unknown): Promise<void> {
	await writeBytesAtomic(target, jsonBytes(value));
}

/**
 * CTF state writes are intentionally rooted and capability-bound: callers must
 * provide the workspace stateStore, which enforces containment and the CTF
 * durability profile. There is no direct filesystem-write fallback for state.
 */
async function ensureEqualOrWrite(
	target: string,
	value: unknown,
	code: CtfWorkspaceErrorCode,
	label: string,
	workspace: CtfWorkspace,
): Promise<void> {
	const expected = jsonBytes(value);
	const existing = await readBytes(target);
	if (existing === undefined) {
		const relative = stateStoreRelativePath(workspace, target);
		await workspace.stateStore.writeJsonAtomic(relative, value, { durability: "ctf" });
		return;
	}
	if (existing.equals(expected)) return;
	let parsed: unknown;
	try {
		parsed = JSON.parse(existing.toString("utf8"));
	} catch {
		throw new CtfWorkspaceError(code, `${label} is corrupt; refusing to overwrite ${target}`);
	}
	if (canonical(parsed) !== canonical(value)) {
		throw new CtfWorkspaceError(code, `${label} conflicts with existing bytes at ${target}`);
	}
	// Semantically identical bytes are intentionally preserved; repair must never clobber user bytes.
}

function asManifest(value: unknown, manifestPath: string): CtfManifest {
	if (!isObject(value)) throw new CtfWorkspaceError("invalid_manifest", `Manifest is not an object: ${manifestPath}`);
	if (value.schemaVersion !== CTF_MANIFEST_SCHEMA) {
		throw new CtfWorkspaceError("unknown_manifest_version", `Unsupported CTF manifest schema at ${manifestPath}`);
	}
	try {
		if (value.skill !== undefined) return validateContractManifest(value) as CtfManifest;
		const allowedKeys = new Set([
			"schemaVersion",
			"competitionId",
			"manifestRevision",
			"createdAt",
			"toolVersion",
			"challenges",
			"activeBenchmarkLockId",
			"manifestDigest",
		]);
		if (
			Object.keys(value).some(key => !allowedKeys.has(key)) ||
			!CtfIdSchema.safeParse(value.competitionId).success ||
			typeof value.manifestRevision !== "number" ||
			!Number.isInteger(value.manifestRevision) ||
			value.manifestRevision < 1 ||
			!TimestampSchema.safeParse(value.createdAt).success ||
			typeof value.toolVersion !== "string" ||
			value.toolVersion.length < 1 ||
			value.toolVersion.length > 128 ||
			(value.activeBenchmarkLockId !== undefined && !CtfIdSchema.safeParse(value.activeBenchmarkLockId).success) ||
			!Array.isArray(value.challenges) ||
			typeof value.manifestDigest !== "string" ||
			!DigestSchema.safeParse(value.manifestDigest).success
		) {
			throw new Error("manifest identity, revision, timestamps, or fields are invalid");
		}
		const ids = new Set<string>();
		for (const descriptor of value.challenges) {
			const parsed = validateChallengeDescriptor(descriptor);
			if (ids.has(parsed.id)) throw new Error(`duplicate challenge id: ${parsed.id}`);
			ids.add(parsed.id);
		}
		const withoutDigest = { ...value } as Record<string, unknown>;
		delete withoutDigest.manifestDigest;
		if (
			!digestsEqual(
				computeManifestDigest(withoutDigest as Omit<CtfManifest, "manifestDigest">),
				value.manifestDigest,
			)
		) {
			throw new Error("manifest digest mismatch");
		}
		return value as CtfManifest;
	} catch (error) {
		if (error instanceof CtfWorkspaceError) throw error;
		throw errorFrom(error, "invalid_manifest", `Manifest is invalid: ${manifestPath}`);
	}
}

export async function readCtfManifest(root: string): Promise<CtfManifest> {
	const resolvedRoot = path.resolve(root);
	const manifestPath = path.join(resolvedRoot, CTF_MANIFEST_FILENAME);
	await assertPathWithinRoot(resolvedRoot, manifestPath, "integrity_error", "CTF manifest");
	let parsed: unknown;
	try {
		parsed = JSON.parse(await fs.readFile(manifestPath, "utf8"));
	} catch (error) {
		if (isErrno(error, "ENOENT"))
			throw new CtfWorkspaceError("manifest_missing", `No CTF manifest found at ${resolvedRoot}`);
		if (error instanceof CtfWorkspaceError) throw error;
		throw new CtfWorkspaceError("invalid_manifest", `Unable to read CTF manifest at ${manifestPath}`);
	}
	return asManifest(parsed, manifestPath);
}

function workspaceFor(root: string, manifest: CtfManifest): CtfWorkspace {
	const resolvedRoot = path.resolve(root);
	const stateRoot = path.join(resolvedRoot, CTF_STATE_DIRNAME);
	return {
		root: resolvedRoot,
		stateRoot,
		stateStore: createRootedStore(stateRoot, { cwd: resolvedRoot, durability: "ctf" }),
		manifestPath: path.join(resolvedRoot, CTF_MANIFEST_FILENAME),
		manifest,
	};
}
/**
 * Root-level manifest updates are outside the `.gjc-ctf` state root. They still
 * use the sanctioned state-writer authority; the initialization write below is
 * the only direct atomic writer retained for backwards-compatible bootstrapping.
 */
function manifestStoreFor(workspace: CtfWorkspace): RootedStore {
	return createRootedStore(workspace.root, { cwd: workspace.root, durability: "ctf" });
}
function manifestRelativePath(workspace: CtfWorkspace): string {
	const expected = path.join(workspace.root, CTF_MANIFEST_FILENAME);
	if (path.resolve(workspace.manifestPath) !== path.resolve(expected)) {
		throw new CtfWorkspaceError(
			"integrity_error",
			`CTF manifest path escapes workspace root: ${workspace.manifestPath}`,
		);
	}
	return path.relative(workspace.root, expected);
}

function competitionRoot(workspace: CtfWorkspace): string {
	return path.join(workspace.stateRoot, COMPETITION_DIRNAME);
}

function stateStoreRelativePath(workspace: CtfWorkspace, target: string): string {
	if (path.resolve(workspace.stateStore.root) !== path.resolve(workspace.stateRoot)) {
		throw new CtfWorkspaceError("integrity_error", "CTF workspace state store is not rooted at the state root");
	}
	return stateRelativePath(workspace, target);
}
function stateRelativePath(workspace: CtfWorkspace, target: string): string {
	const relative = path.relative(workspace.stateRoot, target);
	if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
		throw new CtfWorkspaceError("integrity_error", `CTF state path escapes state root: ${target}`);
	}
	return relative;
}

async function realpathWithMissingLeaf(
	target: string,
	danglingCode: CtfWorkspaceErrorCode = "integrity_error",
): Promise<string> {
	const missing: string[] = [];
	let current = target;
	for (;;) {
		try {
			const resolved = await fs.realpath(current);
			return path.join(resolved, ...missing);
		} catch (error) {
			if (!isErrno(error, "ENOENT")) throw error;
			try {
				if ((await fs.lstat(current)).isSymbolicLink()) {
					throw new CtfWorkspaceError(danglingCode, `CTF path is a dangling symlink: ${target}`);
				}
			} catch (lstatError) {
				if (!isErrno(lstatError, "ENOENT")) throw lstatError;
			}
			const parent = path.dirname(current);
			if (parent === current) return path.resolve(current, ...missing);
			missing.unshift(path.basename(current));
			current = parent;
		}
	}
}
async function assertPathWithinRoot(
	root: string,
	target: string,
	code: CtfWorkspaceErrorCode,
	label: string,
): Promise<void> {
	const [rootRealpath, targetRealpath] = await Promise.all([
		realpathWithMissingLeaf(root),
		realpathWithMissingLeaf(target, code),
	]);
	const relative = path.relative(rootRealpath, targetRealpath);
	if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
		throw new CtfWorkspaceError(code, `${label} escapes competition root`);
	}
}
async function assertStateRoot(workspace: CtfWorkspace): Promise<void> {
	await assertPathWithinRoot(workspace.root, workspace.stateRoot, "integrity_error", "CTF state root");
}

async function assertCompetitionArtifactPaths(
	workspace: CtfWorkspace,
	descriptor: CtfChallengeDescriptor,
	code: CtfWorkspaceErrorCode,
): Promise<void> {
	await assertPathWithinRoot(
		workspace.root,
		path.resolve(workspace.root, descriptor.sourcePath),
		code,
		"challenge source path",
	);
	for (const artifactPath of descriptor.visibleArtifactAllowlist) {
		await assertPathWithinRoot(
			workspace.root,
			path.resolve(workspace.root, artifactPath),
			code,
			"visible artifact path",
		);
	}
}

async function assertStatePath(workspace: CtfWorkspace, target: string): Promise<void> {
	await assertStateRoot(workspace);
	const [root, candidate] = await Promise.all([
		realpathWithMissingLeaf(workspace.stateRoot),
		realpathWithMissingLeaf(target),
	]);
	const relative = path.relative(root, candidate);
	if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
		throw new CtfWorkspaceError("integrity_error", `CTF state path escapes state root: ${target}`);
	}
}

function transactionRoot(workspace: CtfWorkspace): string {
	return path.join(competitionRoot(workspace), REGISTRATION_DIRNAME);
}

function eventRoot(workspace: CtfWorkspace): string {
	return path.join(competitionRoot(workspace), EVENTS_DIRNAME);
}

function checkpointRoot(workspace: CtfWorkspace): string {
	return path.join(competitionRoot(workspace), CHECKPOINTS_DIRNAME);
}

function eventHeadPath(workspace: CtfWorkspace): string {
	return path.join(competitionRoot(workspace), EVENT_HEAD_FILENAME);
}

function registrationJournalPath(workspace: CtfWorkspace): string {
	return path.join(competitionRoot(workspace), REGISTRATION_JOURNAL_FILENAME);
}

async function assertWorkspaceState(workspace: CtfWorkspace): Promise<void> {
	await assertStateRoot(workspace);
	const disk = await readCtfManifest(workspace.root);
	if (
		disk.competitionId !== workspace.manifest.competitionId ||
		disk.manifestRevision !== workspace.manifest.manifestRevision ||
		!digestsEqual(disk.manifestDigest, workspace.manifest.manifestDigest)
	) {
		throw new CtfWorkspaceError("revision_conflict", "workspace manifest is stale", true);
	}
	const stateStat = await fs.stat(workspace.stateRoot).catch(() => undefined);
	await Promise.all(
		workspace.manifest.challenges.map(challenge =>
			assertCompetitionArtifactPaths(workspace, challenge, "integrity_error"),
		),
	);
	if (!stateStat?.isDirectory())
		throw new CtfWorkspaceError("integrity_error", `CTF state directory is missing: ${workspace.stateRoot}`);
	await assertCanonicalEventHead(workspace);
	await validateRegistrationJournal(workspace);
}

export type CtfWorkspaceInitOptions = { skill?: SkillRef };

type GeneratedSkillPublication = {
	skill: SkillRef;
	path: string;
	created: boolean;
};

function generatedSkillArtifactBytes(): Buffer {
	return Buffer.from(`${JSON.stringify(GENERATED_CTF_SKILL_ARTIFACT)}\n`, "utf8");
}

function generatedSkillArtifactLocation(
	root: string,
	relativePath: string,
): {
	directories: string[];
	leaf: string;
	path: string;
} {
	const parts = relativePath.split("/");
	if (parts.some(part => !part || part === "." || part === ".."))
		throw new CtfWorkspaceError("integrity_error", "generated CTF skill artifact path is invalid");
	const leaf = parts.at(-1);
	if (leaf === undefined)
		throw new CtfWorkspaceError("integrity_error", "generated CTF skill artifact path is invalid");
	return { directories: parts.slice(0, -1), leaf, path: path.join(root, ...parts) };
}

async function publishGeneratedSkillArtifact(root: string): Promise<GeneratedSkillPublication> {
	const installed = generatedCtfSkillInstalledIdentity();
	const digest = effectiveSkillDigest(installed);
	const relativePath = generatedCtfSkillArtifactRelativePath(digest);
	const location = generatedSkillArtifactLocation(root, relativePath);
	const bytes = generatedSkillArtifactBytes();
	const publication = ensureRootedArtifact(root, location.directories, location.leaf, bytes, bytes.byteLength);
	if (!publication.ok) {
		throw new CtfWorkspaceError(
			"integrity_error",
			`generated CTF skill artifact publication failed: ${publication.code ?? "unknown"}`,
		);
	}
	if (!publication.created && (publication.bytes === undefined || !Buffer.from(publication.bytes).equals(bytes))) {
		throw new CtfWorkspaceError("integrity_error", "generated CTF skill artifact conflicts with this binary");
	}
	const resolved = await loadCtfSkillIdentity({
		competitionRoot: root,
		expected: { id: installed.id, version: installed.version, digest },
	});
	return {
		skill: { id: resolved.id, version: resolved.version, digest: effectiveSkillDigest(resolved) },
		path: location.path,
		created: publication.created,
	};
}

type GeneratedInitReceipt = {
	schemaVersion: "ctf-init-receipt-1";
	manifest: ManifestV1;
};

function generatedSkillRef(): SkillRef {
	const installed = generatedCtfSkillInstalledIdentity();
	return { id: installed.id, version: installed.version, digest: effectiveSkillDigest(installed) };
}

function assertGeneratedInitManifest(value: unknown): ManifestV1 {
	const manifest = validateContractManifest(value);
	const expectedSkill = generatedSkillRef();
	if (
		manifest.manifestRevision !== 1 ||
		manifest.challenges.length !== 0 ||
		manifest.skill.id !== expectedSkill.id ||
		manifest.skill.version !== expectedSkill.version ||
		!digestsEqual(manifest.skill.digest, expectedSkill.digest)
	) {
		throw new CtfWorkspaceError("integrity_error", "CTF init receipt does not bind the current generated skill");
	}
	return manifest;
}

function generatedInitReceiptBytes(manifest: ManifestV1): Buffer {
	return jsonBytes({ schemaVersion: "ctf-init-receipt-1", manifest } satisfies GeneratedInitReceipt);
}

function parseGeneratedInitReceipt(bytes: Uint8Array): GeneratedInitReceipt {
	let parsed: unknown;
	try {
		parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
	} catch {
		throw new CtfWorkspaceError("integrity_error", "CTF init receipt JSON is invalid");
	}
	if (
		!isObject(parsed) ||
		parsed.schemaVersion !== "ctf-init-receipt-1" ||
		Object.keys(parsed).sort().join(",") !== "manifest,schemaVersion"
	) {
		throw new CtfWorkspaceError("integrity_error", "CTF init receipt shape is invalid");
	}
	const manifest = assertGeneratedInitManifest(parsed.manifest);
	const expected = generatedInitReceiptBytes(manifest);
	if (!Buffer.from(bytes).equals(expected))
		throw new CtfWorkspaceError("integrity_error", "CTF init receipt bytes are not canonical");
	return { schemaVersion: "ctf-init-receipt-1", manifest };
}

function publishGeneratedInitReceipt(root: string, manifest: ManifestV1): boolean {
	const bytes = generatedInitReceiptBytes(manifest);
	const publication = ensureRootedArtifact(root, [], CTF_INIT_RECEIPT_FILENAME, bytes, bytes.byteLength);
	if (!publication.ok)
		throw new CtfWorkspaceError(
			"integrity_error",
			`CTF init receipt publication failed: ${publication.code ?? "unknown"}`,
		);
	if (!publication.created && (publication.bytes === undefined || !Buffer.from(publication.bytes).equals(bytes)))
		throw new CtfWorkspaceError("integrity_error", "CTF init receipt conflicts with this initialization");
	return publication.created;
}

function readGeneratedInitReceipt(root: string): GeneratedInitReceipt {
	const result = readRootedArtifact(root, [], CTF_INIT_RECEIPT_FILENAME, 65_536);
	if (!result.ok || result.bytes === undefined)
		throw new CtfWorkspaceError("unmarked_directory", "Non-empty CTF root has no valid init receipt");
	return parseGeneratedInitReceipt(result.bytes);
}

function initialEventHead(manifest: Pick<CtfManifest, "competitionId" | "manifestRevision">): Record<string, unknown> {
	return {
		schemaVersion: "ctf-event-head-1",
		competitionId: manifest.competitionId,
		revision: manifest.manifestRevision,
		eventId: null,
		eventDigest: ZERO_EVENT_DIGEST,
	};
}

export async function initCtfWorkspace(
	root = process.cwd(),
	toolVersion = "0.0.0",
	options: CtfWorkspaceInitOptions = {},
): Promise<{
	workspace: CtfWorkspace;
	created: boolean;
	noOp: boolean;
	skill: SkillRef | undefined;
	skillArtifactPath: string | undefined;
	skillArtifactCreated: boolean;
}> {
	const resolvedRoot = path.resolve(root);
	const manifestPath = path.join(resolvedRoot, CTF_MANIFEST_FILENAME);
	return withFileLock(
		path.join(path.dirname(resolvedRoot), `.${path.basename(resolvedRoot) || "root"}.ctf-init`),
		async () => {
			if (await pathExists(manifestPath)) {
				const manifest = await readCtfManifest(resolvedRoot);
				const workspace = workspaceFor(resolvedRoot, manifest);
				await assertWorkspaceState(workspace);
				const expectedGeneratedSkill = generatedCtfSkillInstalledIdentity();
				const generatedDigest = effectiveSkillDigest(expectedGeneratedSkill);
				const publication =
					manifest.skill?.id === expectedGeneratedSkill.id &&
					manifest.skill.version === expectedGeneratedSkill.version &&
					digestsEqual(manifest.skill.digest, generatedDigest)
						? await publishGeneratedSkillArtifact(resolvedRoot)
						: undefined;
				return {
					workspace,
					created: false,
					noOp: true,
					skill: manifest.skill,
					skillArtifactPath: publication?.path,
					skillArtifactCreated: publication?.created ?? false,
				};
			}
			let entries: string[];
			try {
				entries = await fs.readdir(resolvedRoot);
			} catch (error) {
				if (isErrno(error, "ENOENT")) entries = [];
				else
					throw new CtfWorkspaceError(
						"unmarked_directory",
						`Refusing to initialize non-directory path: ${resolvedRoot}`,
					);
			}
			const recoveredReceipt =
				entries.length === 0
					? undefined
					: options.skill === undefined
						? readGeneratedInitReceipt(resolvedRoot)
						: (() => {
								throw new CtfWorkspaceError(
									"unmarked_directory",
									`Refusing to initialize non-empty unmarked directory: ${resolvedRoot}`,
								);
							})();
			await fs.mkdir(resolvedRoot, { recursive: true });
			let manifest: CtfManifest;
			if (recoveredReceipt !== undefined) {
				manifest = recoveredReceipt.manifest;
			} else {
				if (options.skill !== undefined) {
					const parsedSkill = SkillRefSchema.safeParse(options.skill);
					if (!parsedSkill.success)
						throw new CtfWorkspaceError("invalid_manifest", "CTF skill identity is invalid");
				}
				const skill = options.skill ?? generatedSkillRef();
				const base: Omit<CtfManifest, "manifestDigest"> = {
					schemaVersion: CTF_MANIFEST_SCHEMA,
					competitionId: randomUUID(),
					manifestRevision: 1,
					createdAt: new Date().toISOString(),
					toolVersion,
					skill,
					challenges: [],
				};
				manifest = { ...base, manifestDigest: computeManifestDigest(base) };
			}
			let publication: GeneratedSkillPublication | undefined;
			if (options.skill === undefined) {
				const generatedManifest = assertGeneratedInitManifest(manifest);
				publishGeneratedInitReceipt(resolvedRoot, generatedManifest);
				publication = await publishGeneratedSkillArtifact(resolvedRoot);
				if (
					generatedManifest.skill.id !== publication.skill.id ||
					generatedManifest.skill.version !== publication.skill.version ||
					!digestsEqual(generatedManifest.skill.digest, publication.skill.digest)
				) {
					throw new CtfWorkspaceError("integrity_error", "CTF init receipt skill identity is inconsistent");
				}
			}
			const workspace = workspaceFor(resolvedRoot, manifest);
			await ensureEqualOrWrite(
				eventHeadPath(workspace),
				initialEventHead(manifest),
				"integrity_error",
				"initial CTF event head",
				workspace,
			);
			// The manifest lives beside `.gjc-ctf`, so the rooted CTF state store cannot
			// address it. This is the only direct atomic write retained for initialization.
			await writeJsonAtomic(manifestPath, manifest);
			return {
				workspace,
				created: true,
				noOp: false,
				skill: manifest.skill,
				skillArtifactPath: publication?.path,
				skillArtifactCreated: publication?.created ?? false,
			};
		},
	);
}

async function pathExists(target: string): Promise<boolean> {
	try {
		await fs.access(target);
		return true;
	} catch {
		return false;
	}
}

export async function discoverCtfWorkspace(start = process.cwd()): Promise<CtfWorkspace> {
	let current = path.resolve(start);
	try {
		if ((await fs.stat(current)).isFile()) current = path.dirname(current);
	} catch (error) {
		if (!isErrno(error, "ENOENT")) throw error;
	}
	for (;;) {
		const marker = path.join(current, CTF_MANIFEST_FILENAME);
		if (await pathExists(marker)) {
			const manifest = await readCtfManifest(current);
			const workspace = workspaceFor(current, manifest);
			await assertWorkspaceState(workspace);
			return workspace;
		}
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
	}
	throw new CtfWorkspaceError("manifest_missing", `No CTF competition found above ${path.resolve(start)}`);
}

export function makeChallengeDescriptor(input: Record<string, unknown>): CtfChallengeDescriptor {
	const base = { ...input, registeredAt: new Date().toISOString() } as Omit<
		CtfChallengeDescriptor,
		"descriptorDigest"
	>;
	try {
		const descriptor = { ...base, descriptorDigest: computeDescriptorDigest(base) } as CtfChallengeDescriptor;
		return validateChallengeDescriptor(descriptor);
	} catch (error) {
		throw errorFrom(error, "invalid_manifest", "challenge descriptor is invalid");
	}
}

interface EventHead {
	schemaVersion: "ctf-event-head-1";
	competitionId: string;
	revision: number;
	eventId: string | null;
	eventDigest: string;
}

function parseEventHead(value: unknown, workspace: CtfWorkspace): EventHead {
	if (
		!isObject(value) ||
		value.schemaVersion !== "ctf-event-head-1" ||
		value.competitionId !== workspace.manifest.competitionId ||
		typeof value.revision !== "number" ||
		!Number.isInteger(value.revision) ||
		value.revision < 1 ||
		!(value.eventId === null || typeof value.eventId === "string") ||
		typeof value.eventDigest !== "string" ||
		!/^[a-f0-9]{64}$/.test(value.eventDigest)
	) {
		throw new CtfWorkspaceError("integrity_error", `CTF event head is invalid: ${eventHeadPath(workspace)}`);
	}
	return value as unknown as EventHead;
}

async function readEventHead(workspace: CtfWorkspace): Promise<EventHead> {
	const target = eventHeadPath(workspace);
	await assertStatePath(workspace, target);
	const value = await readJson(target);
	if (value === undefined)
		throw new CtfWorkspaceError("integrity_error", `CTF event head is missing: ${eventHeadPath(workspace)}`);
	return parseEventHead(value, workspace);
}

async function assertCanonicalEventHead(workspace: CtfWorkspace, expectedRevision?: number): Promise<EventHead> {
	const head = await readEventHead(workspace);
	if (expectedRevision !== undefined && head.revision !== expectedRevision) {
		throw new CtfWorkspaceError(
			"registration_repair_required",
			"CTF event head revision disagrees with the expected registration revision",
		);
	}
	if (head.revision === 1) {
		if (head.eventId !== null || !digestsEqual(head.eventDigest, ZERO_EVENT_DIGEST)) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`CTF event head is not canonical at revision 1: ${eventHeadPath(workspace)}`,
			);
		}
		return head;
	}
	if (head.eventId === null) {
		throw new CtfWorkspaceError(
			"integrity_error",
			`CTF event head is missing its canonical event identity: ${eventHeadPath(workspace)}`,
		);
	}

	const root = eventRoot(workspace);
	await assertStatePath(workspace, root);
	let names: string[];
	try {
		names = await fs.readdir(root);
	} catch (error) {
		if (isErrno(error, "ENOENT")) {
			throw new CtfWorkspaceError("integrity_error", `CTF event head is missing its event state: ${root}`);
		}
		throw error;
	}

	const eventsByRevision = new Map<number, EventV1>();
	const filenamesByEventId = new Map<string, string>();
	for (const name of names) {
		if (!name.endsWith(".json"))
			throw new CtfWorkspaceError("integrity_error", `Unexpected CTF event state: ${name}`);
		const candidatePath = path.join(root, name);
		await assertStatePath(workspace, candidatePath);
		const candidateValue = await readJson(candidatePath);
		let candidate: EventV1;
		try {
			candidate = parseEvent(candidateValue);
		} catch (error) {
			throw errorFrom(error, "integrity_error", `CTF event state is invalid: ${name}`);
		}
		if (candidate.competitionId !== workspace.manifest.competitionId) {
			throw new CtfWorkspaceError("integrity_error", `CTF event has a mismatched competition identity: ${name}`);
		}
		if (candidate.eventId !== name.slice(0, -".json".length)) {
			throw new CtfWorkspaceError("integrity_error", `CTF event filename disagrees with its identity: ${name}`);
		}
		const previousFilename = filenamesByEventId.get(candidate.eventId);
		if (previousFilename !== undefined) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`CTF event identity is duplicated: ${previousFilename}, ${name}`,
			);
		}
		filenamesByEventId.set(candidate.eventId, name);
		if (candidate.revision < 2) {
			throw new CtfWorkspaceError("integrity_error", `CTF event has an unexpected revision: ${candidate.revision}`);
		}
		if (eventsByRevision.has(candidate.revision)) {
			throw new CtfWorkspaceError("integrity_error", `CTF event revision is duplicated: ${candidate.revision}`);
		}
		eventsByRevision.set(candidate.revision, candidate);
	}

	let previousDigest = ZERO_EVENT_DIGEST;
	const highestPersistedRevision = Math.max(head.revision, ...eventsByRevision.keys());
	for (let revision = 2; revision <= highestPersistedRevision; revision += 1) {
		const event = eventsByRevision.get(revision);
		if (event === undefined) {
			throw new CtfWorkspaceError("integrity_error", `CTF event state is missing revision ${revision}`);
		}
		if (!digestsEqual(event.previousEventDigest, previousDigest)) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`CTF event predecessor digest is not canonical at revision ${revision}`,
			);
		}
		previousDigest = computeEventDigest(event);
	}

	const event = eventsByRevision.get(head.revision);
	if (
		event === undefined ||
		event.eventId !== head.eventId ||
		!digestsEqual(computeEventDigest(event), head.eventDigest)
	) {
		throw new CtfWorkspaceError(
			"integrity_error",
			`CTF event head does not match its canonical event: ${head.eventId}`,
		);
	}
	return head;
}

function journalIdentity(txn: RegistrationTxnV1): string {
	return canonical(txn, ["phase"]);
}

async function readRegistrationJournal(workspace: CtfWorkspace): Promise<RegistrationTxnV1[]> {
	const target = registrationJournalPath(workspace);
	await assertStatePath(workspace, target);
	const existing = await readBytes(target);
	if (existing === undefined || existing.length === 0) return [];
	if (existing[existing.length - 1] !== 0x0a) {
		throw new CtfWorkspaceError("integrity_error", "Registration journal is missing a terminal newline");
	}
	const text = existing.toString("utf8");
	if (!Buffer.from(text, "utf8").equals(existing)) {
		throw new CtfWorkspaceError("integrity_error", "Registration journal is not valid UTF-8");
	}
	const lines = text.split("\n");
	lines.pop();
	const transactions: RegistrationTxnV1[] = [];
	const identities = new Map<string, RegistrationTxnV1>();
	for (const [index, rawLine] of lines.entries()) {
		const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
		if (!line.trim()) {
			throw new CtfWorkspaceError("integrity_error", `Registration journal line ${index + 1} is blank`);
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(line);
		} catch {
			throw new CtfWorkspaceError("integrity_error", `Registration journal line ${index + 1} is corrupt`);
		}
		let txn: RegistrationTxnV1;
		try {
			txn = validateRegistrationTxn(parsed);
		} catch (error) {
			throw errorFrom(error, "invalid_registration", `Registration journal line ${index + 1} is invalid`);
		}
		if (txn.competitionId !== workspace.manifest.competitionId) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`Registration journal line ${index + 1} has a mismatched competition identity`,
			);
		}
		const previous = identities.get(txn.txId);
		if (previous !== undefined && journalIdentity(previous) !== journalIdentity(txn)) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`Registration journal line ${index + 1} has a mismatched transaction identity`,
			);
		}
		if (previous?.phase === "committed" && txn.phase !== "committed") {
			throw new CtfWorkspaceError(
				"integrity_error",
				`Registration journal line ${index + 1} regresses a committed transaction`,
			);
		}
		identities.set(txn.txId, txn);
		transactions.push(txn);
	}
	return transactions;
}

async function validateRegistrationJournal(workspace: CtfWorkspace): Promise<RegistrationTxnV1[]> {
	const journal = await readRegistrationJournal(workspace);
	if (journal.length === 0) return journal;
	const durable = await readTransactions(workspace);
	const byId = new Map(durable.map(txn => [txn.txId, txn]));
	for (const txn of journal) {
		const persisted = byId.get(txn.txId);
		if (persisted === undefined || journalIdentity(persisted) !== journalIdentity(txn)) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`Registration journal transaction identity is not durable: ${txn.txId}`,
			);
		}
	}
	return journal;
}

async function appendRegistrationJournal(workspace: CtfWorkspace, txn: RegistrationTxnV1): Promise<void> {
	const target = registrationJournalPath(workspace);
	await assertStatePath(workspace, target);
	let validated: RegistrationTxnV1;
	try {
		validated = validateRegistrationTxn(txn);
	} catch (error) {
		throw errorFrom(error, "invalid_registration", "Registration transaction is invalid");
	}
	if (validated.competitionId !== workspace.manifest.competitionId) {
		throw new CtfWorkspaceError("integrity_error", "Registration transaction identity disagrees with the workspace");
	}
	const existing = await validateRegistrationJournal(workspace);
	const persisted = (await readTransactions(workspace)).find(candidate => candidate.txId === validated.txId);
	if (persisted === undefined || journalIdentity(persisted) !== journalIdentity(validated)) {
		throw new CtfWorkspaceError(
			"integrity_error",
			`Registration transaction identity is not durable: ${validated.txId}`,
		);
	}
	const previous = existing.find(candidate => candidate.txId === validated.txId);
	if (previous !== undefined) {
		if (journalIdentity(previous) !== journalIdentity(validated)) {
			throw new CtfWorkspaceError(
				"integrity_error",
				`Registration journal transaction identity disagrees: ${validated.txId}`,
			);
		}
		if (
			existing.some(
				candidate =>
					candidate.txId === validated.txId &&
					candidate.phase === validated.phase &&
					canonical(candidate) === canonical(validated),
			)
		)
			return;
		if (previous.phase === "committed" && validated.phase !== "committed") {
			throw new CtfWorkspaceError(
				"integrity_error",
				`Registration journal transaction phase regresses: ${validated.txId}`,
			);
		}
	}
	const relative = stateStoreRelativePath(workspace, target);
	await workspace.stateStore.appendJsonl(relative, validated, { durability: "ctf" });
}

async function readTransactions(workspace: CtfWorkspace): Promise<RegistrationTxnV1[]> {
	await assertStatePath(workspace, transactionRoot(workspace));
	let names: string[];
	try {
		names = await fs.readdir(transactionRoot(workspace));
	} catch (error) {
		if (isErrno(error, "ENOENT")) return [];
		throw error;
	}
	const transactions: RegistrationTxnV1[] = [];
	for (const name of names.sort()) {
		if (!name.endsWith(".json"))
			throw new CtfWorkspaceError("integrity_error", `Unexpected registration state: ${name}`);
		const value = await readJson(path.join(transactionRoot(workspace), name));
		try {
			const txn = validateRegistrationTxn(value);
			if (txn.competitionId !== workspace.manifest.competitionId)
				throw new Error("registration competition ID disagrees");
			if (txn.txId !== name.slice(0, -".json".length)) {
				throw new CtfWorkspaceError(
					"integrity_error",
					`Registration transaction filename disagrees with its identity: ${name}`,
				);
			}
			transactions.push(txn);
		} catch (error) {
			throw errorFrom(error, "invalid_registration", `Registration transaction is invalid: ${name}`);
		}
	}
	return transactions;
}

async function readEventForTxn(workspace: CtfWorkspace, txn: RegistrationTxnV1): Promise<EventV1 | undefined> {
	const eventPath = path.join(eventRoot(workspace), `${txn.challengeEvent.eventId}.json`);
	await assertStatePath(workspace, eventPath);
	const value = await readJson(eventPath);
	if (value === undefined) return undefined;
	try {
		const event = parseEvent(value);
		if (
			event.eventId !== txn.challengeEvent.eventId ||
			!digestsEqual(computeEventDigest(event), txn.challengeEventDigest)
		) {
			throw new Error("event digest mismatch");
		}
		return event;
	} catch (error) {
		throw errorFrom(error, "registration_repair_required", `Challenge registration event is corrupt: ${eventPath}`);
	}
}

function checkpointValue(txn: RegistrationTxnV1): Record<string, unknown> {
	const base = {
		schemaVersion: "ctf-checkpoint-1",
		competitionId: txn.competitionId,
		challengeId: txn.challengeId,
		revision: txn.newManifestRevision,
		eventId: txn.challengeEvent.eventId,
		eventDigest: txn.challengeEventDigest,
		manifestDigest: txn.newManifestDigest,
	};
	return { ...base, checkpointDigest: canonical(base) };
}

async function ensureEventAndCheckpoint(workspace: CtfWorkspace, txn: RegistrationTxnV1): Promise<void> {
	const eventPath = path.join(eventRoot(workspace), `${txn.challengeEvent.eventId}.json`);
	await assertStatePath(workspace, eventPath);
	const event = await readEventForTxn(workspace, txn);
	if (event === undefined)
		await ensureEqualOrWrite(
			eventPath,
			txn.challengeEvent,
			"registration_repair_required",
			"registration event",
			workspace,
		);
	const checkpointPath = path.join(
		checkpointRoot(workspace),
		`${txn.newManifestRevision}-${txn.challengeEvent.eventId}.json`,
	);
	await assertStatePath(workspace, checkpointPath);
	await ensureEqualOrWrite(
		checkpointPath,
		checkpointValue(txn),
		"registration_repair_required",
		"registration checkpoint",
		workspace,
	);
	await appendRegistrationJournal(workspace, txn);
}

function descriptorAt(manifest: CtfManifest, id: string): CtfChallengeDescriptor | undefined {
	return manifest.challenges.find(challenge => challenge.id === id);
}
function registrationAuthority(options: CtfRegistrationOptions): CtfTrustedRegistrationAuthority {
	return options.trustedAuthority ?? options.authority ?? options.registrationAuthority ?? options;
}

function registrationAuthorityRequired(descriptor: CtfChallengeDescriptor, options: CtfRegistrationOptions): boolean {
	const mode = options.mode ?? (descriptor.trustLevel === "fixture" ? "fixture" : "scored");
	return mode === "competition" || mode === "scored" || mode === "benchmark";
}

function bindRegistrationAuthority(
	descriptor: CtfChallengeDescriptor,
	options: CtfRegistrationOptions,
): CtfChallengeDescriptor {
	const authority = registrationAuthority(options);
	const registryValue =
		authority.trustedRegistry ?? authority.trustedOracleRegistry ?? authority.oracleRegistry ?? authority.registry;
	const registryDigest = authority.registryDigest ?? authority.oracleRegistryDigest;
	const entryDigest = authority.oracleEntryDigest ?? authority.entryDigest ?? authority.oracleDigest;
	const backendDigest = authority.backendDigest;
	const imageDigest = authority.imageDigest;
	const suppliedAuthority =
		registryValue !== undefined ||
		registryDigest !== undefined ||
		entryDigest !== undefined ||
		backendDigest !== undefined ||
		imageDigest !== undefined;
	if (!registrationAuthorityRequired(descriptor, options) && !suppliedAuthority) return descriptor;
	if (
		registryValue === undefined ||
		registryDigest === undefined ||
		entryDigest === undefined ||
		backendDigest === undefined ||
		imageDigest === undefined
	) {
		throw new CtfWorkspaceError("oracle_integrity_error", "trusted oracle registration authority is missing");
	}

	let trusted: TrustedOracleRegistry;
	try {
		trusted = validateTrustedOracleRegistry(registryValue);
	} catch (error) {
		throw new CtfWorkspaceError(
			"oracle_integrity_error",
			"trusted oracle registration authority is invalid",
			false,
			error instanceof Error ? { cause: error.message } : undefined,
		);
	}
	if (!digestsEqual(trusted.registry.registryDigest, registryDigest)) {
		throw new CtfWorkspaceError("oracle_integrity_error", "trusted oracle registry digest does not match");
	}
	const selectedOracleId = authority.oracleId ?? authority.selectedOracleId;
	if (selectedOracleId !== undefined && selectedOracleId !== descriptor.oracleId) {
		throw new CtfWorkspaceError(
			"oracle_integrity_error",
			"trusted oracle identity does not match challenge descriptor",
		);
	}
	const entries = trusted.registry.entries.filter(entry => entry.oracleId === descriptor.oracleId);
	if (entries.length !== 1) {
		throw new CtfWorkspaceError("oracle_integrity_error", `trusted oracle is not registered: ${descriptor.oracleId}`);
	}
	const entry = entries[0];
	if (!entry?.allowedChallengeIds.includes(descriptor.id)) {
		throw new CtfWorkspaceError(
			"oracle_integrity_error",
			`trusted oracle is not authorized for challenge: ${descriptor.id}`,
		);
	}
	if (!digestsEqual(oracleEntryDigest(entry), entryDigest)) {
		throw new CtfWorkspaceError("oracle_integrity_error", "trusted oracle entry digest does not match");
	}
	const expectedBackendDigest = canonicalDigest(descriptor.backend);
	if (
		!digestsEqual(expectedBackendDigest, backendDigest) ||
		entry.backendDigest === undefined ||
		!digestsEqual(entry.backendDigest, backendDigest)
	) {
		throw new CtfWorkspaceError("oracle_integrity_error", "trusted oracle backend authorization does not match");
	}
	if (
		descriptor.backend.imageDigest === undefined ||
		!digestsEqual(descriptor.backend.imageDigest, imageDigest) ||
		!digestsEqual(entry.imageDigest, imageDigest)
	) {
		throw new CtfWorkspaceError("oracle_integrity_error", "trusted oracle image authorization does not match");
	}
	if (
		descriptor.oracleRegistryDigest !== undefined &&
		!digestsEqual(descriptor.oracleRegistryDigest, registryDigest)
	) {
		throw new CtfWorkspaceError("oracle_integrity_error", "descriptor oracle registry digest does not match");
	}
	if (descriptor.oracleEntryDigest !== undefined && !digestsEqual(descriptor.oracleEntryDigest, entryDigest)) {
		throw new CtfWorkspaceError("oracle_integrity_error", "descriptor oracle entry digest does not match");
	}
	if (descriptor.oracleDigest !== undefined && !digestsEqual(descriptor.oracleDigest, entryDigest)) {
		throw new CtfWorkspaceError("oracle_integrity_error", "descriptor oracle digest does not match");
	}
	if (descriptor.backendDigest !== undefined && !digestsEqual(descriptor.backendDigest, backendDigest)) {
		throw new CtfWorkspaceError("oracle_integrity_error", "descriptor backend digest does not match");
	}

	const { descriptorDigest: _descriptorDigest, ...descriptorWithoutDigest } = descriptor;
	const boundDescriptor = {
		...descriptorWithoutDigest,
		oracleRegistryDigest: registryDigest,
		oracleEntryDigest: entryDigest,
		oracleDigest: entryDigest,
		backendDigest,
	};
	return { ...boundDescriptor, descriptorDigest: computeDescriptorDigest(boundDescriptor) };
}

function manifestWithDescriptor(
	manifest: CtfManifest,
	descriptor: CtfChallengeDescriptor,
	revision: number,
): CtfManifest {
	const base: Omit<CtfManifest, "manifestDigest"> = {
		...manifest,
		manifestRevision: revision,
		challenges: [...manifest.challenges, descriptor],
	};
	return { ...base, manifestDigest: computeManifestDigest(base) };
}

async function updateManifestForTxn(workspace: CtfWorkspace, txn: RegistrationTxnV1): Promise<CtfManifest> {
	const current = await readCtfManifest(workspace.root);
	const found = descriptorAt(current, txn.challengeId);
	if (
		current.manifestRevision === txn.newManifestRevision &&
		digestsEqual(current.manifestDigest, txn.newManifestDigest)
	) {
		if (!found || !digestsEqual(found.descriptorDigest, txn.descriptorDigest)) {
			throw new CtfWorkspaceError(
				"registration_repair_required",
				"new manifest has an unexpected challenge descriptor",
			);
		}
		return current;
	}
	if (
		current.manifestRevision !== txn.baseManifestRevision ||
		!digestsEqual(current.manifestDigest, txn.oldManifestDigest)
	) {
		throw new CtfWorkspaceError("revision_conflict", "manifest changed during registration", true);
	}
	if (found) {
		if (digestsEqual(found.descriptorDigest, txn.descriptorDigest))
			throw new CtfWorkspaceError("revision_conflict", "manifest descriptor exists at an unexpected revision");
		throw new CtfWorkspaceError(
			"idempotency_conflict",
			`Challenge ID already has a different descriptor: ${txn.challengeId}`,
		);
	}
	if (!current.skill)
		throw new CtfWorkspaceError("invalid_manifest", "CTF manifest has no skill identity; registration is refused");
	const next = manifestWithDescriptor(current, txn.descriptor, txn.newManifestRevision);
	if (!digestsEqual(next.manifestDigest, txn.newManifestDigest))
		throw new CtfWorkspaceError("registration_repair_required", "registration transaction manifest digest disagrees");
	const manifestStore = manifestStoreFor(workspace);
	await manifestStore.writeJsonAtomic(manifestRelativePath(workspace), next, { durability: "ctf" });
	return next;
}

async function advanceEventHead(workspace: CtfWorkspace, txn: RegistrationTxnV1, manifest: CtfManifest): Promise<void> {
	if (
		manifest.manifestRevision !== txn.newManifestRevision ||
		!digestsEqual(manifest.manifestDigest, txn.newManifestDigest)
	) {
		throw new CtfWorkspaceError("registration_repair_required", "manifest and registration transaction disagree");
	}
	const current = await assertCanonicalEventHead(workspace);
	if (
		current.revision === txn.newManifestRevision &&
		current.eventId === txn.challengeEvent.eventId &&
		digestsEqual(current.eventDigest, txn.challengeEventDigest)
	)
		return;
	if (
		current.revision !== txn.baseManifestRevision ||
		!digestsEqual(current.eventDigest, txn.challengeEvent.previousEventDigest)
	) {
		throw new CtfWorkspaceError(
			"registration_repair_required",
			"event head cannot be reconciled without overwriting existing bytes",
		);
	}
	await workspace.stateStore.writeJsonAtomic(
		stateStoreRelativePath(workspace, eventHeadPath(workspace)),
		{
			schemaVersion: "ctf-event-head-1",
			competitionId: txn.competitionId,
			revision: txn.newManifestRevision,
			eventId: txn.challengeEvent.eventId,
			eventDigest: txn.challengeEventDigest,
		},
		{ durability: "ctf" },
	);
}

async function commitTxn(
	workspace: CtfWorkspace,
	txn: RegistrationTxnV1,
	phase: "prepared" | "committed",
): Promise<RegistrationTxnV1> {
	const next = { ...txn, phase };
	const txPath = path.join(transactionRoot(workspace), `${txn.txId}.json`);
	await assertStatePath(workspace, txPath);
	const current = await readJson(txPath);
	if (current === undefined)
		throw new CtfWorkspaceError("registration_repair_required", `Registration transaction disappeared: ${txPath}`);
	let parsed: RegistrationTxnV1;
	try {
		parsed = validateRegistrationTxn(current);
	} catch (error) {
		throw errorFrom(error, "registration_repair_required", `Registration transaction is corrupt: ${txPath}`);
	}
	if (parsed.txId !== txn.txId || parsed.phase !== txn.phase || canonical(parsed) !== canonical(txn)) {
		throw new CtfWorkspaceError(
			"registration_repair_required",
			`Registration transaction changed unexpectedly: ${txPath}`,
		);
	}
	await workspace.stateStore.writeJsonAtomic(stateStoreRelativePath(workspace, txPath), next, { durability: "ctf" });
	await appendRegistrationJournal(workspace, next);
	return next;
}

async function recoverTxn(workspace: CtfWorkspace, txn: RegistrationTxnV1): Promise<CtfManifest> {
	await validateRegistrationJournal(workspace);
	const current = await readCtfManifest(workspace.root);
	if (txn.phase === "aborted")
		throw new CtfWorkspaceError(
			"registration_repair_required",
			`Aborted registration transaction requires repair: ${txn.txId}`,
		);
	if (txn.phase === "committed") {
		const descriptor = descriptorAt(current, txn.challengeId);
		if (
			!descriptor ||
			!digestsEqual(descriptor.descriptorDigest, txn.descriptorDigest) ||
			current.manifestRevision < txn.newManifestRevision ||
			(current.manifestRevision === txn.newManifestRevision &&
				!digestsEqual(current.manifestDigest, txn.newManifestDigest))
		) {
			throw new CtfWorkspaceError(
				"registration_repair_required",
				`Committed registration is not represented by the manifest: ${txn.txId}`,
			);
		}
		await assertCanonicalEventHead(workspace);
		await ensureEventAndCheckpoint(workspace, txn);
		return current;
	}
	if (current.manifestRevision > txn.newManifestRevision) {
		throw new CtfWorkspaceError(
			"registration_repair_required",
			`Prepared registration is behind the manifest: ${txn.txId}`,
		);
	}
	if (
		current.manifestRevision === txn.newManifestRevision &&
		digestsEqual(current.manifestDigest, txn.newManifestDigest)
	) {
		const descriptor = descriptorAt(current, txn.challengeId);
		if (!descriptor || !digestsEqual(descriptor.descriptorDigest, txn.descriptorDigest))
			throw new CtfWorkspaceError(
				"registration_repair_required",
				`Prepared registration descriptor is missing: ${txn.txId}`,
			);
		const head = await assertCanonicalEventHead(workspace);
		const baseHead =
			head.revision === txn.baseManifestRevision &&
			digestsEqual(head.eventDigest, txn.challengeEvent.previousEventDigest);
		const targetHead =
			head.revision === txn.newManifestRevision &&
			head.eventId === txn.challengeEvent.eventId &&
			digestsEqual(head.eventDigest, txn.challengeEventDigest);
		if (!baseHead && !targetHead) {
			throw new CtfWorkspaceError(
				"registration_repair_required",
				`Prepared registration event head conflicts: ${txn.txId}`,
			);
		}
		await ensureEventAndCheckpoint(workspace, txn);
		await advanceEventHead(workspace, txn, current);
		await commitTxn(workspace, txn, "committed");
		return current;
	}
	if (
		current.manifestRevision !== txn.baseManifestRevision ||
		!digestsEqual(current.manifestDigest, txn.oldManifestDigest)
	) {
		throw new CtfWorkspaceError("revision_conflict", `Prepared registration has a stale manifest: ${txn.txId}`, true);
	}
	const head = await assertCanonicalEventHead(workspace, txn.baseManifestRevision);
	if (!digestsEqual(head.eventDigest, txn.challengeEvent.previousEventDigest)) {
		throw new CtfWorkspaceError(
			"registration_repair_required",
			`Prepared registration event head conflicts: ${txn.txId}`,
		);
	}
	await ensureEventAndCheckpoint(workspace, txn);
	const manifest = await updateManifestForTxn(workspace, txn);
	await advanceEventHead(workspace, txn, manifest);
	await commitTxn(workspace, txn, "committed");
	return manifest;
}

function buildRegistrationTxn(
	workspace: CtfWorkspace,
	descriptor: CtfChallengeDescriptor,
	head: EventHead,
): RegistrationTxnV1 {
	if (!workspace.manifest.skill)
		throw new CtfWorkspaceError("invalid_manifest", "CTF manifest has no skill identity; registration is refused");
	const createdAt = new Date().toISOString();
	const baseManifest = workspace.manifest;
	const newManifest = manifestWithDescriptor(baseManifest, descriptor, baseManifest.manifestRevision + 1);
	const eventBase: Omit<EventV1, "payloadDigest"> = {
		schemaVersion: CTF_SCHEMA_VERSIONS.event,
		eventId: randomUUID(),
		eventType: "challenge_registered",
		competitionId: baseManifest.competitionId,
		challengeId: descriptor.id,
		previousRevision: baseManifest.manifestRevision,
		revision: newManifest.manifestRevision,
		idempotencyKey: descriptor.id,
		previousEventDigest: head.eventDigest,
		actor: process.env.GJC_CTF_ACTOR?.trim() || "gjc-ctf",
		occurredAt: createdAt,
		payload: {
			challengeId: descriptor.id,
			descriptorDigest: descriptor.descriptorDigest,
			idempotencyKey: descriptor.id,
		},
		evidenceRefs: [],
	};
	const challengeEvent: EventV1 = { ...eventBase, payloadDigest: eventPayloadDigest(eventBase) };
	const txn: RegistrationTxnV1 = {
		schemaVersion: CTF_SCHEMA_VERSIONS.registration,
		txId: randomUUID(),
		idempotencyKey: descriptor.id,
		competitionId: baseManifest.competitionId,
		baseManifestRevision: baseManifest.manifestRevision,
		oldManifestDigest: baseManifest.manifestDigest,
		challengeId: descriptor.id,
		descriptorDigest: descriptor.descriptorDigest,
		challengeEventDigest: computeEventDigest(challengeEvent),
		newManifestRevision: newManifest.manifestRevision,
		newManifestDigest: newManifest.manifestDigest,
		phase: "prepared",
		createdAt,
		actor: eventBase.actor,
		descriptor,
		challengeEvent,
	};
	return validateRegistrationTxn(txn);
}

export async function registerChallenge(
	workspace: CtfWorkspace,
	descriptor: CtfChallengeDescriptor,
	options: CtfRegistrationOptions = {},
): Promise<CtfWorkspace> {
	let validated: CtfChallengeDescriptor;
	try {
		validated = validateChallengeDescriptor(descriptor);
		await assertCompetitionArtifactPaths(workspace, validated, "invalid_manifest");
		validated = bindRegistrationAuthority(validated, options);
	} catch (error) {
		throw errorFrom(error, "invalid_manifest", "challenge descriptor is invalid");
	}
	const lockTarget = path.join(workspace.stateRoot, COMPETITION_DIRNAME, "registration.lock");
	await assertStateRoot(workspace);
	return withFileLock(lockTarget, async () => {
		await assertWorkspaceState(workspace);
		let current = await readCtfManifest(workspace.root);
		if (!current.skill)
			throw new CtfWorkspaceError("invalid_manifest", "CTF manifest has no skill identity; registration is refused");
		const transactions = await readTransactions(workspace);
		for (const txn of transactions) {
			if (
				txn.idempotencyKey === validated.id &&
				(txn.challengeId !== validated.id || !digestsEqual(txn.descriptorDigest, validated.descriptorDigest))
			) {
				throw new CtfWorkspaceError(
					"idempotency_conflict",
					`Challenge ID has a conflicting registration transaction: ${validated.id}`,
				);
			}
		}
		for (const txn of transactions.sort((left, right) => left.createdAt.localeCompare(right.createdAt))) {
			current = await recoverTxn(workspaceFor(workspace.root, current), txn);
		}
		const fresh = await readCtfManifest(workspace.root);
		const existing = descriptorAt(fresh, validated.id);
		if (existing) {
			if (digestsEqual(existing.descriptorDigest, validated.descriptorDigest))
				return workspaceFor(workspace.root, fresh);
			throw new CtfWorkspaceError(
				"idempotency_conflict",
				`Challenge ID already has a different descriptor: ${validated.id}`,
			);
		}
		const head = await assertCanonicalEventHead(workspaceFor(workspace.root, fresh), fresh.manifestRevision);
		const transactionWorkspace = workspaceFor(workspace.root, fresh);
		const txn = buildRegistrationTxn(transactionWorkspace, validated, head);
		const txPath = path.join(transactionRoot(transactionWorkspace), `${txn.txId}.json`);
		await ensureEqualOrWrite(
			txPath,
			txn,
			"registration_repair_required",
			"registration transaction",
			transactionWorkspace,
		);
		await appendRegistrationJournal(transactionWorkspace, txn);
		const committedManifest = await recoverTxn(transactionWorkspace, txn);
		return workspaceFor(workspace.root, committedManifest);
	});
}
