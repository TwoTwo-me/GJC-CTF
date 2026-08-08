import { createHash, randomUUID } from "node:crypto";
import type { Stats } from "node:fs";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { CtfIdSchema } from "../contracts/common";
import { canonicalDigest } from "../contracts/digest";
import type { ChallengeDescriptor } from "../contracts/manifest";
import type {
	CtfArtifactEvidence,
	CtfSolverBackend,
	CtfSolverOutcome,
	CtfSolverRequest,
	CtfTerminationRequest,
} from "../runtime/scheduler";
import {
	fixtureSolverRouteFor,
	REVIEWED_SOLVER_ANALYZER_IDS,
	solverRouteFor,
	validateSolverRoute,
	type SolverAttemptLimits,
	type SolverRoute,
} from "./router";

const FORBIDDEN_BASENAMES = new Set(["challenge.yaml", "solve.py"]);
const MAX_FILE_BYTES = 256 * 1024;
const MAX_VISIBLE_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024;
const MAX_ARTIFACTS = 8;

export type LocalSolverVisibleFile = Readonly<{ path: string; content: Uint8Array }>;
export type LocalSolverArtifact = Readonly<{ path: string; content: Uint8Array }>;
export type LocalSolverRunCapability = Readonly<{
	writeScratch(path: string, content: Uint8Array): Promise<void>;
	readScratch(path: string): Promise<Uint8Array | undefined>;
	publish(path: string, content: Uint8Array): Promise<void>;
}>;
export type LocalSolverSessionInput = Readonly<{
	challengeId: string;
	runId: string;
	routeDigest: string;
	analyzerIds: readonly string[];
	toolProfile: readonly string[];
	toolProfileDigest: string;
	adapterKind: SolverRoute["adapterKind"];
	modelPattern: string;
	thinkingLevel: SolverRoute["thinkingLevel"];
	attemptLimits: SolverAttemptLimits;
	visibleFiles: readonly LocalSolverVisibleFile[];
	runCapability: LocalSolverRunCapability;
	network: "off";
	credentials: "none";
	allowedTools: readonly string[];
	signal: AbortSignal;
}>;
export type LocalSolverSessionResult = Readonly<{
	candidate?: string;
	artifacts?: readonly LocalSolverArtifact[];
}>;
/** The production seam is an AgentSession/SDK adapter, never a child-process exit code. */
export type LocalSolverSession = Readonly<{
	solve(input: LocalSolverSessionInput): Promise<LocalSolverSessionResult>;
	/** Resolves once session-owned work for the run cannot write again. */
	terminate?(request: CtfTerminationRequest): Promise<void>;
}>;
export type LocalSolverAnalyzerResult =
	| Readonly<{ status: "not-applicable" }>
	| Readonly<{ status: "refused"; reason: string }>
	| Readonly<{ status: "candidate"; result: LocalSolverSessionResult }>
	| Readonly<{ status: "cancelled"; reason?: string }>;
export type LocalSolverAnalyzer = Readonly<{
	id: string;
	analyze(input: LocalSolverSessionInput): Promise<LocalSolverAnalyzerResult>;
}>;
export type LocalCtfSolverBackendOptions = Readonly<{
	root: string;
	challenges: ReadonlyMap<string, ChallengeDescriptor>;
	artifactRoot: string;
	allowedTools?: readonly string[];
	analyzers?: readonly LocalSolverAnalyzer[];
	createSession: (request: CtfSolverRequest) => Promise<LocalSolverSession>;
}>;
type MaterializedWithVisibleDigests = Readonly<{
	root: string;
	provenanceDigest: string;
	visibleFileDigests?: Readonly<Record<string, string>>;
	solverRoute?: unknown;
}>;

function safeRelative(value: string): boolean {
	if (!value || value.includes("\0") || path.isAbsolute(value) || value.includes("\\")) return false;
	const normalized = path.posix.normalize(value);
	return normalized !== "." && normalized !== ".." && !normalized.startsWith("../") && normalized === value;
}

function contained(root: string, target: string): boolean {
	const relative = path.relative(root, target);
	return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function forbidden(value: string): boolean {
	return FORBIDDEN_BASENAMES.has(path.posix.basename(value).toLowerCase()) || /(?:^|[./])flag(?:$|[./])/iu.test(value);
}

function digest(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

function sameFile(left: Stats, right: Stats): boolean {
	return (
		left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeMs === right.mtimeMs
	);
}

async function assertNoSymlinkParents(root: string, relative: string): Promise<void> {
	let current = root;
	const segments = relative.split("/").slice(0, -1);
	for (const segment of segments) {
		current = path.join(current, segment);
		const stat = await fs.lstat(current);
		if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("path has an unverified parent");
	}
}

async function verifiedDirectory(directory: string): Promise<string> {
	const absolute = path.resolve(directory);
	const parsed = path.parse(absolute);
	let current = parsed.root;
	for (const segment of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
		current = path.join(current, segment);
		const stat = await fs.lstat(current);
		if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("directory has a symlink ancestor");
	}
	const real = await fs.realpath(absolute);
	if (real !== absolute) throw new Error("directory identity changed while being verified");
	return real;
}

async function readVisible(
	root: string,
	descriptor: ChallengeDescriptor,
	visibleFileDigests: Readonly<Record<string, string>>,
): Promise<LocalSolverVisibleFile[]> {
	const allowlisted = new Set(descriptor.visibleArtifactAllowlist);
	if (
		Object.keys(visibleFileDigests).length !== allowlisted.size ||
		[...allowlisted].some(file => !/^[a-f0-9]{64}$/u.test(visibleFileDigests[file] ?? ""))
	)
		throw new Error("materialized visible-file digest mapping is incomplete");
	const result: LocalSolverVisibleFile[] = [];
	let total = 0;
	for (const relative of descriptor.visibleArtifactAllowlist) {
		if (!safeRelative(relative) || forbidden(relative))
			throw new Error("visible file is outside the approved clean room");
		const target = path.resolve(root, relative);
		if (!contained(root, target)) throw new Error("visible file is outside the approved clean room");
		await assertNoSymlinkParents(root, relative);
		const before = await fs.lstat(target).catch(() => undefined);
		if (before === undefined || !before.isFile() || before.isSymbolicLink())
			throw new Error(`visible file is not materialized: ${relative}`);
		if (before.size > MAX_FILE_BYTES) throw new Error("visible file exceeds solver input budget");
		total += before.size;
		if (total > MAX_VISIBLE_BYTES) throw new Error("visible files exceed solver input budget");
		const handle = await fs.open(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		try {
			const opened = await handle.stat();
			if (!opened.isFile() || !sameFile(before, opened))
				throw new Error("visible file was replaced while being opened");
			const content = new Uint8Array(opened.size);
			let offset = 0;
			while (offset < content.byteLength) {
				const read = await handle.read(content, offset, content.byteLength - offset, offset);
				if (read.bytesRead === 0) throw new Error("visible file changed while being read");
				offset += read.bytesRead;
			}
			const after = await handle.stat();
			const named = await fs.lstat(target);
			if (!sameFile(opened, after) || !sameFile(opened, named) || named.isSymbolicLink())
				throw new Error("visible file changed while being read");
			if (digest(content) !== visibleFileDigests[relative])
				throw new Error("visible file digest does not match materialized authority");
			result.push({ path: relative, content });
		} finally {
			await handle.close();
		}
	}
	return result;
}

async function writeArtifacts(
	root: string,
	runId: string,
	artifacts: readonly LocalSolverArtifact[] | undefined,
): Promise<readonly CtfArtifactEvidence[]> {
	if (artifacts === undefined) return [];
	if (!safeRelative(runId) || artifacts.length > MAX_ARTIFACTS) throw new Error("solver artifact count exceeds bound");
	const verifiedRoot = await verifiedDirectory(root);
	const runRoot = path.resolve(verifiedRoot, runId);
	if (!contained(verifiedRoot, runRoot)) throw new Error("solver artifact root escapes workspace");
	const names = new Set<string>();
	let total = 0;
	for (const artifact of artifacts) {
		if (!safeRelative(artifact.path) || forbidden(artifact.path) || names.has(artifact.path))
			throw new Error("solver artifact path is not permitted");
		names.add(artifact.path);
		if (artifact.content.byteLength > MAX_ARTIFACT_BYTES) throw new Error("solver artifact exceeds size bound");
		total += artifact.content.byteLength;
		if (total > MAX_ARTIFACT_BYTES) throw new Error("solver artifact budget exceeded");
		if (!contained(runRoot, path.resolve(runRoot, artifact.path)))
			throw new Error("solver artifact path escapes run root");
	}
	if (
		await fs
			.lstat(runRoot)
			.then(() => true)
			.catch(() => false)
	)
		throw new Error("solver artifact run already exists");
	const stage = path.resolve(verifiedRoot, `.${runId}.${randomUUID()}.staging`);
	if (!contained(verifiedRoot, stage)) throw new Error("solver artifact staging escapes workspace");
	await fs.mkdir(stage, { mode: 0o700 });
	try {
		for (const artifact of artifacts) {
			const target = path.resolve(stage, artifact.path);
			await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
			await assertNoSymlinkParents(stage, artifact.path);
			await fs.writeFile(target, artifact.content, { flag: "wx", mode: 0o600 });
		}
		if ((await verifiedDirectory(verifiedRoot)) !== verifiedRoot)
			throw new Error("artifact root identity changed before publication");
		await fs.rename(stage, runRoot);
		return artifacts.map(artifact => ({
			path: path.posix.join(runId, artifact.path),
			digest: digest(artifact.content),
			size: artifact.content.byteLength,
		}));
	} catch (error) {
		await fs.rm(stage, { recursive: true, force: true });
		throw error;
	}
}

function validAuthority(request: CtfSolverRequest): boolean {
	const authority = request.authority;
	return (
		CtfIdSchema.safeParse(request.runId).success &&
		CtfIdSchema.safeParse(request.challengeId).success &&
		CtfIdSchema.safeParse(authority.competitionId).success &&
		CtfIdSchema.safeParse(authority.intentId).success &&
		Number.isSafeInteger(authority.fencingToken) &&
		authority.fencingToken > 0 &&
		/^[a-f0-9]{64}$/u.test(authority.skillDigest) &&
		/^[a-f0-9]{64}$/u.test(authority.sandboxPolicyDigest)
	);
}
function createRunCapability(): {
	capability: LocalSolverRunCapability;
	artifacts: readonly LocalSolverArtifact[];
} {
	const scratch = new Map<string, Uint8Array>();
	const published: LocalSolverArtifact[] = [];
	const names = new Set<string>();
	let total = 0;
	let scratchBytes = 0;
	const assertPath = (artifactPath: string, content: Uint8Array): void => {
		if (!safeRelative(artifactPath) || forbidden(artifactPath) || content.byteLength > MAX_ARTIFACT_BYTES)
			throw new Error("run capability artifact is not permitted");
	};
	return {
		capability: Object.freeze({
			async writeScratch(artifactPath, content): Promise<void> {
				assertPath(artifactPath, content);
				const previous = scratch.get(artifactPath);
				const nextSize = scratchBytes - (previous?.byteLength ?? 0) + content.byteLength;
				if (nextSize > MAX_ARTIFACT_BYTES) throw new Error("run capability scratch budget exceeded");
				scratchBytes = nextSize;
				scratch.set(artifactPath, new Uint8Array(content));
			},
			async readScratch(artifactPath): Promise<Uint8Array | undefined> {
				if (!safeRelative(artifactPath)) throw new Error("run capability path is not permitted");
				const content = scratch.get(artifactPath);
				return content === undefined ? undefined : new Uint8Array(content);
			},
			async publish(artifactPath, content): Promise<void> {
				assertPath(artifactPath, content);
				if (names.has(artifactPath)) throw new Error("run capability artifact path is duplicated");
				total += content.byteLength;
				if (published.length >= MAX_ARTIFACTS || total > MAX_ARTIFACT_BYTES)
					throw new Error("run capability artifact budget exceeded");
				names.add(artifactPath);
				published.push(Object.freeze({ path: artifactPath, content: new Uint8Array(content) }));
			},
		}),
		get artifacts(): readonly LocalSolverArtifact[] {
			return Object.freeze([...published]);
		},
	};
}

export function createLocalCtfSolverBackend(options: LocalCtfSolverBackendOptions): CtfSolverBackend {
	const root = path.resolve(options.root);
	const artifactRoot = path.resolve(options.artifactRoot);
	if (!contained(root, artifactRoot)) throw new Error("artifact root must be contained by the workspace root");
	const allowedTools = Object.freeze([...(options.allowedTools ?? [])]);
	const analyzers = Object.freeze([...(options.analyzers ?? [])]);
	const analyzerById = new Map<string, LocalSolverAnalyzer>();
	const reviewedAnalyzerIds = REVIEWED_SOLVER_ANALYZER_IDS;
	for (const analyzer of analyzers) {
		if (!reviewedAnalyzerIds.has(analyzer.id))
			throw new Error(`analyzer ${analyzer.id} is not declared by a reviewed solver route`);
		if (analyzerById.has(analyzer.id)) throw new Error(`analyzer ${analyzer.id} is registered more than once`);
		analyzerById.set(analyzer.id, analyzer);
	}
	type ActiveRun = {
		challengeId: string;
		competitionId: string;
		artifactPath: string;
		controller: AbortController;
		completion: Promise<void>;
		sessionReady: PromiseWithResolvers<LocalSolverSession | undefined>;
		session?: LocalSolverSession;
		termination?: Promise<void>;
	};
	const runs = new Map<string, ActiveRun>();
	return {
		id: "local-gjc-agent",
		termination: "owned",
		async terminate(request): Promise<void> {
			const run = runs.get(request.runId);
			if (run === undefined) return;
			if (request.challengeId !== run.challengeId)
				throw new Error("termination identity does not match the active run");
			if (run.termination === undefined) {
				run.controller.abort(request.reason);
				run.termination = (async () => {
					const session = await Promise.race([run.sessionReady.promise, run.completion.then(() => undefined)]);
					const sessionTermination = await Promise.allSettled([
						Promise.resolve().then(() => session?.terminate?.(request)),
					]);
					const cleanup = (async () => {
						await run.completion;
						const residual = await fs.lstat(run.artifactPath).catch(error => {
							if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
							throw error;
						});
						if (residual !== undefined) throw new Error("terminated run retained artifact output");
					})().finally(() => {
						if (runs.get(request.runId) === run) runs.delete(request.runId);
					});
					const rejected = sessionTermination.find(
						(acknowledgment): acknowledgment is PromiseRejectedResult => acknowledgment.status === "rejected",
					);
					if (rejected !== undefined) {
						void cleanup.catch(() => undefined);
						throw rejected.reason;
					}
					await cleanup;
				})();
			}
			await run.termination;
		},
		async solve(request): Promise<CtfSolverOutcome> {
			if (request.backendId !== "local-gjc-agent") return { status: "blocked", reason: "backend identity mismatch" };
			if (!validAuthority(request)) return { status: "blocked", reason: "run authority is incomplete or invalid" };
			const artifactPath = path.resolve(artifactRoot, request.runId);
			if (artifactPath === artifactRoot || !contained(artifactRoot, artifactPath))
				return { status: "blocked", reason: "run artifact identity escapes workspace" };
			if (runs.has(request.runId)) return { status: "blocked", reason: "run identity is already active" };
			const controller = new AbortController();
			const abort = () => controller.abort(request.signal.reason);
			if (request.signal.aborted) abort();
			else request.signal.addEventListener("abort", abort, { once: true });
			const completion = Promise.withResolvers<void>();
			const sessionReady = Promise.withResolvers<LocalSolverSession | undefined>();
			const run: ActiveRun = {
				challengeId: request.challengeId,
				competitionId: request.authority.competitionId,
				artifactPath,
				controller,
				completion: completion.promise,
				sessionReady,
			};
			runs.set(request.runId, run);
			try {
				const descriptor = options.challenges.get(request.challengeId);
				if (descriptor === undefined || descriptor.networkMode !== "off")
					return { status: "blocked", reason: "challenge is not locally admissible" };
				let route: SolverRoute;
				try {
					route = solverRouteFor(request.challengeId);
				} catch {
					if (descriptor.trustLevel !== "fixture")
						return { status: "blocked", reason: "challenge solver route is not reviewed" };
					route = fixtureSolverRouteFor(request.challengeId);
				}
				const materialized = request.materialized as MaterializedWithVisibleDigests | undefined;
				if (
					materialized === undefined ||
					!/^[a-f0-9]{64}$/u.test(materialized.provenanceDigest) ||
					materialized.visibleFileDigests === undefined
				)
					return {
						status: "blocked",
						reason: "materialized challenge provenance or visible-file authority is unavailable",
					};
				if (materialized.solverRoute !== undefined) {
					try {
						if (validateSolverRoute(materialized.solverRoute).routeDigest !== route.routeDigest)
							return { status: "blocked", reason: "materialized solver route does not match the reviewed route" };
					} catch {
						return { status: "blocked", reason: "materialized solver route is invalid" };
					}
				}
				if (controller.signal.aborted) return { status: "cancelled", reason: "run cancelled or budget exhausted" };
				try {
					const verifiedWorkspaceRoot = await verifiedDirectory(root);
					const visibleRoot = await verifiedDirectory(materialized.root);
					const verifiedArtifactRoot = await verifiedDirectory(artifactRoot);
					if (
						!contained(verifiedWorkspaceRoot, visibleRoot) ||
						!contained(verifiedWorkspaceRoot, verifiedArtifactRoot) ||
						path.dirname(artifactPath) !== verifiedArtifactRoot
					)
						return { status: "blocked", reason: "materialized challenge or artifact root escapes workspace" };
					const existingArtifact = await fs.lstat(artifactPath).catch(error => {
						if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
						throw error;
					});
					if (existingArtifact !== undefined)
						return { status: "blocked", reason: "run artifact identity already exists" };
					const visibleFiles = await readVisible(visibleRoot, descriptor, materialized.visibleFileDigests);
					const toolProfile = Object.freeze([...allowedTools]);
					const runCapability = createRunCapability();
					const input: LocalSolverSessionInput = {
						challengeId: request.challengeId,
						runId: request.runId,
						routeDigest: route.routeDigest,
						analyzerIds: route.analyzerIds,
						toolProfile,
						toolProfileDigest: canonicalDigest(toolProfile),
						adapterKind: route.adapterKind,
						modelPattern: route.modelPattern,
						thinkingLevel: route.thinkingLevel,
						attemptLimits: route.attemptLimits,
						visibleFiles,
						runCapability: runCapability.capability,
						network: "off",
						credentials: "none",
						allowedTools: toolProfile,
						signal: controller.signal,
					};
					const selectedAnalyzers: LocalSolverAnalyzer[] = [];
					for (const analyzerId of route.analyzerIds) {
						const analyzer = analyzerById.get(analyzerId);
						if (analyzer === undefined)
							return { status: "blocked", reason: `reviewed analyzer ${analyzerId} is not registered` };
						selectedAnalyzers.push(analyzer);
					}
					let result: LocalSolverSessionResult | undefined;
					for (const analyzer of selectedAnalyzers) {
						const analysis = await analyzer.analyze(input);
						if (analysis.status === "not-applicable") continue;
						if (analysis.status === "cancelled")
							return { status: "cancelled", reason: analysis.reason ?? "analyzer cancelled" };
						if (analysis.status === "refused")
							return {
								status: "failed",
								reason: `analyzer ${analyzer.id} refused: ${analysis.reason}`.slice(0, 256),
							};
						result = analysis.result;
						break;
					}
					if (controller.signal.aborted)
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					if (result === undefined) {
						run.session = await options.createSession(request);
						run.sessionReady.resolve(run.session);
						result = await run.session.solve(input);
					}
					if (controller.signal.aborted)
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					if (result.candidate === undefined || result.candidate.trim() === "")
						return { status: "failed", reason: "agent produced no candidate" };
					const candidate = new TextEncoder().encode(result.candidate);
					if (candidate.byteLength > MAX_ARTIFACT_BYTES)
						return { status: "failed", reason: "candidate exceeds size bound" };
					if (controller.signal.aborted)
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					const artifactEvidence = await writeArtifacts(verifiedArtifactRoot, request.runId, [
						{ path: "candidate.txt", content: candidate },
						...(result.artifacts ?? []),
						...runCapability.artifacts,
					]);
					if (controller.signal.aborted) {
						await fs.rm(artifactPath, { recursive: true, force: true });
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					}
					return {
						status: "candidate",
						artifacts: artifactEvidence.map(artifact => artifact.path),
						artifactEvidence,
					};
				} catch (error) {
					return {
						status: "failed",
						reason: error instanceof Error ? error.message.slice(0, 256) : "local solver failed",
					};
				}
			} finally {
				request.signal.removeEventListener("abort", abort);
				run.sessionReady.resolve(undefined);
				completion.resolve();
				if (runs.get(request.runId) === run && run.termination === undefined) runs.delete(request.runId);
			}
		},
	};
}
