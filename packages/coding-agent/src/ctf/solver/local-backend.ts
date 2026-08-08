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
	CtfRunTerminationRequest,
	CtfSolverBackend,
	CtfSolverOutcome,
	CtfSolverRequest,
} from "../runtime/scheduler";
import {
	type LocalEvaluationAdapter,
	type LocalEvaluationAdapterLifecycle,
	type LocalEvaluationAdapterProvider,
	matchingLocalEvaluationProviders,
	openLocalEvaluationAdapter,
} from "./local-evaluation-adapter";
import {
	diagnosticRetryLimitFor,
	fixtureSolverRouteFor,
	REVIEWED_SOLVER_ANALYZER_IDS,
	type SolverAttemptLimits,
	type SolverRoute,
	solverRouteFor,
	validateSolverRoute,
} from "./router";

const FORBIDDEN_BASENAMES = new Set(["challenge.yaml", "solve.py"]);
const MAX_FILE_BYTES = 256 * 1024;
const MAX_VISIBLE_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024;
const MAX_ARTIFACTS = 8;
const TERMINATION_TIMEOUT_MS = 250;
const LOCAL_SOLVER_PRODUCER_DIGEST = canonicalDigest({ backendId: "local-gjc-agent", version: 1 });
async function waitBounded(operation: Promise<void>, timeoutMs: number, label: string): Promise<void> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		await Promise.race([
			operation,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
			}),
		]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}
async function awaitOrAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T | undefined> {
	if (signal.aborted) return undefined;
	return await new Promise<T | undefined>((resolve, reject) => {
		const abort = () => finish(undefined);
		const finish = (value?: T, error?: unknown): void => {
			signal.removeEventListener("abort", abort);
			if (error !== undefined) reject(error);
			else resolve(value);
		};
		signal.addEventListener("abort", abort, { once: true });
		promise.then(
			value => finish(value),
			error => finish(undefined, error),
		);
	});
}

export type LocalSolverVisibleFile = Readonly<{ path: string; content: Uint8Array }>;
export type LocalSolverArtifact = Readonly<{ path: string; content: Uint8Array }>;
export type LocalSolverRunCapability = Readonly<{
	writeScratch(path: string, content: Uint8Array): Promise<void>;
	readScratch(path: string): Promise<Uint8Array | undefined>;
	publish(path: string, content: Uint8Array): Promise<void>;
}>;
export type LocalSolverRetryFeedback = Readonly<{
	schemaVersion: "ctf-solver-feedback-1";
	attempt: number;
	code: "analyzers_not_applicable" | "empty_candidate";
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
	visibleFiles: readonly { path: string; content: Uint8Array }[];
	attempt: number;
	retryFeedback?: LocalSolverRetryFeedback;
	evaluationAdapter?: LocalEvaluationAdapter;
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
}>;
/** Acquired synchronously so cancellation owns creation before a session result can arrive. */
export type LocalSolverSessionLifecycle = Readonly<{
	session: Promise<LocalSolverSession>;
	terminate(request: CtfRunTerminationRequest): Promise<void>;
	/** Resolves only after acquisition and session-owned work can no longer write. */
	quiesced: Promise<void>;
}>;
export type LocalSolverAnalyzerResult =
	| Readonly<{ status: "not-applicable" }>
	| Readonly<{ status: "refused"; reason: string }>
	| Readonly<{ status: "candidate"; result: LocalSolverSessionResult }>
	| Readonly<{ status: "cancelled"; reason?: string }>;
export type LocalSolverAnalyzerLifecycle = Readonly<{
	result: Promise<LocalSolverAnalyzerResult>;
	terminate(request: CtfRunTerminationRequest): Promise<void>;
	/** Resolves only after analyzer-owned work can no longer write. */
	quiesced: Promise<void>;
}>;
export function createLocalSolverAnalyzerLifecycle(
	input: LocalSolverSessionInput,
	analyze: (ownedInput: LocalSolverSessionInput) => Promise<LocalSolverAnalyzerResult>,
): LocalSolverAnalyzerLifecycle {
	const controller = new AbortController();
	const abort = () => controller.abort(input.signal.reason);
	if (input.signal.aborted) abort();
	else input.signal.addEventListener("abort", abort, { once: true });
	const result = Promise.resolve().then(() => analyze({ ...input, signal: controller.signal }));
	const quiesced = result
		.then(
			() => undefined,
			() => undefined,
		)
		.finally(() => input.signal.removeEventListener("abort", abort));
	return {
		result,
		terminate: async request => controller.abort(request.reason),
		quiesced,
	};
}
function isLocalSolverAnalyzerLifecycle(value: unknown): value is LocalSolverAnalyzerLifecycle {
	return (
		value !== null &&
		typeof value === "object" &&
		"result" in value &&
		value.result instanceof Promise &&
		"terminate" in value &&
		typeof value.terminate === "function" &&
		"quiesced" in value &&
		value.quiesced instanceof Promise
	);
}
export type LocalSolverAnalyzer = Readonly<{
	id: string;
	analyze(input: LocalSolverSessionInput): LocalSolverAnalyzerLifecycle;
}>;
export type LocalCtfSolverBackendOptions = Readonly<{
	root: string;
	challenges: ReadonlyMap<string, ChallengeDescriptor>;
	artifactRoot: string;
	allowedTools?: readonly string[];
	analyzers?: readonly LocalSolverAnalyzer[];
	adapterProviders?: readonly LocalEvaluationAdapterProvider[];
	createSession: (request: CtfSolverRequest) => LocalSolverSessionLifecycle;
}>;
export type LocalCtfSolverFixtureBackendOptions = Omit<LocalCtfSolverBackendOptions, "createSession"> &
	Readonly<{
		createSession: (
			request: CtfSolverRequest,
		) => Promise<LocalSolverSession & Readonly<{ terminate?(request: CtfRunTerminationRequest): Promise<void> }>>;
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
	return createLocalCtfSolverBackendForRoutes(options, solverRouteFor);
}

/** Fixture-only constructor. Production code must use createLocalCtfSolverBackend. */
export function createLocalCtfSolverFixtureBackend(options: LocalCtfSolverFixtureBackendOptions): CtfSolverBackend {
	return createLocalCtfSolverBackendForRoutes(
		{
			...options,
			createSession: request => {
				const session = options.createSession(request);
				const quiescence = Promise.withResolvers<void>();
				const wrappedSession = session.then(active => ({
					...active,
					solve: async (input: LocalSolverSessionInput) => {
						try {
							return await active.solve(input);
						} finally {
							quiescence.resolve();
						}
					},
				}));
				return {
					session: wrappedSession,
					terminate: async termination => {
						const active = await wrappedSession;
						await active.terminate?.(termination);
						quiescence.resolve();
					},
					quiesced: quiescence.promise,
				};
			},
		},
		fixtureSolverRouteFor,
	);
}

function createLocalCtfSolverBackendForRoutes(
	options: LocalCtfSolverBackendOptions,
	routeFor: (challengeId: string) => SolverRoute,
): CtfSolverBackend {
	const root = path.resolve(options.root);
	const artifactRoot = path.resolve(options.artifactRoot);
	if (!contained(root, artifactRoot)) throw new Error("artifact root must be contained by the workspace root");
	const allowedTools = Object.freeze([...(options.allowedTools ?? [])]);
	const analyzers = Object.freeze([...(options.analyzers ?? [])]);
	const adapterProviders = Object.freeze([...(options.adapterProviders ?? [])]);
	const analyzerById = new Map<string, LocalSolverAnalyzer>();
	const reviewedAnalyzerIds = REVIEWED_SOLVER_ANALYZER_IDS;
	for (const analyzer of analyzers) {
		if (!reviewedAnalyzerIds.has(analyzer.id))
			throw new Error(`analyzer ${analyzer.id} is not declared by a reviewed solver route`);
		if (analyzerById.has(analyzer.id)) throw new Error(`analyzer ${analyzer.id} is registered more than once`);
		analyzerById.set(analyzer.id, analyzer);
	}
	type ActiveRun = {
		runId: string;
		challengeId: string;
		competitionId: string;
		ownerId: string;
		fencingToken: number;
		artifactPath: string;
		controller: AbortController;
		completion: Promise<void>;
		sessionLifecycle?: LocalSolverSessionLifecycle;
		evaluationAdapter?: LocalEvaluationAdapter;
		acquisition?: LocalEvaluationAdapterLifecycle;
		termination?: Promise<void>;
		quiescenceTimeoutMs: number;
	};
	const runs = new Map<string, ActiveRun>();
	return {
		id: "local-gjc-agent",
		termination: "owned",
		async terminate(request): Promise<void> {
			const run = runs.get(request.runId);
			if (run === undefined) return;
			if (
				request.competitionId !== run.competitionId ||
				request.runId !== run.runId ||
				request.challengeId !== run.challengeId ||
				request.ownerId !== run.ownerId ||
				request.fencingToken !== run.fencingToken
			)
				throw new Error("termination identity does not match the active run");
			if (run.termination === undefined) {
				run.controller.abort(request.reason);
				run.termination = (async () => {
					const acquisition = await Promise.allSettled([
						waitBounded(
							Promise.resolve().then(async () => {
								await run.acquisition?.close();
							}),
							run.quiescenceTimeoutMs,
							"termination timed out closing adapter acquisition",
						),
						waitBounded(
							Promise.resolve().then(async () => {
								await run.evaluationAdapter?.close();
							}),
							run.quiescenceTimeoutMs,
							"termination timed out closing evaluation adapter",
						),
					]);
					const acquisitionFailure = acquisition.find(
						(acknowledgment): acknowledgment is PromiseRejectedResult => acknowledgment.status === "rejected",
					);
					if (acquisitionFailure !== undefined) {
						void run.completion.catch(() => undefined);
						throw acquisitionFailure.reason;
					}
					const lifecycle = run.sessionLifecycle;
					if (lifecycle !== undefined) {
						await waitBounded(
							Promise.resolve().then(() => lifecycle.terminate(request)),
							run.quiescenceTimeoutMs,
							"termination timed out waiting for session lifecycle termination",
						);
						await waitBounded(
							lifecycle.quiesced,
							run.quiescenceTimeoutMs,
							"termination timed out waiting for session lifecycle quiescence",
						);
					} else {
						await waitBounded(
							run.completion,
							run.quiescenceTimeoutMs,
							"termination timed out waiting for run completion",
						);
					}
					const residual = await fs.lstat(run.artifactPath).catch(error => {
						if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
						throw error;
					});
					if (residual !== undefined) throw new Error("terminated run retained artifact output");
					if (runs.get(request.runId) === run) runs.delete(request.runId);
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
			const run: ActiveRun = {
				runId: request.runId,
				challengeId: request.challengeId,
				competitionId: request.authority.competitionId,
				ownerId: request.runId,
				fencingToken: request.authority.fencingToken,
				artifactPath,
				controller,
				completion: completion.promise,
				quiescenceTimeoutMs: TERMINATION_TIMEOUT_MS,
			};
			runs.set(request.runId, run);
			try {
				const descriptor = options.challenges.get(request.challengeId);
				if (descriptor === undefined || descriptor.networkMode !== "off")
					return { status: "blocked", reason: "challenge is not locally admissible" };
				let route: SolverRoute;
				try {
					route = routeFor(request.challengeId);
				} catch {
					return { status: "blocked", reason: "challenge solver route is not reviewed" };
				}
				run.quiescenceTimeoutMs = Math.min(TERMINATION_TIMEOUT_MS, route.attemptLimits.wallClockMs);
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
							return {
								status: "blocked",
								reason: "materialized solver route does not match the reviewed route",
							};
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
					const evaluationMaterialization = Object.freeze({
						provenanceDigest: materialized.provenanceDigest,
						visibleFiles: Object.freeze(
							visibleFiles.map(file =>
								Object.freeze({
									path: file.path,
									digest: materialized.visibleFileDigests![file.path]!,
									content: new Uint8Array(file.content),
								}),
							),
						),
					});
					const toolProfile = Object.freeze([...allowedTools]);
					const inputBase: Omit<LocalSolverSessionInput, "attempt" | "retryFeedback" | "runCapability"> = {
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
					const analyzerTerminationRequest = (): CtfRunTerminationRequest => ({
						competitionId: request.authority.competitionId,
						runId: request.runId,
						challengeId: request.challengeId,
						ownerId: request.runId,
						fencingToken: request.authority.fencingToken,
						reason: "cancelled",
					});
					let result: LocalSolverSessionResult | undefined;
					let successfulRunArtifacts: readonly LocalSolverArtifact[] = [];
					let retryFeedback: LocalSolverRetryFeedback | undefined;
					const diagnosticRetryLimit = diagnosticRetryLimitFor(route);
					for (let attempt = 0; attempt <= diagnosticRetryLimit; attempt++) {
						if (controller.signal.aborted)
							return { status: "cancelled", reason: "run cancelled or budget exhausted" };
						const attemptCapability = createRunCapability();
						const input: LocalSolverSessionInput = {
							...inputBase,
							attempt,
							...(retryFeedback === undefined ? {} : { retryFeedback }),
							runCapability: attemptCapability.capability,
						};
						let analyzerResult: LocalSolverSessionResult | undefined;
						for (const analyzer of selectedAnalyzers) {
							const lifecycle: unknown = analyzer.analyze(input);
							if (!isLocalSolverAnalyzerLifecycle(lifecycle)) {
								if (
									lifecycle !== null &&
									typeof lifecycle === "object" &&
									"then" in lifecycle &&
									typeof lifecycle.then === "function"
								)
									void Promise.resolve(lifecycle).catch(() => undefined);
								throw new Error(`analyzer ${analyzer.id} lifecycle is invalid`);
							}
							const terminateAndQuiesce = async (): Promise<void> => {
								const termination = await Promise.allSettled([
									waitBounded(
										Promise.resolve().then(() => lifecycle.terminate(analyzerTerminationRequest())),
										run.quiescenceTimeoutMs,
										`analyzer ${analyzer.id} termination`,
									),
								]);
								const quiescence = await Promise.allSettled([
									waitBounded(
										lifecycle.quiesced,
										run.quiescenceTimeoutMs,
										`analyzer ${analyzer.id} quiescence`,
									),
								]);
								const failure = [...termination, ...quiescence].find(
									(result): result is PromiseRejectedResult => result.status === "rejected",
								);
								if (failure !== undefined) throw failure.reason;
							};
							let analysis: LocalSolverAnalyzerResult | undefined;
							try {
								analysis = await awaitOrAbort(lifecycle.result, controller.signal);
							} catch (error) {
								await terminateAndQuiesce();
								throw error;
							}
							if (analysis === undefined || controller.signal.aborted) {
								await terminateAndQuiesce();
								return { status: "cancelled", reason: "run cancelled or budget exhausted" };
							}
							try {
								await waitBounded(
									lifecycle.quiesced,
									run.quiescenceTimeoutMs,
									`analyzer ${analyzer.id} quiescence`,
								);
							} catch (error) {
								await terminateAndQuiesce();
								throw error;
							}
							if (controller.signal.aborted) {
								await terminateAndQuiesce();
								return { status: "cancelled", reason: "run cancelled or budget exhausted" };
							}
							if (analysis.status === "not-applicable") continue;
							if (analysis.status === "cancelled")
								return { status: "cancelled", reason: analysis.reason ?? "analyzer cancelled" };
							if (analysis.status === "refused")
								return {
									status: "blocked",
									terminalKind: "terminal_refusal",
									reason: `analyzer ${analyzer.id} refused: ${analysis.reason}`.slice(0, 256),
								};
							analyzerResult = analysis.result;
							break;
						}
						if (controller.signal.aborted)
							return { status: "cancelled", reason: "run cancelled or budget exhausted" };
						if (analyzerResult !== undefined) {
							if (analyzerResult.candidate === undefined || analyzerResult.candidate.trim() === "") {
								if (attempt === diagnosticRetryLimit)
									return {
										status: "failed",
										terminalKind: "safe_exhaustion",
										reason: "analyzer produced no candidate",
									};
								retryFeedback = {
									schemaVersion: "ctf-solver-feedback-1",
									attempt,
									code: "empty_candidate",
								};
								continue;
							}
							result = analyzerResult;
							successfulRunArtifacts = attemptCapability.artifacts;
							break;
						}
						if (selectedAnalyzers.length > 0 && attempt < diagnosticRetryLimit) {
							retryFeedback = {
								schemaVersion: "ctf-solver-feedback-1",
								attempt,
								code: "analyzers_not_applicable",
							};
							continue;
						}
						if (route.adapterKind === "browser-session")
							return { status: "blocked", reason: "browser-session routes are disabled" };
						const matchingProviders = matchingLocalEvaluationProviders(adapterProviders, route);
						if (route.adapterKind !== "offline-checker" && matchingProviders.length !== 1)
							return {
								status: "blocked",
								reason:
									matchingProviders.length === 0
										? "reviewed local evaluation adapter provider is not registered"
										: "reviewed local evaluation adapter provider is registered more than once",
							};
						let evaluationAdapter: LocalEvaluationAdapter | undefined;
						let sessionExhaustionReason: string | undefined;
						try {
							if (matchingProviders.length === 1) {
								const acquisition: LocalEvaluationAdapterLifecycle = {
									close: async () => {
										controller.abort(new Error("local evaluation adapter closed before acquisition"));
									},
								};
								run.acquisition = acquisition;
								evaluationAdapter = await openLocalEvaluationAdapter(
									matchingProviders[0]!,
									route,
									controller.signal,
									Object.freeze({
										competitionId: request.authority.competitionId,
										runId: request.runId,
										challengeId: request.challengeId,
										fencingToken: request.authority.fencingToken,
									}),
									acquisition,
									evaluationMaterialization,
								);
								run.evaluationAdapter = evaluationAdapter;
								if (controller.signal.aborted)
									return { status: "cancelled", reason: "run cancelled or budget exhausted" };
							}
							const lifecycle = options.createSession(request);
							if (
								lifecycle === null ||
								typeof lifecycle !== "object" ||
								typeof lifecycle.terminate !== "function" ||
								lifecycle.session === undefined ||
								typeof lifecycle.session.then !== "function" ||
								lifecycle.quiesced === undefined ||
								typeof lifecycle.quiesced.then !== "function"
							)
								throw new Error("local solver session lifecycle is invalid");
							run.sessionLifecycle = lifecycle;
							const terminateSession = async (label: string): Promise<void> => {
								await waitBounded(
									Promise.resolve().then(() => lifecycle.terminate(analyzerTerminationRequest())),
									run.quiescenceTimeoutMs,
									`session lifecycle termination ${label}`,
								);
								await waitBounded(
									lifecycle.quiesced,
									run.quiescenceTimeoutMs,
									`session lifecycle quiescence ${label}`,
								);
							};
							const session = await awaitOrAbort(lifecycle.session, controller.signal);
							if (session === undefined || controller.signal.aborted) {
								await terminateSession("after cancellation");
								return { status: "cancelled", reason: "run cancelled or budget exhausted" };
							}
							let sessionResult: LocalSolverSessionResult;
							try {
								sessionResult = await session.solve(
									evaluationAdapter === undefined ? input : { ...input, evaluationAdapter },
								);
							} catch (error) {
								await terminateSession("after rejection");
								throw error;
							}
							try {
								await waitBounded(
									lifecycle.quiesced,
									run.quiescenceTimeoutMs,
									"session lifecycle quiescence after completion",
								);
							} catch (error) {
								await terminateSession("after completion quiescence failure");
								throw error;
							}
							if (sessionResult.candidate === undefined || sessionResult.candidate.trim() === "") {
								if (attempt === diagnosticRetryLimit) {
									sessionExhaustionReason = "agent produced no candidate";
								} else {
									retryFeedback = {
										schemaVersion: "ctf-solver-feedback-1",
										attempt,
										code: "empty_candidate",
									};
									continue;
								}
							} else {
								result = sessionResult;
								successfulRunArtifacts = attemptCapability.artifacts;
								break;
							}
						} finally {
							if (evaluationAdapter !== undefined)
								await waitBounded(
									evaluationAdapter.close(),
									run.quiescenceTimeoutMs,
									"evaluation adapter cleanup",
								);
						}
						if (controller.signal.aborted)
							return { status: "cancelled", reason: "run cancelled or budget exhausted" };
						if (sessionExhaustionReason !== undefined)
							return {
								status: "failed",
								terminalKind: "safe_exhaustion",
								reason: sessionExhaustionReason,
							};
					}
					if (result === undefined)
						return {
							status: "failed",
							terminalKind: "safe_exhaustion",
							reason: "solver diagnostic attempts exhausted",
						};
					if (controller.signal.aborted) {
						const lifecycle = run.sessionLifecycle;
						if (lifecycle !== undefined) {
							await waitBounded(
								Promise.resolve().then(() =>
									lifecycle.terminate({
										competitionId: request.authority.competitionId,
										runId: request.runId,
										challengeId: request.challengeId,
										ownerId: request.runId,
										fencingToken: request.authority.fencingToken,
										reason: "cancelled",
									}),
								),
								run.quiescenceTimeoutMs,
								"session lifecycle termination after cancellation",
							);
							await waitBounded(
								lifecycle.quiesced,
								run.quiescenceTimeoutMs,
								"session lifecycle quiescence after cancellation",
							);
						}
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					}
					if (result.candidate === undefined || result.candidate.trim() === "")
						return {
							status: "failed",
							terminalKind: "safe_exhaustion",
							reason: "solver produced no candidate after diagnostic attempts",
						};
					const candidate = new TextEncoder().encode(result.candidate);
					if (candidate.byteLength > MAX_ARTIFACT_BYTES)
						return { status: "failed", reason: "candidate exceeds size bound" };
					if (controller.signal.aborted)
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					const artifactEvidence = await writeArtifacts(verifiedArtifactRoot, request.runId, [
						{ path: "candidate.txt", content: candidate },
						...(result.artifacts ?? []),
						...successfulRunArtifacts,
					]);
					if (controller.signal.aborted) {
						await fs.rm(artifactPath, { recursive: true, force: true });
						return { status: "cancelled", reason: "run cancelled or budget exhausted" };
					}
					return {
						status: "candidate",
						artifacts: artifactEvidence.map(artifact => artifact.path),
						artifactEvidence,
						producerDigest: LOCAL_SOLVER_PRODUCER_DIGEST,
						routeDigest: route.routeDigest,
					};
				} catch (error) {
					return {
						status: "failed",
						reason: error instanceof Error ? error.message.slice(0, 256) : "local solver failed",
					};
				}
			} finally {
				request.signal.removeEventListener("abort", abort);
				completion.resolve();
				if (runs.get(request.runId) === run && run.termination === undefined) runs.delete(request.runId);
			}
		},
	};
}
