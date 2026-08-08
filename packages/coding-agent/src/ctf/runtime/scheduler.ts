import { createHash, randomUUID } from "node:crypto";
import * as path from "node:path";
import { CtfError } from "../contracts/errors";
import type { CtfRunMode, UnavailableRunResult } from "./run-orchestrator";

export type CtfArtifactEvidence = Readonly<{
	path: string;
	digest: string;
	size: number;
}>;

export type CtfSolverOutcome = Readonly<{
	status: "candidate" | "failed" | "blocked" | "cancelled";
	reason?: string;
	artifacts?: readonly string[];
	artifactEvidence?: readonly CtfArtifactEvidence[];
}>;

export type CtfRunReason =
	| "authority_unavailable"
	| "backend_invalid_artifact_evidence"
	| "backend_invalid_result"
	| "backend_result_mismatch"
	| "cancelled"
	| "setup_failed"
	| "solver_failed";

export type CtfTerminationAcknowledgment = Readonly<{
	ownerId: string;
}>;

export type CtfMaterializedChallenge = Readonly<{
	root: string;
	provenanceDigest: string;
	visibleFileDigests?: Readonly<Record<string, string>>;
}>;
export type CtfSolverRequest = Readonly<{
	runId: string;
	challengeId: string;
	mode: CtfRunMode;
	backendId: string;
	budgetMs?: number;
	signal: AbortSignal;
	materialized?: CtfMaterializedChallenge;
	authority: Readonly<{
		competitionId: string;
		fencingToken: number;
		intentId: string;
		skillDigest: string;
		sandboxPolicyDigest: string;
	}>;
}>;

export type CtfTerminationRequest = Readonly<{
	runId: string;
	challengeId: string;
	ownerId: string;
	reason: "cancelled" | "budget_exhausted";
}>;

export type CtfSolverBackend = Readonly<{
	id: string;
	solve(request: CtfSolverRequest): Promise<CtfSolverOutcome>;
	/** Resolves only after this backend can prove no work for the run can write again. */
	terminate?(request: CtfTerminationRequest): Promise<void>;
	/** Cooperative fixture cancellation is never admitted for competition scoring. */
	termination?: "owned" | "cooperative-fixture";
}>;

export type CtfRunAuthority = Readonly<{
	fencingToken: number;
	intentId: string;
	skillDigest: string;
	sandboxPolicyDigest: string;
}>;

export type CtfPreparedRun = Readonly<{
	authority: CtfRunAuthority;
	finalize(
		outcome: CtfSolverOutcome,
		context?: Readonly<{ signal: AbortSignal }>,
	): Promise<CtfSolverOutcome | undefined>;
	/** Resolves only after finalization-owned work can no longer write for this run. */
	terminate?(request: CtfTerminationRequest): Promise<void>;
}>;

export type CtfScheduledRun =
	| UnavailableRunResult
	| Readonly<{
			schemaVersion: "ctf-run-result-1";
			status: CtfSolverOutcome["status"];
			runId: string;
			competitionId: string;
			challengeId: string;
			mode: CtfRunMode;
			reason?: CtfRunReason;
			artifacts?: readonly string[];
			artifactEvidence?: readonly CtfArtifactEvidence[];
	  }>;

export type CtfBatchScheduleRequest = Readonly<{
	competitionId: string;
	challengeIds: readonly string[];
	mode: CtfRunMode;
	concurrency: number;
	budgetMs?: number;
	backend?: CtfSolverBackend;
	signal?: AbortSignal;
	createUnavailable: (challengeId: string, mode: CtfRunMode) => Promise<UnavailableRunResult>;
	/** Static authority is retained for one-challenge compatibility only. */
	authority?: CtfRunAuthority;
	authorityFor?: (
		input: Readonly<{
			challengeId: string;
			runId: string;
			authorityOwnerId: string;
			index: number;
			signal: AbortSignal;
		}>,
	) => Promise<CtfRunAuthority>;
	/** Resolves only after authority acquisition-owned work can no longer write for this owner. */
	terminateAuthority?: (request: CtfTerminationRequest) => Promise<CtfTerminationAcknowledgment>;
	materializedFor?: (
		input: Readonly<{
			challengeId: string;
			runId: string;
			materializationOwnerId: string;
			index: number;
			signal: AbortSignal;
		}>,
	) => Promise<CtfMaterializedChallenge>;
	/** Resolves only after materialization-owned work can no longer write for this owner. */
	terminateMaterialization?: (request: CtfTerminationRequest) => Promise<void>;
	prepareRun?: (
		input: Readonly<{
			challengeId: string;
			runId: string;
			preparationOwnerId: string;
			index: number;
			backendId: string;
			signal: AbortSignal;
		}>,
	) => Promise<CtfPreparedRun>;
	/** Resolves only after preparation-owned work can no longer write for this owner. */
	terminatePreparation?: (request: CtfTerminationRequest) => Promise<void>;
	runIdFactory?: (input: Readonly<{ challengeId: string; index: number }>) => string;
}>;

export type CtfBatchScheduleResult = Readonly<{
	schemaVersion: "ctf-batch-result-1";
	status: "complete" | "partial" | "cancelled";
	results: readonly CtfScheduledRun[];
	scheduler: Readonly<{ concurrency: number; budgetMs?: number; backend?: string }>;
	aggregationDigest: string;
}>;

function assertPositive(value: number, label: string): void {
	if (!Number.isSafeInteger(value) || value < 1)
		throw new CtfError("invalid_api_request", `${label} must be a positive integer`);
}
function validRunId(value: string): boolean {
	return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
}

function redactedReason(reason: string | undefined): string | undefined {
	if (reason === undefined || reason.trim().length === 0) return undefined;
	return reason.length > 256 ? `${reason.slice(0, 256)}…` : reason;
}
function validArtifactPath(value: string): boolean {
	return (
		value.length > 0 &&
		!path.isAbsolute(value) &&
		!value.includes("\\") &&
		path.posix.normalize(value) === value &&
		value !== "." &&
		!value.startsWith("../") &&
		!value.includes("/../")
	);
}
function isArtifactPathList(value: unknown): value is readonly string[] {
	return (
		Array.isArray(value) &&
		value.every(item => typeof item === "string" && validArtifactPath(item)) &&
		new Set(value).size === value.length
	);
}
function isArtifactEvidence(value: unknown): value is CtfArtifactEvidence {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	return (
		typeof record.path === "string" &&
		validArtifactPath(record.path) &&
		typeof record.digest === "string" &&
		/^[a-f0-9]{64}$/u.test(record.digest) &&
		typeof record.size === "number" &&
		Number.isSafeInteger(record.size) &&
		record.size >= 0
	);
}
function isArtifactEvidenceList(value: unknown): value is readonly CtfArtifactEvidence[] {
	return (
		Array.isArray(value) &&
		value.every(isArtifactEvidence) &&
		new Set(value.map(item => `${item.path}\u0000${item.digest}`)).size === value.length &&
		new Set(value.map(item => item.path)).size === value.length
	);
}

function normalizeSolverOutcome(value: unknown): CtfSolverOutcome {
	if (value === null || typeof value !== "object") {
		return { status: "failed", reason: "solver backend returned an invalid result" };
	}
	const record = value as Record<string, unknown>;
	if (!["candidate", "failed", "blocked", "cancelled"].includes(String(record.status))) {
		return { status: "failed", reason: "solver backend returned an invalid result" };
	}
	if (record.reason !== undefined && typeof record.reason !== "string") {
		return { status: "failed", reason: "solver backend returned an invalid result" };
	}
	const artifacts = record.artifacts;
	if (artifacts !== undefined && !isArtifactPathList(artifacts)) {
		return { status: "failed", reason: "solver backend returned an invalid result" };
	}
	const artifactEvidence = record.artifactEvidence;
	if (artifactEvidence !== undefined && !isArtifactEvidenceList(artifactEvidence))
		return { status: "failed", reason: "solver backend returned invalid artifact evidence" };
	if (
		artifactEvidence !== undefined &&
		artifacts !== undefined &&
		(artifactEvidence.length !== artifacts.length ||
			artifactEvidence.some((item, index) => item.path !== artifacts[index]))
	)
		return { status: "failed", reason: "solver backend artifact evidence does not match paths" };
	return {
		status: record.status as CtfSolverOutcome["status"],
		...(record.reason === undefined ? {} : { reason: record.reason as string }),
		...(artifacts === undefined ? {} : { artifacts }),
		...(artifactEvidence === undefined ? {} : { artifactEvidence }),
	};
}
function durableReason(outcome: CtfSolverOutcome): CtfRunReason | undefined {
	if (outcome.status === "candidate") return undefined;
	if (outcome.status === "blocked") return "authority_unavailable";
	if (outcome.status === "cancelled") return "cancelled";
	if (outcome.reason === "solver backend returned invalid artifact evidence")
		return "backend_invalid_artifact_evidence";
	if (outcome.reason === "solver backend artifact evidence does not match paths") return "backend_result_mismatch";
	if (outcome.reason === "solver backend returned an invalid result") return "backend_invalid_result";
	if (outcome.reason === "solver setup failed") return "setup_failed";
	return "solver_failed";
}

function aggregationDigest(results: readonly CtfScheduledRun[]): string {
	const canonical = results.map(result => ({
		status: result.status,
		competitionId: result.competitionId,
		challengeId: result.challengeId,
		mode: result.mode,
		reason: redactedReason(result.reason),
		artifacts: "artifacts" in result ? [...(result.artifacts ?? [])].sort() : undefined,
		artifactEvidence:
			"artifactEvidence" in result
				? [...(result.artifactEvidence ?? [])].sort((left, right) => left.path.localeCompare(right.path))
				: undefined,
	}));
	return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}
async function awaitWithAbort<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
	if (signal.aborted) throw new Error("run cancelled");
	const aborted = Promise.withResolvers<never>();
	const abort = () => aborted.reject(new Error("run cancelled"));
	signal.addEventListener("abort", abort, { once: true });
	try {
		return await Promise.race([value, aborted.promise]);
	} finally {
		signal.removeEventListener("abort", abort);
	}
}
async function materializeWithTermination(
	materializedFor: NonNullable<CtfBatchScheduleRequest["materializedFor"]>,
	terminateMaterialization: NonNullable<CtfBatchScheduleRequest["terminateMaterialization"]>,
	input: Readonly<{
		challengeId: string;
		runId: string;
		materializationOwnerId: string;
		index: number;
		signal: AbortSignal;
	}>,
): Promise<CtfMaterializedChallenge> {
	const cancelled = Promise.withResolvers<never>();
	let termination: Promise<void> | undefined;
	const terminate = () => {
		if (termination === undefined) {
			termination = awaitTerminationAcknowledgments([
				() =>
					terminateMaterialization({
						runId: input.runId,
						challengeId: input.challengeId,
						ownerId: input.materializationOwnerId,
						reason: input.signal.reason === "run budget exhausted" ? "budget_exhausted" : "cancelled",
					}),
			]);
			void termination.then(
				() => cancelled.reject(new Error("run cancelled")),
				error => cancelled.reject(error),
			);
		}
		return termination;
	};
	const abort = () => {
		void terminate();
	};
	input.signal.addEventListener("abort", abort, { once: true });
	try {
		if (input.signal.aborted) {
			await terminate();
			throw new Error("run cancelled");
		}
		const materialized = await Promise.race([materializedFor(input), cancelled.promise]);
		if (input.signal.aborted) {
			await terminate();
			throw new Error("run cancelled");
		}
		return materialized;
	} finally {
		input.signal.removeEventListener("abort", abort);
	}
}
async function prepareWithTermination(
	prepareRun: NonNullable<CtfBatchScheduleRequest["prepareRun"]>,
	terminatePreparation: NonNullable<CtfBatchScheduleRequest["terminatePreparation"]>,
	input: Readonly<{
		challengeId: string;
		runId: string;
		preparationOwnerId: string;
		index: number;
		backendId: string;
		signal: AbortSignal;
	}>,
): Promise<CtfPreparedRun> {
	const cancelled = Promise.withResolvers<never>();
	let termination: Promise<void> | undefined;
	const terminate = () => {
		if (termination === undefined) {
			termination = awaitTerminationAcknowledgments([
				() =>
					terminatePreparation({
						runId: input.runId,
						challengeId: input.challengeId,
						ownerId: input.preparationOwnerId,
						reason: input.signal.reason === "run budget exhausted" ? "budget_exhausted" : "cancelled",
					}),
			]);
			void termination.then(
				() => cancelled.reject(new Error("run cancelled")),
				error => cancelled.reject(error),
			);
		}
		return termination;
	};
	const abort = () => {
		void terminate();
	};
	input.signal.addEventListener("abort", abort, { once: true });
	try {
		if (input.signal.aborted) {
			await terminate();
			throw new Error("run cancelled");
		}
		let prepared: CtfPreparedRun;
		try {
			prepared = await Promise.race([prepareRun(input), cancelled.promise]);
		} catch (error) {
			if (input.signal.aborted) await terminate();
			throw error;
		}
		if (input.signal.aborted) {
			await terminate();
			throw new Error("run cancelled");
		}
		return prepared;
	} finally {
		input.signal.removeEventListener("abort", abort);
	}
}
async function acquireAuthorityWithTermination(
	authorityFor: NonNullable<CtfBatchScheduleRequest["authorityFor"]>,
	terminateAuthority: NonNullable<CtfBatchScheduleRequest["terminateAuthority"]>,
	input: Readonly<{
		challengeId: string;
		runId: string;
		authorityOwnerId: string;
		index: number;
		signal: AbortSignal;
	}>,
): Promise<CtfRunAuthority> {
	const cancelled = Promise.withResolvers<never>();
	let termination: Promise<void> | undefined;
	const terminate = () => {
		if (termination === undefined) {
			termination = Promise.resolve()
				.then(() =>
					terminateAuthority({
						runId: input.runId,
						challengeId: input.challengeId,
						ownerId: input.authorityOwnerId,
						reason: input.signal.reason === "run budget exhausted" ? "budget_exhausted" : "cancelled",
					}),
				)
				.then(acknowledgment => {
					if (acknowledgment === undefined || acknowledgment.ownerId !== input.authorityOwnerId)
						throw new CtfError("invalid_api_request", "authority termination acknowledgment owner mismatch");
				});
			void termination.then(
				() => cancelled.reject(new Error("run cancelled")),
				error => cancelled.reject(error),
			);
		}
		return termination;
	};
	const abort = () => {
		void terminate();
	};
	input.signal.addEventListener("abort", abort, { once: true });
	try {
		if (input.signal.aborted) {
			await terminate();
			throw new Error("run cancelled");
		}
		const authority = await Promise.race([authorityFor(input), cancelled.promise]);
		if (input.signal.aborted) {
			await terminate();
			throw new Error("run cancelled");
		}
		return authority;
	} finally {
		input.signal.removeEventListener("abort", abort);
	}
}
async function awaitTerminationAcknowledgments(owners: readonly (() => Promise<void>)[]): Promise<void> {
	const acknowledgments = await Promise.allSettled(owners.map(owner => Promise.resolve().then(owner)));
	const rejected = acknowledgments.find(
		(acknowledgment): acknowledgment is PromiseRejectedResult => acknowledgment.status === "rejected",
	);
	if (rejected !== undefined)
		throw new CtfError("invalid_api_request", "termination acknowledgment rejected", {
			details: {
				cause: rejected.reason instanceof Error ? rejected.reason.message : String(rejected.reason),
			},
		});
}

async function executeWithBudget(
	backend: CtfSolverBackend,
	request: CtfSolverRequest,
	terminate: (() => Promise<void>) | undefined,
): Promise<CtfSolverOutcome> {
	const cancelled = Promise.withResolvers<CtfSolverOutcome>();
	let termination: Promise<void> | undefined;
	const terminateRun = () => {
		if (termination === undefined) {
			if (terminate === undefined) throw new CtfError("invalid_api_request", "run termination is unavailable");
			termination = terminate();
			void termination.then(
				() => cancelled.resolve({ status: "cancelled", reason: "run cancelled or budget exhausted" }),
				error => cancelled.reject(error),
			);
		}
		return termination;
	};
	const onAbort = () => {
		if (terminate !== undefined) void terminateRun();
	};
	request.signal.addEventListener("abort", onAbort, { once: true });
	const execution = Promise.resolve()
		.then(() => backend.solve(request))
		.then(normalizeSolverOutcome)
		.catch((): CtfSolverOutcome => ({ status: "failed", reason: "solver backend failed" }));
	try {
		if (request.signal.aborted) {
			if (terminate !== undefined) {
				await terminateRun();
				return { status: "cancelled", reason: "run cancelled or budget exhausted" };
			}
			await execution;
			return { status: "cancelled", reason: "run cancelled or budget exhausted" };
		}
		const outcome = await Promise.race([execution, cancelled.promise]);
		if (request.signal.aborted) {
			await terminateRun();
			return { status: "cancelled", reason: "run cancelled or budget exhausted" };
		}
		return outcome;
	} finally {
		request.signal.removeEventListener("abort", onAbort);
	}
}

/** Schedule independent runs with bounded concurrency and stable result ordering. */
export async function scheduleCtfRuns(request: CtfBatchScheduleRequest): Promise<CtfBatchScheduleResult> {
	if (request.challengeIds.length === 0)
		throw new CtfError("invalid_api_request", "at least one challenge is required");
	assertPositive(request.concurrency, "concurrency");
	if (request.budgetMs !== undefined) assertPositive(request.budgetMs, "budget-ms");
	const challengeIds = [...new Set(request.challengeIds)].sort();
	if (challengeIds.length !== request.challengeIds.length)
		throw new CtfError("invalid_api_request", "challenge ids must be unique");
	if (request.backend !== undefined && challengeIds.length > 1 && request.authority !== undefined)
		throw new CtfError("invalid_api_request", "multi-challenge runs require challenge-scoped authority");
	if (
		request.backend !== undefined &&
		request.budgetMs !== undefined &&
		((request.mode === "competition" &&
			(request.backend.terminate === undefined || request.backend.termination === "cooperative-fixture")) ||
			(request.mode !== "competition" &&
				request.backend.terminate === undefined &&
				request.backend.termination !== "cooperative-fixture"))
	)
		throw new CtfError(
			"invalid_api_request",
			request.mode === "competition"
				? "production budgeted runs require backend termination acknowledgment"
				: "budgeted fixture runs require explicit cooperative termination",
		);
	if (
		request.mode === "competition" &&
		request.materializedFor !== undefined &&
		request.terminateMaterialization === undefined
	)
		throw new CtfError("invalid_api_request", "production materialization requires termination acknowledgment");
	if (
		request.mode === "competition" &&
		request.prepareRun !== undefined &&
		(request.budgetMs !== undefined || request.signal !== undefined) &&
		request.terminatePreparation === undefined
	)
		throw new CtfError("invalid_api_request", "production preparation requires termination acknowledgment");
	if (
		request.mode === "competition" &&
		request.authorityFor !== undefined &&
		(request.budgetMs !== undefined || request.signal !== undefined) &&
		request.terminateAuthority === undefined
	)
		throw new CtfError("invalid_api_request", "production authority acquisition requires termination acknowledgment");
	const runPlans = challengeIds.map((challengeId, index) => ({
		challengeId,
		index,
		runId: request.runIdFactory?.({ challengeId, index }) ?? randomUUID(),
		materializationOwnerId: randomUUID(),
		preparationOwnerId: randomUUID(),
		authorityOwnerId: randomUUID(),
	}));
	if (
		runPlans.some(plan => !validRunId(plan.runId)) ||
		new Set(runPlans.map(plan => plan.runId)).size !== runPlans.length
	)
		throw new CtfError("invalid_api_request", "run ids must be valid and unique");
	const concurrency = Math.min(request.concurrency, challengeIds.length);
	const results = new Array<CtfScheduledRun>(challengeIds.length);
	let cursor = 0;
	const worker = async (): Promise<void> => {
		for (;;) {
			if (request.signal?.aborted) return;
			const index = cursor++;
			const plan = runPlans[index];
			if (plan === undefined) return;
			const { challengeId, runId, materializationOwnerId, preparationOwnerId, authorityOwnerId } = plan;
			const backend = request.backend;
			if (backend === undefined) {
				results[index] = await request.createUnavailable(challengeId, request.mode);
				continue;
			}
			const signalController = new AbortController();
			const abort = () => signalController.abort(request.signal?.reason);
			request.signal?.addEventListener("abort", abort, { once: true });
			const timer =
				request.budgetMs === undefined
					? undefined
					: setTimeout(() => signalController.abort("run budget exhausted"), request.budgetMs);
			try {
				let preparation: CtfPreparedRun | undefined;
				let terminalError: CtfError | undefined;
				let outcome: CtfSolverOutcome;
				try {
					preparation =
						request.prepareRun === undefined
							? undefined
							: request.terminatePreparation === undefined
								? await awaitWithAbort(
										request.prepareRun({
											challengeId,
											runId,
											preparationOwnerId,
											index,
											backendId: backend.id,
											signal: signalController.signal,
										}),
										signalController.signal,
									)
								: await prepareWithTermination(request.prepareRun, request.terminatePreparation, {
										challengeId,
										runId,
										preparationOwnerId,
										index,
										backendId: backend.id,
										signal: signalController.signal,
									});
					const authority =
						preparation?.authority ??
						(request.authorityFor !== undefined
							? request.terminateAuthority === undefined
								? await awaitWithAbort(
										request.authorityFor({
											challengeId,
											runId,
											authorityOwnerId,
											index,
											signal: signalController.signal,
										}),
										signalController.signal,
									)
								: await acquireAuthorityWithTermination(request.authorityFor, request.terminateAuthority, {
										challengeId,
										runId,
										authorityOwnerId,
										index,
										signal: signalController.signal,
									})
							: request.authority);
					if (signalController.signal.aborted) {
						outcome = { status: "cancelled", reason: "run cancelled or budget exhausted" };
					} else if (authority === undefined) {
						outcome = { status: "blocked", reason: "run authority is unavailable" };
					} else {
						const materialized =
							request.materializedFor === undefined
								? undefined
								: request.terminateMaterialization === undefined
									? await awaitWithAbort(
											request.materializedFor({
												challengeId,
												runId,
												materializationOwnerId,
												index,
												signal: signalController.signal,
											}),
											signalController.signal,
										)
									: await materializeWithTermination(
											request.materializedFor,
											request.terminateMaterialization,
											{
												challengeId,
												runId,
												materializationOwnerId,
												index,
												signal: signalController.signal,
											},
										);
						const terminationRequest = (): CtfTerminationRequest => ({
							runId,
							challengeId,
							ownerId: runId,
							reason:
								signalController.signal.reason === "run budget exhausted" ? "budget_exhausted" : "cancelled",
						});
						if (
							request.mode === "competition" &&
							request.budgetMs !== undefined &&
							preparation?.terminate === undefined &&
							preparation !== undefined
						)
							throw new CtfError(
								"invalid_api_request",
								"production budgeted finalization requires termination acknowledgment",
							);
						outcome = await executeWithBudget(
							backend,
							{
								runId,
								challengeId,
								mode: request.mode,
								backendId: backend.id,
								budgetMs: request.budgetMs,
								signal: signalController.signal,
								authority: { competitionId: request.competitionId, ...authority },
								...(materialized === undefined ? {} : { materialized }),
							},
							backend.terminate === undefined
								? undefined
								: async () =>
										awaitTerminationAcknowledgments([
											() => backend.terminate?.(terminationRequest()) ?? Promise.resolve(),
										]),
						);
					}
				} catch (error) {
					if (error instanceof CtfError && preparation === undefined) throw error;
					if (error instanceof CtfError) terminalError = error;
					if (signalController.signal.aborted) {
						outcome = { status: "cancelled", reason: "run cancelled or budget exhausted" };
					} else if (preparation === undefined) {
						throw error;
					} else {
						outcome = { status: "failed", reason: "solver setup failed" };
					}
				}
				if (preparation !== undefined) {
					const terminationRequest = (): CtfTerminationRequest => ({
						runId,
						challengeId,
						ownerId: runId,
						reason: signalController.signal.reason === "run budget exhausted" ? "budget_exhausted" : "cancelled",
					});
					const cancelled = Promise.withResolvers<void>();
					let termination: Promise<void> | undefined;
					const terminateFinalization = () => {
						if (preparation.terminate === undefined)
							return Promise.reject(
								new CtfError(
									"invalid_api_request",
									"cancelled finalization requires termination acknowledgment",
								),
							);
						if (termination === undefined) {
							termination = awaitTerminationAcknowledgments([
								() => preparation.terminate?.(terminationRequest()) ?? Promise.resolve(),
							]);
							void termination.then(
								() => cancelled.resolve(),
								error => cancelled.reject(error),
							);
						}
						return termination;
					};
					const onAbort = () => {
						void terminateFinalization();
					};
					signalController.signal.addEventListener("abort", onAbort, { once: true });
					try {
						const finalizationOutcome = signalController.signal.aborted
							? { status: "cancelled" as const, reason: "run cancelled or budget exhausted" }
							: outcome;
						const finalization = Promise.resolve().then(() =>
							preparation.finalize(finalizationOutcome, { signal: signalController.signal }),
						);
						if (signalController.signal.aborted) {
							void finalization.catch(() => undefined);
							await terminateFinalization();
							outcome = { status: "cancelled", reason: "run cancelled or budget exhausted" };
						} else {
							const finalized = await Promise.race([finalization, cancelled.promise]);
							if (signalController.signal.aborted) {
								await terminateFinalization();
								outcome = { status: "cancelled", reason: "run cancelled or budget exhausted" };
							} else if (finalized !== undefined) outcome = normalizeSolverOutcome(finalized);
						}
					} finally {
						signalController.signal.removeEventListener("abort", onAbort);
					}
				}
				if (terminalError !== undefined) throw terminalError;
				results[index] = {
					schemaVersion: "ctf-run-result-1",
					...outcome,
					runId,
					competitionId: request.competitionId,
					challengeId,
					mode: request.mode,
					reason: durableReason(outcome),
				};
			} finally {
				request.signal?.removeEventListener("abort", abort);
				if (timer !== undefined) clearTimeout(timer);
			}
		}
	};
	await Promise.all(Array.from({ length: concurrency }, () => worker()));
	const completed = results.filter((result): result is CtfScheduledRun => result !== undefined);
	const status = request.signal?.aborted
		? "cancelled"
		: completed.length === challengeIds.length
			? "complete"
			: "partial";
	return {
		schemaVersion: "ctf-batch-result-1",
		status,
		results: completed,
		scheduler: { concurrency, budgetMs: request.budgetMs, backend: request.backend?.id },
		aggregationDigest: aggregationDigest(completed),
	};
}
