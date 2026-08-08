import { randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import { type Digest, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import { type VerifiedEvaluationEvidenceV1, validateVerifiedEvaluationEvidence } from "../contracts/evaluation";
import { type RunOwnerV1, validateRunOwner } from "../contracts/run";
import { effectiveSkillDigest } from "../contracts/skill";
import { loadCtfSkillIdentity } from "../skills/identity-loader";
import { CanonicalEventLog } from "../state/event-log";
import { RunLeaseStore } from "../state/lease";
import { type CtfStateStore, createCtfStateStore } from "../state/storage";
import type { CtfWorkspace } from "../workspace";
import type { CtfPreparedRun, CtfSolverOutcome } from "./scheduler";

export type CtfRunMode = "competition" | "benchmark";

export type CtfRunReadinessContract = Readonly<{
	backendReady: boolean;
	oracleReady: boolean;
}>;

export type CtfRunStartRequest = Readonly<{
	challengeId: string;
	mode: CtfRunMode;
	readiness?: CtfRunReadinessContract;
}>;

export type UnavailableRunResult = Readonly<{
	schemaVersion: "ctf-run-result-1";
	status: "unavailable";
	runId: string;
	competitionId: string;
	challengeId: string;
	mode: CtfRunMode;
	reason: string;
}>;

function validateRunMode(value: unknown): CtfRunMode {
	if (value !== "competition" && value !== "benchmark") {
		throw new CtfError("invalid_api_request", "run mode must be competition or benchmark");
	}
	return value;
}

function validateRunStartRequest(value: CtfRunStartRequest): CtfRunStartRequest {
	if (value === null || typeof value !== "object") {
		throw new CtfError("invalid_api_request", "CTF run start request is required");
	}
	const request = value as unknown as Record<string, unknown>;
	if (typeof request.challengeId !== "string" || request.challengeId.trim().length === 0) {
		throw new CtfError("invalid_api_request", "challenge id is required");
	}
	return {
		challengeId: request.challengeId,
		mode: validateRunMode(request.mode),
		readiness: request.readiness as CtfRunReadinessContract | undefined,
	};
}

function readinessIsAvailable(readiness: CtfRunReadinessContract | undefined): boolean {
	if (readiness === undefined || typeof readiness !== "object" || readiness === null) return false;
	return readiness.backendReady === true && readiness.oracleReady === true;
}

/**
 * Start a run only through the existing fenced unavailable lifecycle until a
 * verified backend and oracle executor are implemented. Readiness is an
 * explicit admission contract, not permission to execute a model or container.
 */
export async function startCtfRun(workspace: CtfWorkspace, request: CtfRunStartRequest): Promise<UnavailableRunResult> {
	const validated = validateRunStartRequest(request);
	challengeExists(workspace, validated.challengeId);
	const readinessAvailable = readinessIsAvailable(validated.readiness);
	const result = await createUnavailableRun(workspace, validated.challengeId, validated.mode);
	if (!readinessAvailable) return result;
	// A positive caller contract is not a verified executor; stay fail-closed.
	return result;
}

function challengeExists(workspace: CtfWorkspace, challengeId: string): void {
	if (!workspace.manifest.challenges.some(challenge => challenge.id === challengeId)) {
		throw new CtfError("invalid_manifest", `challenge is not registered: ${challengeId}`);
	}
}
const UNAVAILABLE_TERMINAL_REASON = "solver_backend_or_oracle_unavailable";
const UNAVAILABLE_RESULT_REASON = "no approved solver backend and trusted oracle are configured";

function terminalPersistenceError(error: unknown): CtfError {
	return new CtfError(
		"integrity_error",
		"blocked terminal lifecycle persistence was interrupted; recovery is required",
		{
			details: {
				cause: error instanceof Error ? error.message : String(error),
				...(error instanceof CtfError ? { code: error.code } : {}),
			},
		},
	);
}

function payloadString(payload: Record<string, unknown>, key: string): string | undefined {
	const value = payload[key];
	return typeof value === "string" ? value : undefined;
}

function payloadNumber(payload: Record<string, unknown>, key: string): number | undefined {
	const value = payload[key];
	return typeof value === "number" && Number.isInteger(value) ? value : undefined;
}

function requireEvidenceDigest(value: unknown): Digest {
	if (!isDigest(value)) throw new CtfError("digest_mismatch", "evaluation evidence receipt digest is invalid");
	return value;
}

/**
 * Create an auditable blocked run without pretending that a solver or oracle
 * exists. The run owner and lifecycle events remain durable for later resume.
 */
export async function createUnavailableRun(
	workspace: CtfWorkspace,
	challengeId: string,
	mode: CtfRunMode,
): Promise<UnavailableRunResult> {
	challengeExists(workspace, challengeId);
	validateRunMode(mode);
	const runId = randomUUID();
	const store = createCtfStateStore(workspace.stateRoot);
	const lease = new RunLeaseStore(store, {
		competitionId: workspace.manifest.competitionId,
		challengeId,
	});
	const owner = await lease.acquire({
		competitionId: workspace.manifest.competitionId,
		challengeId,
		runId,
		ownerId: "gjc-ctf-cli",
		processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
		state: "created",
	});
	await store.writeJsonAtomic(`runs/${runId}/owner.json`, owner);
	const eventLog = new CanonicalEventLog(store, {
		competitionId: workspace.manifest.competitionId,
		challengeId,
	});
	await eventLog.appendDraft({
		eventType: "run_created",
		competitionId: owner.competitionId,
		challengeId: owner.challengeId,
		runId,
		idempotencyKey: `${runId}:created`,
		actor: owner.ownerId,
		payload: { mode, fencingToken: owner.fencingToken, state: owner.state },
		evidenceRefs: [],
	});
	const running = await lease.transition(runId, owner.fencingToken, owner.ownerId, "running");
	await eventLog.appendDraft({
		eventType: "run_started",
		competitionId: running.competitionId,
		challengeId: running.challengeId,
		runId,
		idempotencyKey: `${runId}:started`,
		actor: running.ownerId,
		payload: { mode, fencingToken: running.fencingToken },
		evidenceRefs: [],
	});
	await store.writeJsonAtomic(`runs/${runId}/owner.json`, running);
	const terminalFence = running.fencingToken;
	try {
		// Append the canonical terminal event before sealing the lease. A crash can
		// therefore leave an active lease that resume can finish, but never a
		// terminal lease with no corresponding event.
		await eventLog.appendDraft({
			eventType: "run_terminal",
			competitionId: running.competitionId,
			challengeId: running.challengeId,
			runId,
			idempotencyKey: `${runId}:blocked`,
			actor: running.ownerId,
			payload: { mode, state: "blocked", reason: UNAVAILABLE_TERMINAL_REASON, fencingToken: terminalFence },
			evidenceRefs: [],
		});
		const blocked = await lease.transition(runId, terminalFence, running.ownerId, "blocked");
		await store.writeJsonAtomic(`runs/${runId}/owner.json`, blocked);
	} catch (error) {
		throw terminalPersistenceError(error);
	}
	return {
		schemaVersion: "ctf-run-result-1",
		status: "unavailable",
		runId,
		competitionId: workspace.manifest.competitionId,
		challengeId,
		mode,
		reason: UNAVAILABLE_RESULT_REASON,
	};
}
export type CtfEvidenceReceiptRecordingRequest = Readonly<{
	runId: string;
	challengeId: string;
	fencingToken: number;
	evidence: VerifiedEvaluationEvidenceV1;
}>;

async function persistEvidenceReceipt(
	store: CtfStateStore,
	runId: string,
	evidence: VerifiedEvaluationEvidenceV1,
): Promise<void> {
	const path = `runs/${runId}/evidence/${evidence.receiptDigest}.json`;
	await store.withLock(path, async () => {
		try {
			const existing = validateVerifiedEvaluationEvidence(
				JSON.parse(await fs.readFile(store.resolve(path), "utf8")),
			);
			if (existing.receiptDigest !== evidence.receiptDigest)
				throw new CtfError("integrity_error", "existing evidence receipt does not match its path");
			return;
		} catch (error) {
			if (typeof error !== "object" || error === null || !("code" in error) || error.code !== "ENOENT") throw error;
		}
		await store.writeJsonAtomic(path, evidence);
	});
}

async function readEvidenceReceipt(
	store: CtfStateStore,
	runId: string,
	receiptDigest: VerifiedEvaluationEvidenceV1["receiptDigest"],
): Promise<VerifiedEvaluationEvidenceV1 | undefined> {
	try {
		return validateVerifiedEvaluationEvidence(
			JSON.parse(await fs.readFile(store.resolve(`runs/${runId}/evidence/${receiptDigest}.json`), "utf8")),
		);
	} catch (error) {
		if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return undefined;
		throw error;
	}
}

/**
 * Attach already verified, anchored evaluation evidence under the live leader
 * fence. The resulting terminal state is deliberately blocked and unscored.
 */
export async function recordVerifiedEvaluationEvidence(
	workspace: CtfWorkspace,
	request: CtfEvidenceReceiptRecordingRequest,
): Promise<RunOwnerV1> {
	if (!request.runId.trim() || !request.challengeId.trim())
		throw new CtfError("invalid_api_request", "run id and challenge id are required");
	const evidence = validateVerifiedEvaluationEvidence(request.evidence);
	const receiptDigest = requireEvidenceDigest(evidence.receiptDigest);
	if (
		evidence.competitionId !== workspace.manifest.competitionId ||
		evidence.runId !== request.runId ||
		evidence.challengeId !== request.challengeId ||
		evidence.fencingToken !== request.fencingToken
	)
		throw new CtfError("cross_challenge_reference", "evidence receipt does not match the requested run fence");
	challengeExists(workspace, request.challengeId);
	const store = createCtfStateStore(workspace.stateRoot);
	const lease = new RunLeaseStore(store, {
		competitionId: workspace.manifest.competitionId,
		challengeId: request.challengeId,
	});
	const owner = await lease.read();
	if (
		owner === undefined ||
		owner.runId !== request.runId ||
		owner.competitionId !== evidence.competitionId ||
		owner.challengeId !== evidence.challengeId ||
		owner.fencingToken !== request.fencingToken
	)
		throw new CtfError("stale_run_fence", "evidence receipt is not bound to the live run leader");
	const eventLog = new CanonicalEventLog(store, {
		competitionId: owner.competitionId,
		challengeId: owner.challengeId,
	});
	if (owner.state === "blocked") {
		const existing = await readEvidenceReceipt(store, owner.runId, receiptDigest);
		const history = await eventLog.read();
		const terminal = history.events.find(
			event =>
				event.runId === owner.runId &&
				event.idempotencyKey === `${owner.runId}:verified-evidence-pending-score-authority`,
		);
		if (
			existing?.receiptDigest !== evidence.receiptDigest ||
			terminal?.payload.reason !== "verified_evidence_pending_score_authority" ||
			!terminal.evidenceRefs.includes(receiptDigest)
		)
			throw new CtfError("invalid_transition", "blocked run does not contain this evaluation evidence receipt");
		return owner;
	}
	if (owner.state !== "running")
		throw new CtfError("invalid_transition", "only a running leader lease can record evaluation evidence");
	const history = await eventLog.read();
	const started = history.events.find(event => event.runId === owner.runId && event.eventType === "run_started");
	const mode = started?.payload.mode;
	if (mode !== "competition" && mode !== "benchmark")
		throw new CtfError("integrity_error", "run has no valid started mode for evidence recording");
	await persistEvidenceReceipt(store, owner.runId, evidence);
	try {
		await eventLog.appendDraft({
			eventType: "run_heartbeat",
			competitionId: owner.competitionId,
			challengeId: owner.challengeId,
			runId: owner.runId,
			idempotencyKey: `${owner.runId}:evidence:${receiptDigest}`,
			actor: owner.ownerId,
			payload: {
				fencingToken: owner.fencingToken,
				receiptDigest,
				state: "running",
			},
			evidenceRefs: [receiptDigest],
		});
		await eventLog.appendDraft({
			eventType: "run_terminal",
			competitionId: owner.competitionId,
			challengeId: owner.challengeId,
			runId: owner.runId,
			idempotencyKey: `${owner.runId}:verified-evidence-pending-score-authority`,
			actor: owner.ownerId,
			payload: {
				mode,
				state: "blocked",
				reason: "verified_evidence_pending_score_authority",
				fencingToken: owner.fencingToken,
			},
			evidenceRefs: [receiptDigest],
		});
		const blocked = await lease.transition(owner.runId, owner.fencingToken, owner.ownerId, "blocked");
		await store.writeJsonAtomic(`runs/${owner.runId}/owner.json`, blocked);
		return blocked;
	} catch (error) {
		throw terminalPersistenceError(error);
	}
}

export type CtfSolverRunPreparationRequest = Readonly<{
	challengeId: string;
	runId: string;
	mode: CtfRunMode;
	backendId: string;
	signal?: AbortSignal;
}>;

function solverTerminal(outcome: CtfSolverOutcome): {
	state: "failed" | "blocked" | "aborted";
	reason: string;
} {
	switch (outcome.status) {
		case "candidate":
			return { state: "blocked", reason: "candidate_pending_trusted_oracle" };
		case "blocked":
			return { state: "blocked", reason: "solver_backend_blocked" };
		case "cancelled":
			return { state: "aborted", reason: "solver_run_cancelled" };
		case "failed":
			return { state: "failed", reason: "solver_backend_failed" };
	}
}

/**
 * Prepare one leader-owned solver run under a durable lease. Candidate output is
 * deliberately sealed as blocked until a trusted oracle promotes it.
 */
export async function prepareCtfSolverRun(
	workspace: CtfWorkspace,
	request: CtfSolverRunPreparationRequest,
): Promise<CtfPreparedRun> {
	challengeExists(workspace, request.challengeId);
	validateRunMode(request.mode);
	if (!request.runId.trim() || !request.backendId.trim())
		throw new CtfError("invalid_api_request", "solver run id and backend id are required");
	if (request.signal?.aborted) throw new CtfError("invalid_transition", "solver run preparation cancelled");
	const descriptor = workspace.manifest.challenges.find(challenge => challenge.id === request.challengeId);
	if (descriptor === undefined)
		throw new CtfError("invalid_manifest", "registered challenge descriptor is unavailable");
	const skill = await loadCtfSkillIdentity({
		competitionRoot: workspace.root,
		expected: workspace.manifest.skill,
	});
	const store = createCtfStateStore(workspace.stateRoot);
	const lease = new RunLeaseStore(store, {
		competitionId: workspace.manifest.competitionId,
		challengeId: request.challengeId,
	});
	const owner = await lease.acquire({
		competitionId: workspace.manifest.competitionId,
		challengeId: request.challengeId,
		runId: request.runId,
		ownerId: "gjc-ctf-scheduler",
		processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
		state: "created",
	});
	await store.writeJsonAtomic(`runs/${request.runId}/owner.json`, owner);
	const eventLog = new CanonicalEventLog(store, {
		competitionId: owner.competitionId,
		challengeId: owner.challengeId,
	});
	await eventLog.appendDraft({
		eventType: "run_created",
		competitionId: owner.competitionId,
		challengeId: owner.challengeId,
		runId: request.runId,
		idempotencyKey: `${request.runId}:created`,
		actor: owner.ownerId,
		payload: {
			mode: request.mode,
			backendId: request.backendId,
			fencingToken: owner.fencingToken,
			state: owner.state,
		},
		evidenceRefs: [],
	});
	const running = await lease.transition(request.runId, owner.fencingToken, owner.ownerId, "running");
	await eventLog.appendDraft({
		eventType: "run_started",
		competitionId: running.competitionId,
		challengeId: running.challengeId,
		runId: request.runId,
		idempotencyKey: `${request.runId}:started`,
		actor: running.ownerId,
		payload: { mode: request.mode, backendId: request.backendId, fencingToken: running.fencingToken },
		evidenceRefs: [],
	});
	await store.writeJsonAtomic(`runs/${request.runId}/owner.json`, running);
	let finalization: Promise<CtfSolverOutcome> | undefined;
	const finalize = (
		outcome: CtfSolverOutcome,
		context?: Readonly<{ signal: AbortSignal }>,
	): Promise<CtfSolverOutcome> => {
		if (finalization !== undefined) return finalization;
		finalization = (async () => {
			const effectiveOutcome: CtfSolverOutcome = context?.signal.aborted
				? { status: "cancelled", reason: "run cancelled or budget exhausted" }
				: outcome;
			const terminal = solverTerminal(effectiveOutcome);
			try {
				await eventLog.appendDraft({
					eventType: "run_terminal",
					competitionId: running.competitionId,
					challengeId: running.challengeId,
					runId: request.runId,
					idempotencyKey: `${request.runId}:terminal`,
					actor: running.ownerId,
					payload: {
						mode: request.mode,
						backendId: request.backendId,
						state: terminal.state,
						reason: terminal.reason,
						fencingToken: running.fencingToken,
					},
					evidenceRefs: [],
				});
				const terminalOwner = await lease.transition(
					request.runId,
					running.fencingToken,
					running.ownerId,
					terminal.state,
				);
				await store.writeJsonAtomic(`runs/${request.runId}/owner.json`, terminalOwner);
			} catch (error) {
				throw terminalPersistenceError(error);
			}
			return effectiveOutcome;
		})();
		return finalization;
	};
	const terminate = async (): Promise<void> => {
		await finalize({ status: "cancelled", reason: "run cancelled or budget exhausted" });
	};
	if (request.signal?.aborted) {
		await finalize({ status: "cancelled", reason: "run cancelled or budget exhausted" }, { signal: request.signal });
		throw new CtfError("invalid_transition", "solver run preparation cancelled");
	}
	return {
		authority: {
			fencingToken: running.fencingToken,
			intentId: `${request.runId}:leader-execution`,
			skillDigest: effectiveSkillDigest(skill),
			sandboxPolicyDigest: descriptor.safetyPolicyDigest,
		},
		finalize,
		terminate,
	};
}
export async function resumeUnavailableRun(workspace: CtfWorkspace, runId: string): Promise<UnavailableRunResult> {
	if (typeof runId !== "string" || !runId.trim()) throw new CtfError("invalid_transition", "run id is required");
	const store = createCtfStateStore(workspace.stateRoot);
	let owner: RunOwnerV1;
	try {
		const raw = await fs.readFile(store.resolve(`runs/${runId}/owner.json`), "utf8");
		owner = validateRunOwner(JSON.parse(raw));
	} catch (error) {
		if (error instanceof CtfError) throw error;
		throw new CtfError("integrity_error", `run owner is unavailable: ${runId}`);
	}
	if (owner.runId !== runId || owner.competitionId !== workspace.manifest.competitionId) {
		throw new CtfError("cross_challenge_reference", "run owner does not belong to this competition");
	}
	const eventLog = new CanonicalEventLog(store, {
		competitionId: owner.competitionId,
		challengeId: owner.challengeId,
	});
	const eventHistory = await eventLog.read();
	const runEvents = eventHistory.events.filter(event => event.runId === runId);
	if (runEvents.length === 0) {
		throw new CtfError("integrity_error", "run has no canonical lifecycle events; recovery is required");
	}
	const createdEvent = runEvents[0];
	const startedEvents = runEvents.filter(event => event.eventType === "run_started");
	const startedEvent = startedEvents[0];
	const startedIndex = startedEvent === undefined ? -1 : runEvents.indexOf(startedEvent);
	const terminalEvent = runEvents.at(-1);
	if (
		createdEvent?.eventType !== "run_created" ||
		startedEvents.length !== 1 ||
		startedIndex <= 0 ||
		terminalEvent?.eventType !== "run_terminal" ||
		terminalEvent === startedEvent
	) {
		throw new CtfError("integrity_error", "run lifecycle is incomplete or out of order; recovery is required");
	}
	if (
		runEvents.slice(1, -1).some(event => event.eventType === "run_created") ||
		runEvents.slice(0, -1).some(event => event.eventType === "run_terminal")
	) {
		throw new CtfError("integrity_error", "run lifecycle contains multiple terminal or creation events");
	}
	if (
		createdEvent.actor !== owner.ownerId ||
		startedEvent.actor !== owner.ownerId ||
		terminalEvent.actor !== owner.ownerId
	) {
		throw new CtfError("integrity_error", "run lifecycle actors do not match the durable owner");
	}
	const createdFence = payloadNumber(createdEvent.payload, "fencingToken");
	const startedFence = payloadNumber(startedEvent.payload, "fencingToken");
	const terminalFence = payloadNumber(terminalEvent.payload, "fencingToken");
	if (
		createdFence !== owner.fencingToken ||
		startedFence !== owner.fencingToken ||
		terminalFence !== owner.fencingToken
	) {
		throw new CtfError("stale_run_fence", "run lifecycle events are not bound to the current owner fence");
	}
	if (createdEvent.payload.state !== "created") {
		throw new CtfError("integrity_error", "run creation event has no created state");
	}
	if (owner.state !== "running" && owner.state !== "blocked") {
		throw new CtfError("integrity_error", "unavailable run owner is not in a recoverable blocked lifecycle state");
	}
	if (terminalEvent.payload.state !== "blocked") {
		throw new CtfError("integrity_error", "unavailable run terminal event is not blocked");
	}
	const terminalReason = payloadString(terminalEvent.payload, "reason");
	if (terminalReason !== UNAVAILABLE_TERMINAL_REASON) {
		throw new CtfError("integrity_error", "unavailable run terminal event has an unexpected reason");
	}
	const mode = terminalEvent.payload.mode;
	if (mode !== "competition" && mode !== "benchmark") {
		throw new CtfError("integrity_error", "run terminal event has no valid mode");
	}
	if (createdEvent.payload.mode !== mode || startedEvent.payload.mode !== mode) {
		throw new CtfError("integrity_error", "run lifecycle events disagree on run mode");
	}
	const lease = new RunLeaseStore(store, {
		competitionId: owner.competitionId,
		challengeId: owner.challengeId,
	});
	let durableOwner: RunOwnerV1;
	try {
		const currentLease = await lease.read();
		if (!currentLease || currentLease.runId !== runId) {
			throw new CtfError("integrity_error", "run lease is unavailable during terminal recovery");
		}
		if (currentLease.ownerId !== owner.ownerId || currentLease.fencingToken !== owner.fencingToken) {
			throw new CtfError("stale_run_fence", "run lease and owner file do not share the current fence");
		}
		if (currentLease.fencingToken !== terminalEvent.payload.fencingToken) {
			throw new CtfError("stale_run_fence", "run terminal event is not bound to the current lease fence");
		}
		if (currentLease.state === "running") {
			durableOwner = await lease.transition(runId, currentLease.fencingToken, currentLease.ownerId, "blocked");
		} else if (currentLease.state === "blocked") {
			durableOwner = currentLease;
		} else {
			throw new CtfError("integrity_error", "run lease is not in a recoverable blocked lifecycle state");
		}
		if (owner.state !== "blocked") {
			await store.writeJsonAtomic(`runs/${runId}/owner.json`, durableOwner);
		}
	} catch (error) {
		throw terminalPersistenceError(error);
	}
	challengeExists(workspace, durableOwner.challengeId);
	return {
		schemaVersion: "ctf-run-result-1",
		status: "unavailable",
		runId,
		competitionId: durableOwner.competitionId,
		challengeId: durableOwner.challengeId,
		mode,
		reason: `run is ${durableOwner.state}; durable solver resume is not configured`,
	};
}
