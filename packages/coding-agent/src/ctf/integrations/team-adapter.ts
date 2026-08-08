import { executeGjcTeamApiOperation } from "../../gjc-runtime/team-runtime";
import { CtfError, canonicalDigest, digestsEqual, isDigest, sha256Hex } from "../contracts";

/** The small, typed surface the CTF runtime is allowed to use for GJC teams. */
export type CtfTeamApiExecutor = (
	operation: string,
	input: Record<string, unknown>,
	cwd?: string,
	env?: NodeJS.ProcessEnv,
) => Promise<unknown>;

export interface CtfTeamAdapterOptions {
	cwd?: string;
	env?: NodeJS.ProcessEnv;
	execute?: CtfTeamApiExecutor;
	clock?: () => string;
}

export interface CtfTeamClaimRequest {
	teamName: string;
	workerId: string;
	taskId?: string;
}

export interface CtfTeamClaimEvidence {
	kind: "claim";
	teamName: string;
	workerId: string;
	taskId: string;
	claimToken: string;
	observedAt: string;
	evidenceDigest: string;
}

export interface CtfTeamStartupRequest {
	teamName: string;
	workerId: string;
	protocolVersion?: string;
	pid?: number;
	session?: string;
}

export interface CtfTeamStartupEvidence {
	kind: "startup";
	teamName: string;
	workerId: string;
	protocolVersion: string;
	ackAt: string;
	evidenceDigest: string;
}

export interface CtfTeamCompletionEvidenceItem {
	kind: "command" | "inspection" | "artifact";
	status: "passed" | "verified" | "failed" | "unknown";
	summary: string;
	command?: string;
}

export interface CtfTeamCompletionEvidence {
	summary: string;
	items: readonly CtfTeamCompletionEvidenceItem[];
	files?: readonly string[];
	notes?: string;
}

export interface CtfTeamCompletionRequest {
	teamName: string;
	workerId: string;
	taskId: string;
	claimToken: string;
	completionEvidence: CtfTeamCompletionEvidence;
}

export interface CtfTeamCompletionReceipt {
	kind: "completion";
	teamName: string;
	workerId: string;
	taskId: string;
	status: "completed";
	completionEvidenceDigest: string;
	observedAt: string;
	evidenceDigest: string;
}

export interface CtfTeamMonitorRequest {
	teamName: string;
	workerId?: string;
}

export interface CtfTeamMonitorEvidence {
	kind: "monitor";
	teamName: string;
	phase: "starting" | "running" | "awaiting_integration" | "complete" | "failed" | "cancelled";
	observedAt: string;
	taskCounts: {
		pending: number;
		inProgress: number;
		completed: number;
		failed: number;
		blocked: number;
	};
	worker?: {
		id: string;
		status: string;
		heartbeatObserved: boolean;
	};
	monitorDigest: string;
	evidenceDigest: string;
}

export type CtfTeamVerificationDisposition = "confirmed" | "refuted" | "blocked";

export interface CtfTeamVerificationRequest {
	teamName: string;
	workerId?: string;
	taskId?: string;
	claimToken?: string;
	disposition?: CtfTeamVerificationDisposition;
	outcome?: CtfTeamVerificationDisposition;
	summary: string;
	observations: readonly string[];
	sourceDigest?: string;
}

export interface CtfTeamVerificationEvidence {
	kind: "verification";
	teamName: string;
	workerId?: string;
	taskId?: string;
	disposition: CtfTeamVerificationDisposition;
	summary: string;
	observations: readonly string[];
	sourceDigest: string;
	observedAt: string;
	evidenceDigest: string;
}

export interface CtfTeamPreflightEvidence {
	kind: "preflight";
	passed: true;
	summary: string;
	checks: readonly string[];
	evidenceDigest: string;
}

export interface CtfTeamIndependenceEvidence {
	kind: "independence";
	independent: true;
	summary: string;
	sources: readonly string[];
	evidenceDigest: string;
}

export interface CtfTeamInformationGainEvidence {
	kind: "information_gain";
	gain: number;
	summary: string;
	evidenceDigest: string;
}

export interface CtfTeamPromotionRequest {
	teamName: string;
	workerId?: string;
	taskId?: string;
	verification: CtfTeamVerificationEvidence | CtfTeamVerificationRequest;
	preflight: CtfTeamPreflightEvidence;
	independence: CtfTeamIndependenceEvidence;
	informationGain: CtfTeamInformationGainEvidence;
}

export type CtfTeamPromotionRejection =
	| "preflight_required"
	| "preflight_invalid"
	| "independence_required"
	| "independence_invalid"
	| "information_gain_required"
	| "information_gain_invalid"
	| "verification_required"
	| "verification_refuted"
	| "verification_blocked"
	| "verification_invalid"
	| "stale_claim"
	| "identity_mismatch";

export type CtfTeamPromotionDecision =
	| {
			promoted: true;
			teamName: string;
			workerId?: string;
			taskId?: string;
			verificationDigest: string;
			promotionDigest: string;
			evidenceDigest: string;
	  }
	| {
			promoted: false;
			teamName: string;
			reason: CtfTeamPromotionRejection;
			evidenceDigest: string;
	  };

export type CtfTeamTerminalState = "completed" | "failed" | "blocked" | "cancelled";

export type CtfTeamTerminationReason =
	| "completed"
	| "failed"
	| "blocked"
	| "cancelled"
	| "budget_exhausted"
	| "no_progress";

export interface CtfTeamTerminalRequest {
	teamName: string;
	workerId?: string;
	taskId?: string;
	reason: CtfTeamTerminationReason;
	summary: string;
	evidence: readonly string[];
	budget?: { used: number; limit: number };
	progress?: { beforeDigest: string; afterDigest: string; observations: readonly string[] };
}

export interface CtfTeamTerminalLifecycleEvidence {
	kind: "terminal";
	teamName: string;
	workerId?: string;
	taskId?: string;
	state: CtfTeamTerminalState;
	reason: CtfTeamTerminationReason;
	summary: string;
	evidence: readonly string[];
	sourceDigest: string;
	observedAt: string;
	evidenceDigest: string;
}
export type CtfTeamTerminalDecision = CtfTeamTerminalLifecycleEvidence;

export interface CtfTeamStaleClaimRequeueRequest {
	teamName: string;
	workerId: string;
	taskId: string;
	claimToken?: string;
	summary?: string;
}

export interface CtfTeamStaleClaimRequeueEvidence {
	kind: "stale_claim_requeue";
	teamName: string;
	workerId: string;
	taskId: string;
	requeued: true;
	observedAt: string;
	sourceDigest: string;
	evidenceDigest: string;
}

export interface CtfTeamAdapter {
	claim(request: CtfTeamClaimRequest): Promise<CtfTeamClaimEvidence>;
	startup(request: CtfTeamStartupRequest): Promise<CtfTeamStartupEvidence>;
	complete(request: CtfTeamCompletionRequest): Promise<CtfTeamCompletionReceipt>;
	monitor(request: CtfTeamMonitorRequest): Promise<CtfTeamMonitorEvidence>;
	verify(request: CtfTeamVerificationRequest): Promise<CtfTeamVerificationEvidence>;
	promote(request: CtfTeamPromotionRequest): Promise<CtfTeamPromotionDecision>;
	terminate(request: CtfTeamTerminalRequest): Promise<CtfTeamTerminalDecision>;
	requeueStaleClaim(request: CtfTeamStaleClaimRequeueRequest): Promise<CtfTeamStaleClaimRequeueEvidence>;
	requeue(request: CtfTeamStaleClaimRequeueRequest): Promise<CtfTeamStaleClaimRequeueEvidence>;
	recoverStaleClaim(request: CtfTeamStaleClaimRequeueRequest): Promise<CtfTeamStaleClaimRequeueEvidence>;
	confirm(request: Omit<CtfTeamVerificationRequest, "disposition" | "outcome">): Promise<CtfTeamVerificationEvidence>;
	refute(request: Omit<CtfTeamVerificationRequest, "disposition" | "outcome">): Promise<CtfTeamVerificationEvidence>;
	block(request: Omit<CtfTeamVerificationRequest, "disposition" | "outcome">): Promise<CtfTeamVerificationEvidence>;
}

function record(value: unknown, label: string): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new CtfError("integrity_error", `${label} response is not an object`);
	}
	return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string): string {
	if (typeof value !== "string" || value.trim().length === 0)
		throw new CtfError("invalid_api_request", `${label} is required`);
	return value.trim();
}

function validTimestamp(value: unknown, label: string): string {
	const result = requiredString(value, label);
	if (!Number.isFinite(Date.parse(result))) throw new CtfError("integrity_error", `${label} is not a timestamp`);
	return result;
}

function assertRequestId(value: string, label: string): void {
	if (value.includes("/") || value.includes("\\") || value.includes("..")) {
		throw new CtfError("invalid_api_request", `${label} contains an unsafe path component`);
	}
}

function completionEvidence(value: CtfTeamCompletionEvidence): CtfTeamCompletionEvidence {
	if (!value || typeof value !== "object" || typeof value.summary !== "string" || value.summary.trim().length === 0) {
		throw new CtfError("missing_evidence", "team completion requires a non-empty evidence summary");
	}
	if (!Array.isArray(value.items) || value.items.length === 0) {
		throw new CtfError("missing_evidence", "team completion requires evidence items");
	}
	let verified = false;
	const items = value.items.map(item => {
		if (!item || typeof item !== "object")
			throw new CtfError("missing_evidence", "team completion contains an invalid evidence item");
		const candidate = item as CtfTeamCompletionEvidenceItem;
		if (
			!["command", "inspection", "artifact"].includes(candidate.kind) ||
			!["passed", "verified", "failed", "unknown"].includes(candidate.status) ||
			typeof candidate.summary !== "string" ||
			candidate.summary.trim().length === 0
		) {
			throw new CtfError("missing_evidence", "team completion contains an invalid evidence item");
		}
		if (
			candidate.kind === "command" &&
			(typeof candidate.command !== "string" || candidate.command.trim().length === 0)
		) {
			throw new CtfError("missing_evidence", "command evidence requires its command");
		}
		if (candidate.status === "passed" || candidate.status === "verified") verified = true;
		return {
			kind: candidate.kind,
			status: candidate.status,
			summary: candidate.summary.trim(),
			...(candidate.command ? { command: candidate.command.trim() } : {}),
		};
	});
	if (!verified) throw new CtfError("missing_evidence", "team completion requires passed or verified evidence");
	return {
		summary: value.summary.trim(),
		items,
		...(value.files ? { files: [...value.files] } : {}),
		...(value.notes ? { notes: value.notes } : {}),
	};
}

function ctfFailure(message: string, details?: Record<string, unknown>): never {
	throw new CtfError("stale_claim", message, details ? { details } : undefined);
}

function phaseOf(value: unknown): CtfTeamMonitorEvidence["phase"] {
	const phase = record(value, "monitor").phase;
	if (
		phase === "starting" ||
		phase === "running" ||
		phase === "awaiting_integration" ||
		phase === "complete" ||
		phase === "failed" ||
		phase === "cancelled"
	)
		return phase;
	throw new CtfError("integrity_error", "monitor response has no valid team phase");
}

function taskStatus(value: unknown): "pending" | "in_progress" | "completed" | "failed" | "blocked" {
	if (
		value === "pending" ||
		value === "in_progress" ||
		value === "completed" ||
		value === "failed" ||
		value === "blocked"
	)
		return value;
	throw new CtfError("integrity_error", "team task has an invalid status");
}

function taskHasVerifiedCompletionEvidence(value: unknown): boolean {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const evidence = (value as Record<string, unknown>).completion_evidence;
	if (typeof evidence !== "object" || evidence === null || Array.isArray(evidence)) return false;
	const items = (evidence as Record<string, unknown>).items;
	return (
		Array.isArray(items) &&
		items.some(item => {
			if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
			const status = (item as Record<string, unknown>).status;
			return status === "passed" || status === "verified";
		})
	);
}

function evidenceStrings(value: unknown, label: string): string[] {
	if (
		!Array.isArray(value) ||
		value.length === 0 ||
		value.some(item => typeof item !== "string" || item.trim().length === 0)
	) {
		throw new CtfError("missing_evidence", `${label} requires non-empty evidence`);
	}
	return value.map(item => item.trim());
}

function evidenceDigestBound<T extends Record<string, unknown>>(value: T, label: string): T {
	const supplied = value.evidenceDigest;
	if (!isDigest(supplied) || !digestsEqual(sha256Hex(canonicalDigest(value, ["evidenceDigest"])), supplied)) {
		throw new CtfError("digest_mismatch", `${label} evidence digest does not match its content`);
	}
	return value;
}

function normalizedVerificationDisposition(request: CtfTeamVerificationRequest): CtfTeamVerificationDisposition {
	const disposition = request.disposition ?? request.outcome;
	if (disposition !== "confirmed" && disposition !== "refuted" && disposition !== "blocked") {
		throw new CtfError(
			"invalid_api_request",
			"team verification requires confirmation, refutation, or block disposition",
		);
	}
	if (request.disposition !== undefined && request.outcome !== undefined && request.disposition !== request.outcome) {
		throw new CtfError("invalid_api_request", "team verification disposition and outcome disagree");
	}
	return disposition;
}

function normalizedVerificationEvidence(value: CtfTeamVerificationEvidence): CtfTeamVerificationEvidence {
	const teamName = requiredString(value.teamName, "verification teamName");
	const workerId = value.workerId === undefined ? undefined : requiredString(value.workerId, "verification workerId");
	const taskId = value.taskId === undefined ? undefined : requiredString(value.taskId, "verification taskId");
	if (workerId) assertRequestId(workerId, "workerId");
	if (taskId) assertRequestId(taskId, "taskId");
	const disposition = normalizedVerificationDisposition(value);
	const summary = requiredString(value.summary, "verification summary");
	const observations = evidenceStrings(value.observations, "verification");
	const sourceDigest = requiredString(value.sourceDigest, "verification sourceDigest");
	if (!isDigest(sourceDigest))
		throw new CtfError("invalid_digest", "verification sourceDigest is not a SHA-256 digest");
	const normalized = {
		kind: "verification" as const,
		teamName,
		...(workerId ? { workerId } : {}),
		...(taskId ? { taskId } : {}),
		disposition,
		summary,
		observations,
		sourceDigest,
		observedAt: validTimestamp(value.observedAt, "verification observedAt"),
		evidenceDigest: value.evidenceDigest,
	};
	evidenceDigestBound(normalized, "verification");
	return normalized;
}

function normalizedPreflightEvidence(value: CtfTeamPreflightEvidence): CtfTeamPreflightEvidence {
	if (value?.kind !== "preflight" || value.passed !== true) {
		throw new CtfError("missing_provenance", "team promotion requires a passed preflight");
	}
	const summary = requiredString(value.summary, "preflight summary");
	const checks = evidenceStrings(value.checks, "preflight");
	const normalized = {
		kind: "preflight" as const,
		passed: true as const,
		summary,
		checks,
		evidenceDigest: value.evidenceDigest,
	};
	evidenceDigestBound(normalized, "preflight");
	return normalized;
}

function normalizedIndependenceEvidence(value: CtfTeamIndependenceEvidence): CtfTeamIndependenceEvidence {
	if (value?.kind !== "independence" || value.independent !== true) {
		throw new CtfError("missing_provenance", "team promotion requires independent evidence");
	}
	const summary = requiredString(value.summary, "independence summary");
	const sources = evidenceStrings(value.sources, "independence");
	const normalized = {
		kind: "independence" as const,
		independent: true as const,
		summary,
		sources,
		evidenceDigest: value.evidenceDigest,
	};
	evidenceDigestBound(normalized, "independence");
	return normalized;
}

function normalizedInformationGainEvidence(value: CtfTeamInformationGainEvidence): CtfTeamInformationGainEvidence {
	if (
		value?.kind !== "information_gain" ||
		typeof value.gain !== "number" ||
		!Number.isFinite(value.gain) ||
		value.gain <= 0
	) {
		throw new CtfError("missing_evidence", "team promotion requires positive information gain");
	}
	const summary = requiredString(value.summary, "information gain summary");
	const normalized = {
		kind: "information_gain" as const,
		gain: value.gain,
		summary,
		evidenceDigest: value.evidenceDigest,
	};
	evidenceDigestBound(normalized, "information gain");
	return normalized;
}

function terminalStateForReason(reason: CtfTeamTerminationReason): CtfTeamTerminalState {
	if (reason === "completed") return "completed";
	if (reason === "failed" || reason === "budget_exhausted" || reason === "no_progress") return "failed";
	if (reason === "blocked") return "blocked";
	return "cancelled";
}

function assertTerminalRequest(request: CtfTeamTerminalRequest): {
	reason: CtfTeamTerminationReason;
	summary: string;
	evidence: string[];
} {
	const reason = request.reason;
	if (
		reason !== "completed" &&
		reason !== "failed" &&
		reason !== "blocked" &&
		reason !== "cancelled" &&
		reason !== "budget_exhausted" &&
		reason !== "no_progress"
	) {
		throw new CtfError("invalid_api_request", "team termination requires a terminal reason");
	}
	const summary = requiredString(request.summary, "terminal summary");
	const evidence = evidenceStrings(request.evidence, "terminal");
	if (reason === "budget_exhausted") {
		const budget = request.budget;
		if (
			!budget ||
			!Number.isInteger(budget.used) ||
			!Number.isInteger(budget.limit) ||
			budget.used < 0 ||
			budget.limit <= 0 ||
			budget.used < budget.limit
		) {
			throw new CtfError(
				"invalid_api_request",
				"budget termination requires used budget at or above its positive limit",
			);
		}
	}
	if (reason === "no_progress") {
		const progress = request.progress;
		if (
			!progress ||
			!isDigest(progress.beforeDigest) ||
			!isDigest(progress.afterDigest) ||
			!digestsEqual(progress.beforeDigest, progress.afterDigest)
		) {
			throw new CtfError(
				"invalid_api_request",
				"no-progress termination requires equal before and after progress digests",
			);
		}
		evidenceStrings(progress.observations, "no-progress");
	}
	return { reason, summary, evidence };
}
export const validateCtfTeamVerificationEvidence = normalizedVerificationEvidence;
export const validateCtfTeamPreflightEvidence = normalizedPreflightEvidence;
export const validateCtfTeamIndependenceEvidence = normalizedIndependenceEvidence;
export const validateCtfTeamInformationGainEvidence = normalizedInformationGainEvidence;
export const validateCtfTeamTerminalRequest = assertTerminalRequest;

/**
 * Adapt the existing GJC team API without creating a second team runtime. The
 * adapter only returns evidence after validating the API's persisted receipts.
 */
export function createCtfTeamAdapter(options: CtfTeamAdapterOptions = {}): CtfTeamAdapter {
	const cwd = options.cwd ?? process.cwd();
	const env = options.env ?? process.env;
	const execute = options.execute ?? executeGjcTeamApiOperation;
	const clock = options.clock ?? (() => new Date().toISOString());
	const call = (operation: string, input: Record<string, unknown>) => execute(operation, input, cwd, env);
	const callChecked = async (operation: string, input: Record<string, unknown>): Promise<unknown> => {
		try {
			return await call(operation, input);
		} catch (error) {
			if (error instanceof CtfError) throw error;
			const message = error instanceof Error ? error.message.toLowerCase() : "";
			if (
				operation === "claim-task" ||
				operation === "transition-task-status" ||
				message.includes("claim") ||
				message.includes("lease") ||
				message.includes("stale")
			) {
				throw new CtfError("stale_claim", "GJC team claim operation was rejected");
			}
			throw new CtfError("integrity_error", "GJC team API operation was rejected");
		}
	};
	const monitorEvidence = async (request: CtfTeamMonitorRequest): Promise<CtfTeamMonitorEvidence> => {
		const teamName = requiredString(request.teamName, "teamName");
		const snapshot = record(await callChecked("read-monitor-snapshot", { team_name: teamName }), "monitor snapshot");
		const taskResult = record(await callChecked("list-tasks", { team_name: teamName }), "team tasks");
		if (!Array.isArray(taskResult.tasks)) throw new CtfError("integrity_error", "team task list is missing");
		const counts = { pending: 0, inProgress: 0, completed: 0, failed: 0, blocked: 0 };
		for (const task of taskResult.tasks) {
			const status = taskStatus(record(task, "team task").status);
			if (status === "pending") counts.pending += 1;
			if (status === "in_progress") counts.inProgress += 1;
			if (status === "completed") {
				counts.completed += 1;
				if (!taskHasVerifiedCompletionEvidence(task))
					throw new CtfError("missing_evidence", "completed team task has no verified completion evidence");
			}
			if (status === "failed") counts.failed += 1;
			if (status === "blocked") counts.blocked += 1;
		}
		const workerId = request.workerId?.trim();
		let worker: CtfTeamMonitorEvidence["worker"];
		if (workerId) {
			assertRequestId(workerId, "workerId");
			const status = record(
				await callChecked("read-worker-status", { team_name: teamName, worker_id: workerId }),
				"worker status",
			);
			const heartbeat = await callChecked("read-worker-heartbeat", { team_name: teamName, worker_id: workerId });
			worker = {
				id: workerId,
				status: requiredString(status.state, "worker status"),
				heartbeatObserved: heartbeat !== null && heartbeat !== undefined,
			};
		}
		const evidenceBase = {
			kind: "monitor" as const,
			teamName,
			phase: phaseOf(snapshot),
			observedAt: clock(),
			taskCounts: counts,
			...(worker ? { worker } : {}),
			monitorDigest: canonicalDigest({ snapshot, tasks: taskResult.tasks }),
		};
		return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
	};

	return {
		async claim(request) {
			const teamName = requiredString(request.teamName, "teamName");
			const workerId = requiredString(request.workerId, "workerId");
			assertRequestId(workerId, "workerId");
			const taskId = request.taskId === undefined ? undefined : requiredString(request.taskId, "taskId");
			if (taskId) assertRequestId(taskId, "taskId");
			const result = record(
				await callChecked("claim-task", {
					team_name: teamName,
					worker_id: workerId,
					...(taskId ? { task_id: taskId } : {}),
				}),
				"claim",
			);
			if (result.ok !== true) ctfFailure("GJC team refused the task claim");
			if (requiredString(result.worker_id, "claim worker_id") !== workerId)
				ctfFailure("GJC team returned a claim for another worker");
			if (result.status !== "in_progress") ctfFailure("GJC team claim is not in progress");
			const claimedTaskId = requiredString(result.task_id, "claim task_id");
			const claimToken = requiredString(result.claim_token, "claim claim_token");
			if (taskId && claimedTaskId !== taskId) ctfFailure("GJC team returned a different task claim");
			const evidenceBase = {
				kind: "claim" as const,
				teamName,
				workerId,
				taskId: claimedTaskId,
				claimToken,
				observedAt: clock(),
			};
			return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
		},

		async startup(request) {
			const teamName = requiredString(request.teamName, "teamName");
			const workerId = requiredString(request.workerId, "workerId");
			assertRequestId(workerId, "workerId");
			const protocolVersion = request.protocolVersion?.trim() || "1";
			const result = record(
				await callChecked("worker-startup-ack", {
					team_name: teamName,
					worker_id: workerId,
					protocol_version: protocolVersion,
					...(request.pid === undefined ? {} : { pid: request.pid }),
					...(request.session === undefined ? {} : { session: request.session }),
				}),
				"startup",
			);
			if (requiredString(result.worker, "startup worker") !== workerId)
				ctfFailure("GJC startup ACK belongs to another worker");
			if (requiredString(result.protocol_version, "startup protocol_version") !== protocolVersion)
				ctfFailure("GJC startup protocol version disagrees");
			const ackAt = validTimestamp(result.ack_at, "startup ack_at");
			const evidenceBase = { kind: "startup" as const, teamName, workerId, protocolVersion, ackAt };
			return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
		},

		async complete(request) {
			const teamName = requiredString(request.teamName, "teamName");
			const workerId = requiredString(request.workerId, "workerId");
			const taskId = requiredString(request.taskId, "taskId");
			const claimToken = requiredString(request.claimToken, "claimToken");
			assertRequestId(workerId, "workerId");
			assertRequestId(taskId, "taskId");
			const evidence = completionEvidence(request.completionEvidence);
			const completionEvidenceDigest = canonicalDigest(evidence);
			const result = record(
				await callChecked("transition-task-status", {
					team_name: teamName,
					task_id: taskId,
					to: "completed",
					worker_id: workerId,
					claim_token: claimToken,
					completion_evidence: evidence,
				}),
				"completion",
			);
			if (result.worker_id !== undefined && requiredString(result.worker_id, "completion worker_id") !== workerId) {
				ctfFailure("GJC team completion belongs to another worker");
			}
			if (
				result.ok !== true ||
				result.status !== "completed" ||
				requiredString(result.task_id, "completion task_id") !== taskId
			) {
				ctfFailure("GJC team did not return a completed task receipt");
			}
			const persistedResult = record(
				await callChecked("read-task", { team_name: teamName, task_id: taskId }),
				"completion task",
			);
			const persistedTask = record(persistedResult.task, "completion task");
			if (persistedTask.status !== "completed" || !taskHasVerifiedCompletionEvidence(persistedTask)) {
				throw new CtfError("missing_evidence", "GJC team completion was not persisted with verified evidence");
			}
			const evidenceBase = {
				kind: "completion" as const,
				teamName,
				workerId,
				taskId,
				status: "completed" as const,
				completionEvidenceDigest,
				observedAt: clock(),
			};
			return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
		},

		async monitor(request) {
			return monitorEvidence(request);
		},

		async verify(request) {
			const teamName = requiredString(request.teamName, "teamName");
			const workerId = request.workerId === undefined ? undefined : requiredString(request.workerId, "workerId");
			const taskId = request.taskId === undefined ? undefined : requiredString(request.taskId, "taskId");
			if (workerId) assertRequestId(workerId, "workerId");
			if (taskId) assertRequestId(taskId, "taskId");
			const disposition = normalizedVerificationDisposition(request);
			const summary = requiredString(request.summary, "verification summary");
			const observations = evidenceStrings(request.observations, "verification");
			const monitor = await monitorEvidence({ teamName, ...(workerId ? { workerId } : {}) });
			let task: Record<string, unknown> | undefined;
			if (taskId) {
				const taskResult = record(
					await callChecked("read-task", { team_name: teamName, task_id: taskId }),
					"verification task",
				);
				task = record(taskResult.task, "verification task");
				if (requiredString(task.id, "verification task id") !== taskId) {
					throw new CtfError("integrity_error", "verification task receipt names another task");
				}
				if (workerId && task.claim !== undefined) {
					const claim = record(task.claim, "verification claim");
					if (requiredString(claim.owner, "verification claim owner") !== workerId)
						ctfFailure("verification claim belongs to another worker");
					if (
						request.claimToken !== undefined &&
						requiredString(claim.token, "verification claim token") !== request.claimToken
					) {
						ctfFailure("verification claim token is stale");
					}
				}
			}
			if (
				disposition === "confirmed" &&
				(task?.status !== "completed" || !taskHasVerifiedCompletionEvidence(task))
			) {
				throw new CtfError(
					"missing_evidence",
					"confirmation requires a persisted completed task with verified evidence",
				);
			}
			if (disposition === "refuted" && task && task.status !== "failed") {
				throw new CtfError("integrity_error", "refutation requires a persisted failed task");
			}
			if (disposition === "blocked" && task && task.status !== "blocked") {
				throw new CtfError("integrity_error", "block requires a persisted blocked task");
			}
			const sourceDigest = canonicalDigest({ monitor, task: task ?? null });
			if (request.sourceDigest !== undefined) {
				if (!isDigest(request.sourceDigest) || !digestsEqual(request.sourceDigest, sourceDigest)) {
					throw new CtfError(
						"digest_mismatch",
						"verification source digest does not match the observed team state",
					);
				}
			}
			const evidenceBase = {
				kind: "verification" as const,
				teamName,
				...(workerId ? { workerId } : {}),
				...(taskId ? { taskId } : {}),
				disposition,
				summary,
				observations,
				sourceDigest,
				observedAt: clock(),
			};
			return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
		},

		async promote(request) {
			const teamName = requiredString(request.teamName, "promotion teamName");
			const rejection = (reason: CtfTeamPromotionRejection): CtfTeamPromotionDecision => {
				const base = { promoted: false as const, teamName, reason };
				return { ...base, evidenceDigest: sha256Hex(canonicalDigest(base)) };
			};
			if (!request.preflight) return rejection("preflight_required");
			if (!request.independence) return rejection("independence_required");
			if (!request.informationGain) return rejection("information_gain_required");
			if (!request.verification) return rejection("verification_required");
			let preflight: CtfTeamPreflightEvidence;
			let independence: CtfTeamIndependenceEvidence;
			let informationGain: CtfTeamInformationGainEvidence;
			try {
				preflight = normalizedPreflightEvidence(request.preflight);
			} catch {
				return rejection("preflight_invalid");
			}
			try {
				independence = normalizedIndependenceEvidence(request.independence);
			} catch {
				return rejection("independence_invalid");
			}
			try {
				informationGain = normalizedInformationGainEvidence(request.informationGain);
			} catch {
				return rejection("information_gain_invalid");
			}
			let verification: CtfTeamVerificationEvidence;
			try {
				verification =
					"kind" in request.verification
						? normalizedVerificationEvidence(request.verification as CtfTeamVerificationEvidence)
						: await this.verify(request.verification as CtfTeamVerificationRequest);
			} catch (error) {
				if (error instanceof CtfError && error.code === "stale_claim") return rejection("stale_claim");
				return rejection("verification_invalid");
			}
			if (
				verification.teamName !== teamName ||
				(request.workerId !== undefined && verification.workerId !== request.workerId) ||
				(request.taskId !== undefined && verification.taskId !== request.taskId)
			) {
				return rejection("identity_mismatch");
			}
			if (verification.disposition === "refuted") return rejection("verification_refuted");
			if (verification.disposition === "blocked") return rejection("verification_blocked");
			if (verification.disposition !== "confirmed") return rejection("verification_invalid");
			const promotionBase = {
				teamName,
				...(request.workerId ? { workerId: request.workerId } : {}),
				...(request.taskId ? { taskId: request.taskId } : {}),
				verificationDigest: verification.evidenceDigest,
				preflightDigest: preflight.evidenceDigest,
				independenceDigest: independence.evidenceDigest,
				informationGainDigest: informationGain.evidenceDigest,
			};
			const promotionDigest = sha256Hex(canonicalDigest(promotionBase));
			const promotedBase = { promoted: true as const, ...promotionBase, promotionDigest };
			return {
				...promotedBase,
				evidenceDigest: sha256Hex(canonicalDigest(promotedBase)),
			};
		},

		async terminate(request) {
			const teamName = requiredString(request.teamName, "terminal teamName");
			const workerId = request.workerId === undefined ? undefined : requiredString(request.workerId, "workerId");
			const taskId = request.taskId === undefined ? undefined : requiredString(request.taskId, "taskId");
			if (workerId) assertRequestId(workerId, "workerId");
			if (taskId) assertRequestId(taskId, "taskId");
			const { reason, summary, evidence } = assertTerminalRequest(request);
			const monitor = await monitorEvidence({ teamName, ...(workerId ? { workerId } : {}) });
			if (
				reason === "completed" &&
				(monitor.phase !== "complete" ||
					monitor.taskCounts.completed === 0 ||
					monitor.taskCounts.pending > 0 ||
					monitor.taskCounts.inProgress > 0 ||
					monitor.taskCounts.failed > 0 ||
					monitor.taskCounts.blocked > 0)
			) {
				throw new CtfError("integrity_error", "completed termination requires a terminal complete team snapshot");
			}
			if (reason === "failed" && monitor.phase !== "failed") {
				throw new CtfError("integrity_error", "failed termination requires a failed team snapshot");
			}
			if (reason === "blocked" && monitor.taskCounts.blocked === 0 && monitor.phase !== "failed") {
				throw new CtfError("integrity_error", "blocked termination requires blocked task evidence");
			}
			if (reason === "cancelled" && monitor.phase !== "cancelled") {
				throw new CtfError("integrity_error", "cancelled termination requires a cancelled team snapshot");
			}
			const evidenceBase = {
				kind: "terminal" as const,
				teamName,
				...(workerId ? { workerId } : {}),
				...(taskId ? { taskId } : {}),
				state: terminalStateForReason(reason),
				reason,
				summary,
				evidence,
				sourceDigest: monitor.evidenceDigest,
				observedAt: clock(),
			};
			return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
		},

		async requeueStaleClaim(request) {
			const teamName = requiredString(request.teamName, "requeue teamName");
			const workerId = requiredString(request.workerId, "requeue workerId");
			const taskId = requiredString(request.taskId, "requeue taskId");
			assertRequestId(workerId, "workerId");
			assertRequestId(taskId, "taskId");
			const result = record(
				await callChecked("recover-stale-claims", { team_name: teamName }),
				"stale claim recovery",
			);
			if (!Array.isArray(result.recovered_claims)) {
				throw new CtfError("integrity_error", "stale claim recovery response is missing recovered claims");
			}
			const recovered = result.recovered_claims.some(candidate => {
				if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) return false;
				const value = candidate as Record<string, unknown>;
				return value.task_id === taskId && value.worker === workerId;
			});
			if (!recovered) {
				throw new CtfError("stale_claim", "GJC team did not requeue the requested stale claim", {
					retryable: true,
				});
			}
			const sourceDigest = canonicalDigest(result);
			const evidenceBase = {
				kind: "stale_claim_requeue" as const,
				teamName,
				workerId,
				taskId,
				requeued: true as const,
				observedAt: clock(),
				sourceDigest,
			};
			return { ...evidenceBase, evidenceDigest: sha256Hex(canonicalDigest(evidenceBase)) };
		},
		async requeue(request) {
			return this.requeueStaleClaim(request);
		},
		async recoverStaleClaim(request) {
			return this.requeueStaleClaim(request);
		},

		async confirm(request) {
			return this.verify({ ...request, disposition: "confirmed", outcome: "confirmed" });
		},
		async refute(request) {
			return this.verify({ ...request, disposition: "refuted", outcome: "refuted" });
		},
		async block(request) {
			return this.verify({ ...request, disposition: "blocked", outcome: "blocked" });
		},
	};
}

export const createCtfGjcTeamAdapter = createCtfTeamAdapter;
