import * as fs from "node:fs/promises";
import * as z from "zod/v4";
import type { RootedStoreOperationOptions } from "../../gjc-runtime/storage/rooted-store";
import { canonicalDigest, type Digest, digestsEqual } from "../contracts/digest";
import { CtfError, type CtfErrorCode, CtfErrorCodeSchema } from "../contracts/errors";
import {
	type ClaimProofV1,
	claimProofDigest,
	type IntentV2,
	validateClaimProof,
	validateIntent,
} from "../contracts/intent";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";
import { CanonicalEventLog, type EventAppendResult, type EventLogIdentity } from "./event-log";
import type { RunLeaseStore } from "./lease";
import { type CtfStateStore, type CtfStateStoreLike, createCtfStateStore } from "./storage";

export const CTF_INTENT_OUTCOMES_PATH = "intent-outcomes.jsonl" as const;
export function ctfIntentOutcomesPath(identity: EventLogIdentity = {}): string {
	if (identity.challengeId !== undefined) {
		return `challenges/${encodeURIComponent(identity.challengeId)}/intent-outcomes.jsonl`;
	}
	return CTF_INTENT_OUTCOMES_PATH;
}
export const ctfIntentOutcomePath = ctfIntentOutcomesPath;

export const IntentOutcomeV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.state),
		intentId: z.string().min(1),
		idempotencyKey: z.string().min(1),
		accepted: z.boolean(),
		rejectionCode: CtfErrorCodeSchema.optional(),
		rejectionMessage: z.string().min(1).optional(),
		canonicalRevision: z.number().int().positive(),
		eventDigest: z.string().regex(/^[a-f0-9]{64}$/),
		createdAt: z.string().datetime({ offset: true }),
		outcomeDigest: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict()
	.superRefine((outcome, ctx) => {
		if (!outcome.accepted && outcome.rejectionCode === undefined) {
			ctx.addIssue({
				code: "custom",
				path: ["rejectionCode"],
				message: "rejected intent outcomes require a typed rejection code",
			});
		}
		if (outcome.accepted && outcome.rejectionCode !== undefined) {
			ctx.addIssue({
				code: "custom",
				path: ["rejectionCode"],
				message: "accepted intent outcomes cannot carry a rejection code",
			});
		}
	});
export type IntentOutcomeV1 = z.infer<typeof IntentOutcomeV1Schema>;

export interface IntentSubmissionResult {
	readonly outcome: IntentOutcomeV1;
	readonly event: EventAppendResult["event"];
	readonly duplicate: boolean;
}
/** Current claim snapshot supplied by an explicitly authorized verifier. */
export interface ClaimVerificationInput {
	readonly intent: IntentV2;
	readonly proof: ClaimProofV1;
}

export interface ClaimVerificationResult {
	readonly teamName: ClaimProofV1["teamName"];
	readonly taskId: ClaimProofV1["taskId"];
	readonly workerId: ClaimProofV1["workerId"];
	readonly claimToken: ClaimProofV1["claimToken"];
	readonly lane: ClaimProofV1["lane"];
	readonly requiredRole: ClaimProofV1["requiredRole"];
	readonly teamStateRevision: ClaimProofV1["teamStateRevision"];
	readonly runFencingToken: IntentV2["runFencingToken"];
	readonly expiresAt: ClaimProofV1["expiresAt"];
	readonly lifecycleState?: ClaimProofV1["lifecycleState"];
}

/** Verifier for current team claim state; proof bytes alone never authorize an intent. */
export interface ClaimSnapshotVerifier {
	verifyCurrentClaim(input: ClaimVerificationInput): Promise<ClaimVerificationResult> | ClaimVerificationResult;
}

/** Constructor options for claim verification and rooted state storage. */
export interface CanonicalIntentStoreOptions extends RootedStoreOperationOptions {
	readonly claimVerifier?: ClaimSnapshotVerifier;
}

function isErrno(error: unknown, code: string): boolean {
	return typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === code;
}

function withoutWriterReceipt(value: unknown): unknown {
	if (!value || typeof value !== "object" || Array.isArray(value)) return value;
	const copy = { ...(value as Record<string, unknown>) };
	delete copy.receipt;
	return copy;
}

function outcomeDigest(value: Omit<IntentOutcomeV1, "outcomeDigest">): Digest {
	return canonicalDigest(value);
}
function auditableRejection(error: unknown): error is CtfError {
	return (
		error instanceof CtfError &&
		(error.code === "stale_claim" ||
			error.code === "stale_run_fence" ||
			error.code === "revision_conflict" ||
			error.code === "digest_mismatch")
	);
}

function makeOutcome(event: IntentSubmissionResult["event"]): IntentOutcomeV1 {
	const accepted = event.eventType === "intent_accepted";
	const payload =
		event.payload && typeof event.payload === "object" ? (event.payload as Record<string, unknown>) : undefined;
	let rejectionCode: CtfErrorCode | undefined;
	if (!accepted) {
		const parsed = CtfErrorCodeSchema.safeParse(payload?.rejectionCode);
		if (!parsed.success)
			throw new CtfError("integrity_error", "intent rejection event does not carry a typed rejection code");
		rejectionCode = parsed.data;
	}
	const base: Omit<IntentOutcomeV1, "outcomeDigest"> = {
		schemaVersion: CTF_SCHEMA_VERSIONS.state,
		intentId: payload && typeof payload.intentId === "string" ? payload.intentId : event.eventId,
		idempotencyKey: event.idempotencyKey,
		accepted,
		...(accepted
			? {}
			: {
					rejectionCode: rejectionCode!,
					...(typeof payload?.rejectionMessage === "string" ? { rejectionMessage: payload.rejectionMessage } : {}),
				}),
		canonicalRevision: event.revision,
		eventDigest: requireDigest(event),
		createdAt: event.occurredAt,
	};
	return { ...base, outcomeDigest: outcomeDigest(base) };
}

function requireDigest(event: IntentSubmissionResult["event"]): Digest {
	return canonicalDigest(event);
}

function parseOutcome(line: string, lineNumber: number): IntentOutcomeV1 {
	let parsed: unknown;
	try {
		parsed = JSON.parse(line);
	} catch (error) {
		throw new CtfError("integrity_error", `intent outcome log contains invalid JSON at line ${lineNumber}`, {
			details: { cause: error instanceof Error ? error.message : String(error) },
		});
	}
	const result = IntentOutcomeV1Schema.safeParse(withoutWriterReceipt(parsed));
	if (!result.success)
		throw new CtfError("integrity_error", `intent outcome is invalid at line ${lineNumber}`, {
			details: { issues: result.error.issues },
		});
	const { outcomeDigest: persisted, ...base } = result.data;
	if (!digestsEqual(outcomeDigest(base), persisted))
		throw new CtfError("digest_mismatch", `intent outcome digest mismatch at line ${lineNumber}`);
	return result.data;
}

async function readOutcomes(store: CtfStateStore, outcomePath: string): Promise<IntentOutcomeV1[]> {
	let raw: string;
	try {
		raw = await fs.readFile(store.resolve(outcomePath), "utf8");
	} catch (error) {
		if (isErrno(error, "ENOENT")) return [];
		throw error;
	}
	if (!raw.endsWith("\n")) throw new CtfError("integrity_error", "intent outcome log has a partial tail");
	const lines = raw.split("\n");
	lines.pop();
	return lines.map((line, index) => {
		if (!line.trim())
			throw new CtfError("integrity_error", `intent outcome log contains an empty line at line ${index + 1}`);
		return parseOutcome(line, index + 1);
	});
}

/** Canonical intent submission authority with durable idempotent outcomes. */
export class CanonicalIntentStore {
	readonly store: CtfStateStore;
	readonly eventLog: CanonicalEventLog;
	readonly leaseStore?: RunLeaseStore;
	readonly outcomePath: string;
	readonly claimVerifier?: ClaimSnapshotVerifier;

	constructor(
		store: CtfStateStoreLike,
		eventLog?: CanonicalEventLog,
		leaseStore?: RunLeaseStore,
		options?: CanonicalIntentStoreOptions,
	) {
		this.store = createCtfStateStore(store, options);
		this.eventLog = eventLog ?? new CanonicalEventLog(this.store);
		this.outcomePath = ctfIntentOutcomesPath(this.eventLog.identity);
		this.leaseStore = leaseStore;
		this.claimVerifier = options?.claimVerifier;
	}
	private leaseLockPath(intent: IntentV2): string {
		return `leases/${encodeURIComponent(intent.competitionId)}/${encodeURIComponent(intent.challengeId)}.json`;
	}

	private assertClaimProof(intent: IntentV2, rawProof: unknown): ClaimProofV1 {
		let proof: ClaimProofV1;
		try {
			proof = validateClaimProof(rawProof);
		} catch (error) {
			if (error instanceof CtfError) throw error;
			throw new CtfError("stale_claim", "claim proof is invalid", {
				details: { cause: error instanceof Error ? error.message : String(error) },
			});
		}
		const identity: Array<
			keyof Pick<ClaimProofV1, "teamName" | "taskId" | "workerId" | "claimToken" | "lane" | "requiredRole">
		> = ["teamName", "taskId", "workerId", "claimToken", "lane", "requiredRole"];
		for (const field of identity) {
			if (proof[field] !== intent[field])
				throw new CtfError("stale_claim", `claim proof ${field} does not match intent`);
		}
		if (proof.expiresAt !== intent.claimExpiresAt) {
			throw new CtfError("stale_claim", "claim proof expiry does not match intent");
		}
		if (
			proof.lifecycleState !== "starting" &&
			proof.lifecycleState !== "ready" &&
			proof.lifecycleState !== "running"
		) {
			throw new CtfError("stale_claim", "claim lifecycle is not active");
		}
		const expiresAt = new Date(proof.expiresAt);
		if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
			throw new CtfError("stale_claim", "claim proof has expired", { retryable: true });
		}
		if (!digestsEqual(claimProofDigest(proof), intent.claimProofDigest)) {
			throw new CtfError("digest_mismatch", "claim proof digest does not match intent");
		}
		return proof;
	}

	private async assertCurrentClaim(intent: IntentV2, proof: ClaimProofV1): Promise<void> {
		if (proof.source === "gjc-team-api") {
			if (!this.claimVerifier) {
				throw new CtfError("stale_claim", "current team claim verifier is required for gjc-team-api claim proofs");
			}
			let verified: ClaimVerificationResult;
			try {
				verified = await this.claimVerifier.verifyCurrentClaim({ intent, proof });
			} catch (error) {
				if (error instanceof CtfError && error.code === "stale_claim") throw error;
				throw new CtfError("stale_claim", "current team claim verifier could not confirm the claim", {
					details: { cause: error instanceof Error ? error.message : String(error) },
				});
			}
			const expected: ClaimVerificationResult = {
				teamName: proof.teamName,
				taskId: proof.taskId,
				workerId: proof.workerId,
				claimToken: proof.claimToken,
				lane: proof.lane,
				requiredRole: proof.requiredRole,
				teamStateRevision: proof.teamStateRevision,
				runFencingToken: intent.runFencingToken,
				expiresAt: proof.expiresAt,
			};
			for (const field of Object.keys(expected) as Array<keyof ClaimVerificationResult>) {
				if (verified === null || typeof verified !== "object" || verified[field] !== expected[field]) {
					throw new CtfError("stale_claim", `current team claim verifier did not confirm ${field}`);
				}
			}
			if (verified.lifecycleState !== undefined && verified.lifecycleState !== proof.lifecycleState) {
				throw new CtfError("stale_claim", "current team claim lifecycle changed");
			}
			const expiresAt = new Date(verified.expiresAt);
			if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
				throw new CtfError("stale_claim", "current team claim has expired", { retryable: true });
			}
		}
		if (!this.leaseStore) throw new CtfError("stale_run_fence", "intent submission requires a fenced run lease");
		const current = await this.leaseStore.read(intent.competitionId, intent.challengeId);
		if (!current || current.runId !== intent.runId || current.fencingToken !== intent.runFencingToken) {
			throw new CtfError("stale_run_fence", "run fencing token is stale", { retryable: true });
		}
		if (current.teamName !== intent.teamName || current.teamName !== proof.teamName) {
			throw new CtfError("stale_claim", "run lease does not belong to the claimed team");
		}
		if (
			current.state === "failed" ||
			current.state === "blocked" ||
			current.state === "solved" ||
			current.state === "aborted"
		) {
			throw new CtfError("stale_claim", "run is no longer active");
		}
		await this.leaseStore.assertFence(intent.runId, intent.runFencingToken);
	}

	private intentEventMatches(event: IntentSubmissionResult["event"], intent: IntentV2): boolean {
		if (event.idempotencyKey !== intent.idempotencyKey) return false;
		if (!event.payload || typeof event.payload !== "object") return false;
		const payload = event.payload as Record<string, unknown>;
		if (payload.intentId !== intent.intentId || payload.payloadDigest !== intent.payloadDigest) return false;
		if (!payload.intent || typeof payload.intent !== "object" || Array.isArray(payload.intent)) return false;
		return digestsEqual(canonicalDigest(payload.intent), canonicalDigest(intent));
	}

	private async persistOutcome(
		outcome: IntentOutcomeV1,
		options?: RootedStoreOperationOptions,
	): Promise<IntentOutcomeV1> {
		return this.store.withLock(
			this.outcomePath,
			async () => {
				const existing = await readOutcomes(this.store, this.outcomePath);
				const duplicate = existing.find(candidate => candidate.idempotencyKey === outcome.idempotencyKey);
				if (duplicate) {
					if (!digestsEqual(duplicate.outcomeDigest, outcome.outcomeDigest))
						throw new CtfError("idempotency_conflict", "intent idempotency key has a conflicting outcome");
					return duplicate;
				}
				await this.store.appendJsonl(this.outcomePath, outcome, options);
				return outcome;
			},
			options,
		);
	}

	async readOutcomes(): Promise<readonly IntentOutcomeV1[]> {
		return readOutcomes(this.store, this.outcomePath);
	}

	private async rejectIntent(
		intent: IntentV2,
		error: CtfError,
		options?: RootedStoreOperationOptions,
	): Promise<IntentSubmissionResult> {
		const eventResult = await this.eventLog.appendDraft(
			{
				eventId: intent.intentId,
				eventType: "intent_rejected",
				competitionId: intent.competitionId,
				challengeId: intent.challengeId,
				runId: intent.runId,
				idempotencyKey: intent.idempotencyKey,
				actor: intent.workerId,
				occurredAt: intent.createdAt,
				payload: {
					intentId: intent.intentId,
					intentVersion: intent.intentVersion,
					payloadDigest: intent.payloadDigest,
					intent,
					rejectionCode: error.code,
					rejectionMessage: error.message,
					...(error.details === undefined ? {} : { rejectionDetails: error.details }),
				},
				evidenceRefs: intent.evidenceRefs.map(ref => ref as Digest),
			},
			options,
		);
		if (!this.intentEventMatches(eventResult.event, intent)) {
			throw new CtfError("idempotency_conflict", "canonical rejection event does not match submitted intent");
		}
		const outcome = await this.persistOutcome(makeOutcome(eventResult.event), options);
		return { outcome, event: eventResult.event, duplicate: !eventResult.appended };
	}

	async submit(rawIntent: unknown, options?: RootedStoreOperationOptions): Promise<IntentSubmissionResult>;
	async submit(
		rawIntent: unknown,
		claimProof: ClaimProofV1,
		options?: RootedStoreOperationOptions,
	): Promise<IntentSubmissionResult>;
	async submit(
		rawIntent: unknown,
		claimProofOrOptions?: ClaimProofV1 | RootedStoreOperationOptions,
		maybeOptions?: RootedStoreOperationOptions,
	): Promise<IntentSubmissionResult> {
		const intent = validateIntent(rawIntent);
		const hasProofArgument =
			claimProofOrOptions !== undefined &&
			typeof claimProofOrOptions === "object" &&
			claimProofOrOptions !== null &&
			"source" in claimProofOrOptions;
		const proof = hasProofArgument ? claimProofOrOptions : undefined;
		const options = (hasProofArgument ? maybeOptions : (maybeOptions ?? claimProofOrOptions)) as
			| RootedStoreOperationOptions
			| undefined;
		const submitUnderLeaseLock = async (): Promise<IntentSubmissionResult> => {
			const current = await this.eventLog.read();
			const existing = current.events.find(event => event.idempotencyKey === intent.idempotencyKey);
			if (existing) {
				if (!this.intentEventMatches(existing, intent))
					throw new CtfError(
						"idempotency_conflict",
						"intent idempotency key has a conflicting immutable identity",
					);
				const outcome = await this.persistOutcome(makeOutcome(existing), options);
				return { outcome, event: existing, duplicate: true };
			}
			try {
				const validatedProof = this.assertClaimProof(intent, proof);
				await this.assertCurrentClaim(intent, validatedProof);
				if (intent.baseRevision !== current.revision) {
					return this.rejectIntent(
						intent,
						new CtfError(
							"revision_conflict",
							`intent is based on revision ${intent.baseRevision}, current revision is ${current.revision}`,
							{ retryable: true },
						),
						options,
					);
				}
			} catch (error) {
				if (auditableRejection(error)) return this.rejectIntent(intent, error, options);
				throw error;
			}
			try {
				const eventResult = await this.eventLog.appendDraft(
					{
						eventId: intent.intentId,
						eventType: "intent_accepted",
						competitionId: intent.competitionId,
						challengeId: intent.challengeId,
						runId: intent.runId,
						idempotencyKey: intent.idempotencyKey,
						actor: intent.workerId,
						occurredAt: intent.createdAt,
						payload: {
							intentId: intent.intentId,
							intentVersion: intent.intentVersion,
							payloadDigest: intent.payloadDigest,
							intent,
						},
						evidenceRefs: intent.evidenceRefs.map(ref => ref as Digest),
					},
					options,
					intent.baseRevision,
				);
				if (!this.intentEventMatches(eventResult.event, intent))
					throw new CtfError("idempotency_conflict", "canonical event does not match submitted intent");
				const outcome = await this.persistOutcome(makeOutcome(eventResult.event), options);
				return { outcome, event: eventResult.event, duplicate: !eventResult.appended };
			} catch (error) {
				if (auditableRejection(error)) return this.rejectIntent(intent, error, options);
				throw error;
			}
		};
		if (this.leaseStore) {
			return this.leaseStore.store.withLock(this.leaseLockPath(intent), submitUnderLeaseLock, options);
		}
		return submitUnderLeaseLock();
	}
}

export const IntentStore = CanonicalIntentStore;
export const IntentOutcomeStore = CanonicalIntentStore;
