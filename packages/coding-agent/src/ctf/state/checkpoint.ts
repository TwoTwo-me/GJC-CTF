import * as fs from "node:fs/promises";
import * as z from "zod/v4";
import type { RootedStoreOperationOptions } from "../../gjc-runtime/storage/rooted-store";
import { CtfIdSchema, DigestSchema, NonNegativeIntegerSchema, TimestampSchema } from "../contracts/common";
import { canonicalDigest, type Digest, digestsEqual } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import { eventDigest } from "../contracts/event";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";
import { CanonicalEventLog, EMPTY_EVENT_DIGEST, type EventLogIdentity, type EventLogReadResult } from "./event-log";
import { type CtfStateStore, type CtfStateStoreLike, createCtfStateStore } from "./storage";

export const CTF_CHECKPOINT_PATH = "checkpoint.json" as const;
export function ctfCheckpointPath(identity: EventLogIdentity = {}): string {
	if (identity.challengeId !== undefined) {
		return `challenges/${encodeURIComponent(identity.challengeId)}/checkpoint.json`;
	}
	return CTF_CHECKPOINT_PATH;
}

/** Atomic metadata identifying an exact point in the canonical event stream. */
export const CheckpointV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.state),
		competitionId: CtfIdSchema,
		challengeId: CtfIdSchema.optional(),
		canonicalRevision: NonNegativeIntegerSchema,
		canonicalDigest: DigestSchema,
		eventCount: NonNegativeIntegerSchema,
		journalByteOffset: NonNegativeIntegerSchema,
		lastEventDigest: DigestSchema.optional(),
		graphDigest: DigestSchema.optional(),
		projectionDigest: DigestSchema.optional(),
		createdAt: TimestampSchema,
		checkpointDigest: DigestSchema,
	})
	.strict();
export type CheckpointV1 = z.infer<typeof CheckpointV1Schema>;

export interface CheckpointInput {
	competitionId: string;
	challengeId?: string;
	canonicalRevision: number;
	canonicalDigest: Digest;
	eventCount: number;
	journalByteOffset: number;
	lastEventDigest?: Digest;
	graphDigest?: Digest;
	projectionDigest?: Digest;
	createdAt?: string;
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

function checkpointDigest(checkpoint: Omit<CheckpointV1, "checkpointDigest">): Digest {
	return canonicalDigest(checkpoint);
}

function validateCheckpoint(value: unknown): CheckpointV1 {
	const parsed = CheckpointV1Schema.safeParse(withoutWriterReceipt(value));
	if (!parsed.success) {
		throw new CtfError("integrity_error", "checkpoint metadata is invalid", {
			details: { issues: parsed.error.issues },
		});
	}
	const checkpoint = parsed.data;
	if (!Number.isSafeInteger(checkpoint.journalByteOffset) || checkpoint.journalByteOffset < 0) {
		throw new CtfError("integrity_error", "checkpoint journal byte offset must be a non-negative safe integer");
	}
	const { checkpointDigest: persistedDigest, ...base } = checkpoint;
	if (!digestsEqual(checkpointDigest(base), persistedDigest)) {
		throw new CtfError("digest_mismatch", "checkpoint digest mismatch");
	}
	if (checkpoint.eventCount !== checkpoint.canonicalRevision) {
		throw new CtfError("revision_conflict", "checkpoint event count must equal canonical revision");
	}
	if (checkpoint.canonicalRevision === 0 && !digestsEqual(checkpoint.canonicalDigest, EMPTY_EVENT_DIGEST)) {
		throw new CtfError("digest_mismatch", "empty checkpoint does not use the empty event digest");
	}
	if (
		checkpoint.lastEventDigest !== undefined &&
		!digestsEqual(checkpoint.lastEventDigest, checkpoint.canonicalDigest)
	) {
		throw new CtfError("digest_mismatch", "checkpoint last-event digest does not match the canonical digest");
	}
	return checkpoint;
}

function assertCheckpointIdentity(checkpoint: CheckpointV1, identity: EventLogIdentity): void {
	if (identity.competitionId !== undefined && checkpoint.competitionId !== identity.competitionId) {
		throw new CtfError("cross_challenge_reference", "checkpoint competition does not belong to this event log");
	}
	if (identity.challengeId !== undefined && checkpoint.challengeId !== identity.challengeId) {
		throw new CtfError("cross_challenge_reference", "checkpoint challenge does not belong to this event log");
	}
}

/** Verify that checkpoint metadata names an exact immutable event-log prefix. */
function assertCanonicalPrefix(checkpoint: CheckpointV1, head: EventLogReadResult, identity: EventLogIdentity): void {
	assertCheckpointIdentity(checkpoint, identity);
	const streamCompetition = identity.competitionId ?? head.events[0]?.competitionId;
	if (streamCompetition !== undefined && checkpoint.competitionId !== streamCompetition) {
		throw new CtfError(
			"cross_challenge_reference",
			"checkpoint competition does not match the canonical event stream",
		);
	}
	if (checkpoint.canonicalRevision > head.revision) {
		throw new CtfError("revision_conflict", "checkpoint revision is not at or behind the canonical head", {
			details: { checkpointRevision: checkpoint.canonicalRevision, canonicalRevision: head.revision },
		});
	}
	const expectedJournalByteOffset = head.journalByteOffsets?.[checkpoint.canonicalRevision];
	if (expectedJournalByteOffset === undefined || checkpoint.journalByteOffset !== expectedJournalByteOffset) {
		throw new CtfError("integrity_error", "checkpoint journal byte offset does not match the canonical prefix", {
			details: {
				canonicalRevision: checkpoint.canonicalRevision,
				expectedJournalByteOffset,
				actualJournalByteOffset: checkpoint.journalByteOffset,
			},
		});
	}
	const eventAtRevision =
		checkpoint.canonicalRevision === 0 ? undefined : head.events[checkpoint.canonicalRevision - 1];
	const expectedDigest = eventAtRevision === undefined ? EMPTY_EVENT_DIGEST : eventDigest(eventAtRevision);
	if (!digestsEqual(checkpoint.canonicalDigest, expectedDigest)) {
		throw new CtfError("digest_mismatch", "checkpoint canonical digest does not match the event at its revision");
	}
	if (checkpoint.lastEventDigest !== undefined && !digestsEqual(checkpoint.lastEventDigest, expectedDigest)) {
		throw new CtfError("digest_mismatch", "checkpoint last-event digest does not match the event at its revision");
	}
	if (eventAtRevision !== undefined) {
		if (checkpoint.competitionId !== eventAtRevision.competitionId) {
			throw new CtfError(
				"cross_challenge_reference",
				"checkpoint competition does not match its canonical event prefix",
			);
		}
		if (checkpoint.challengeId !== undefined && checkpoint.challengeId !== eventAtRevision.challengeId) {
			throw new CtfError(
				"cross_challenge_reference",
				"checkpoint challenge does not match its canonical event prefix",
			);
		}
	}
}

function checkpointFor(input: CheckpointInput): CheckpointV1 {
	const base: Omit<CheckpointV1, "checkpointDigest"> = {
		schemaVersion: CTF_SCHEMA_VERSIONS.state,
		competitionId: input.competitionId,
		...(input.challengeId === undefined ? {} : { challengeId: input.challengeId }),
		canonicalRevision: input.canonicalRevision,
		canonicalDigest: input.canonicalDigest,
		eventCount: input.eventCount,
		journalByteOffset: input.journalByteOffset,
		lastEventDigest: input.lastEventDigest ?? input.canonicalDigest,
		...(input.graphDigest === undefined ? {} : { graphDigest: input.graphDigest }),
		...(input.projectionDigest === undefined ? {} : { projectionDigest: input.projectionDigest }),
		createdAt: input.createdAt ?? new Date().toISOString(),
	};
	return validateCheckpoint({ ...base, checkpointDigest: checkpointDigest(base) });
}

/** Read a checkpoint without trusting a writer receipt or mutating corrupt state. */
export async function readCheckpoint(
	store: CtfStateStoreLike,
	identity: EventLogIdentity = {},
): Promise<CheckpointV1 | undefined> {
	const rooted = createCtfStateStore(store);
	try {
		const raw = await fs.readFile(rooted.resolve(ctfCheckpointPath(identity)), "utf8");
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch (error) {
			throw new CtfError("integrity_error", "checkpoint file is not valid JSON", {
				details: { cause: error instanceof Error ? error.message : String(error) },
			});
		}
		const checkpoint = validateCheckpoint(parsed);
		assertCheckpointIdentity(checkpoint, identity);
		return checkpoint;
	} catch (error) {
		if (isErrno(error, "ENOENT")) return undefined;
		throw error;
	}
}

function assertStoreRootIdentity(store: CtfStateStore, eventLog: CanonicalEventLog): void {
	if (store.root !== eventLog.store.root) {
		throw new CtfError("integrity_error", "checkpoint store and event log must use the same root");
	}
}

/**
 * Checkpoint manager. A checkpoint may never point past the canonical head and
 * an older checkpoint can never overwrite a newer one.
 */
export class CheckpointStore {
	readonly store: CtfStateStore;
	readonly eventLog: CanonicalEventLog;
	readonly path: string;

	constructor(store: CtfStateStoreLike, eventLog?: CanonicalEventLog, options?: RootedStoreOperationOptions) {
		this.store = createCtfStateStore(store, { ...options, durability: "ctf" });
		this.eventLog = eventLog ?? new CanonicalEventLog(this.store);
		assertStoreRootIdentity(this.store, this.eventLog);
		this.path = ctfCheckpointPath(this.eventLog.identity);
	}

	async read(): Promise<CheckpointV1 | undefined> {
		assertStoreRootIdentity(this.store, this.eventLog);
		const checkpoint = await readCheckpoint(this.store, this.eventLog.identity);
		if (checkpoint === undefined) return undefined;
		const head = await this.eventLog.read();
		assertCanonicalPrefix(checkpoint, head, this.eventLog.identity);
		return checkpoint;
	}

	async write(input: CheckpointInput, options?: RootedStoreOperationOptions): Promise<CheckpointV1> {
		assertStoreRootIdentity(this.store, this.eventLog);
		const durableOptions: RootedStoreOperationOptions = { ...options, durability: "ctf" };
		return this.store.withLock(
			this.path,
			async () => {
				const head: EventLogReadResult = await this.eventLog.read();
				if (
					!Number.isInteger(input.canonicalRevision) ||
					input.canonicalRevision < 0 ||
					input.canonicalRevision > head.revision
				) {
					throw new CtfError("revision_conflict", "checkpoint revision is not at or behind the canonical head", {
						details: { checkpointRevision: input.canonicalRevision, canonicalRevision: head.revision },
					});
				}
				if (
					!Number.isInteger(input.eventCount) ||
					input.eventCount < 0 ||
					input.eventCount !== input.canonicalRevision
				) {
					throw new CtfError("revision_conflict", "checkpoint event count must equal canonical revision");
				}
				const eventAtRevision =
					input.canonicalRevision === 0 ? undefined : head.events[input.canonicalRevision - 1];
				const expectedDigest = eventAtRevision === undefined ? EMPTY_EVENT_DIGEST : eventDigest(eventAtRevision);
				if (!digestsEqual(input.canonicalDigest, expectedDigest)) {
					throw new CtfError(
						"digest_mismatch",
						"checkpoint canonical digest does not match the event at its revision",
					);
				}
				if (input.lastEventDigest !== undefined && !digestsEqual(input.lastEventDigest, expectedDigest)) {
					throw new CtfError(
						"digest_mismatch",
						"checkpoint last-event digest does not match the event at its revision",
					);
				}
				if (!Number.isSafeInteger(input.journalByteOffset) || input.journalByteOffset < 0) {
					throw new CtfError(
						"integrity_error",
						"checkpoint journal byte offset must be a non-negative safe integer",
					);
				}
				const expectedJournalByteOffset = head.journalByteOffsets?.[input.canonicalRevision];
				if (input.journalByteOffset !== expectedJournalByteOffset) {
					throw new CtfError(
						"integrity_error",
						"checkpoint journal byte offset does not match the canonical prefix",
						{
							details: {
								canonicalRevision: input.canonicalRevision,
								expectedJournalByteOffset,
								actualJournalByteOffset: input.journalByteOffset,
							},
						},
					);
				}
				assertCheckpointIdentity(checkpointFor(input), this.eventLog.identity);
				const streamCompetition = this.eventLog.identity.competitionId ?? head.events[0]?.competitionId;
				if (streamCompetition !== undefined && input.competitionId !== streamCompetition) {
					throw new CtfError(
						"cross_challenge_reference",
						"checkpoint competition does not match the canonical event stream",
					);
				}
				if (eventAtRevision !== undefined) {
					if (input.competitionId !== eventAtRevision.competitionId) {
						throw new CtfError(
							"cross_challenge_reference",
							"checkpoint competition does not match its canonical event prefix",
						);
					}
					if (input.challengeId !== undefined && input.challengeId !== eventAtRevision.challengeId) {
						throw new CtfError(
							"cross_challenge_reference",
							"checkpoint challenge does not match its canonical event prefix",
						);
					}
				}
				const next = checkpointFor(input);
				const previous = await this.read();
				if (previous && previous.canonicalRevision > next.canonicalRevision) {
					throw new CtfError("revision_conflict", "checkpoint revision moved backwards");
				}
				if (previous && previous.canonicalRevision === next.canonicalRevision) {
					if (
						!digestsEqual(previous.canonicalDigest, next.canonicalDigest) ||
						previous.competitionId !== next.competitionId ||
						previous.challengeId !== next.challengeId ||
						previous.eventCount !== next.eventCount ||
						previous.journalByteOffset !== next.journalByteOffset ||
						previous.lastEventDigest !== next.lastEventDigest ||
						previous.graphDigest !== next.graphDigest ||
						previous.projectionDigest !== next.projectionDigest
					) {
						throw new CtfError("integrity_error", "checkpoint metadata conflicts at the same revision");
					}
				}
				if (!previous || previous.checkpointDigest !== next.checkpointDigest)
					await this.store.writeJsonAtomic(this.path, next, durableOptions);
				return next;
			},
			durableOptions,
		);
	}

	async checkpointHead(options?: RootedStoreOperationOptions): Promise<CheckpointV1> {
		const head = await this.eventLog.read();
		if (head.journalByteOffset === undefined)
			throw new CtfError("integrity_error", "canonical event log did not provide a journal byte offset");
		const competitionId = this.eventLog.identity.competitionId ?? head.events[0]?.competitionId;
		if (!competitionId)
			throw new CtfError("invalid_manifest", "cannot checkpoint an empty event log without competition identity");
		return this.write(
			{
				competitionId,
				challengeId: this.eventLog.identity.challengeId,
				canonicalRevision: head.revision,
				canonicalDigest: head.digest,
				eventCount: head.eventCount,
				journalByteOffset: head.journalByteOffset,
			},
			options,
		);
	}
}

export const CheckpointManager = CheckpointStore;
export const CheckpointWriter = CheckpointStore;
export function checkpointDigestOf(checkpoint: Omit<CheckpointV1, "checkpointDigest">): Digest {
	return checkpointDigest(checkpoint);
}
