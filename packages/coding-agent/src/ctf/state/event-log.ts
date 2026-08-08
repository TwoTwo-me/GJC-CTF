import { randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import type { RootedStoreOperationOptions } from "../../gjc-runtime/storage/rooted-store";
import { type Digest, digestsEqual } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	assertGraphEventWriterCapability,
	type EventV1,
	eventDigest,
	eventPayloadDigest,
	type GraphEventWriterCapability,
	validateEvent,
} from "../contracts/event";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";
import type { RunLeaseVerifier } from "./lease";
import { type CtfStateStore, type CtfStateStoreLike, createCtfStateStore } from "./storage";

/** Digest used as the predecessor of the first event in a canonical stream. */
export const EMPTY_EVENT_DIGEST = "0".repeat(64) as Digest;
export const CTF_EVENT_LOG_PATH = "events.jsonl" as const;
export function ctfEventLogPath(identity: EventLogIdentity = {}): string {
	if (identity.challengeId !== undefined) {
		return `challenges/${encodeURIComponent(identity.challengeId)}/journal.jsonl`;
	}
	return CTF_EVENT_LOG_PATH;
}

export interface EventLogIdentity {
	competitionId?: string;
	challengeId?: string;
}
export interface CanonicalEventLogOptions extends RootedStoreOperationOptions {
	/** Live lease authority used to revalidate run graph writer capabilities. */
	readonly leaseStore?: RunLeaseVerifier;
	/** Testable lease authority; when present it takes precedence over leaseStore. */
	readonly leaseVerifier?: RunLeaseVerifier;
}

export interface EventLogMetadata {
	readonly revision: number;
	readonly digest: Digest;
	readonly eventCount: number;
	/** UTF-8 byte end of the canonical head; populated by canonical log reads. */
	readonly journalByteOffset?: number;
	readonly complete: true;
}

export interface EventLogReadResult extends EventLogMetadata {
	readonly events: readonly EventV1[];
	/** UTF-8 byte ends for each canonical revision, including revision zero. */
	readonly journalByteOffsets?: readonly number[];
}

export interface EventAppendResult {
	readonly event: EventV1;
	readonly digest: Digest;
	readonly appended: boolean;
	readonly metadata: EventLogMetadata;
}

export interface EventDraft {
	eventId?: string;
	eventType: EventV1["eventType"];
	competitionId: string;
	challengeId: string;
	runId?: string;
	idempotencyKey: string;
	actor: string;
	occurredAt?: string;
	payload: Record<string, unknown>;
	evidenceRefs: readonly Digest[];
}

function isErrno(error: unknown, code: string): boolean {
	return typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === code;
}

function parseLine(line: string, lineNumber: number): EventV1 {
	let parsed: unknown;
	try {
		parsed = JSON.parse(line);
	} catch (error) {
		throw new CtfError("integrity_error", `event log contains invalid JSON at line ${lineNumber}`, {
			details: { line: lineNumber, cause: error instanceof Error ? error.message : String(error) },
		});
	}
	try {
		return validateEvent(parsed);
	} catch (error) {
		if (error instanceof CtfError) {
			throw new CtfError("integrity_error", `event log contains an invalid event at line ${lineNumber}`, {
				details: { line: lineNumber, cause: error.message, code: error.code },
			});
		}
		throw error;
	}
}

function metadata(events: readonly EventV1[], journalByteOffset: number): EventLogMetadata {
	const last = events.at(-1);
	return {
		revision: last?.revision ?? 0,
		digest: last ? eventDigest(last) : EMPTY_EVENT_DIGEST,
		eventCount: events.length,
		journalByteOffset,
		complete: true,
	};
}

function equivalentEventIdentity(left: EventV1, right: EventV1): boolean {
	return (
		left.eventType === right.eventType &&
		left.competitionId === right.competitionId &&
		left.challengeId === right.challengeId &&
		left.runId === right.runId
	);
}

function isGraphTransitionEvent(eventType: EventV1["eventType"]): boolean {
	return eventType === "node_transition" || eventType === "edge_transition";
}

function validateGraphWriterAuthority(
	event: Pick<EventV1, "eventType" | "competitionId" | "challengeId" | "runId" | "actor" | "payload">,
	capability: GraphEventWriterCapability | undefined,
): GraphEventWriterCapability | undefined {
	if (!isGraphTransitionEvent(event.eventType)) return undefined;
	if (capability === undefined) {
		throw new CtfError("stale_run_fence", "graph transition append requires a validated writer capability", {
			retryable: true,
		});
	}
	const validated = assertGraphEventWriterCapability(capability);
	if (
		validated.competitionId !== event.competitionId ||
		validated.challengeId !== event.challengeId ||
		validated.runId !== event.runId ||
		validated.actor !== event.actor
	) {
		throw new CtfError("stale_run_fence", "graph transition writer capability does not match event identity", {
			retryable: true,
			details: {
				eventCompetitionId: event.competitionId,
				eventChallengeId: event.challengeId,
				eventRunId: event.runId,
				eventActor: event.actor,
			},
		});
	}
	const fencingToken = event.payload.fencingToken;
	if (
		typeof fencingToken !== "number" ||
		!Number.isSafeInteger(fencingToken) ||
		fencingToken !== validated.fencingToken
	) {
		throw new CtfError("stale_run_fence", "graph transition is not bound to the writer capability fence", {
			retryable: true,
			details: { eventFencingToken: fencingToken, capabilityFencingToken: validated.fencingToken },
		});
	}
	return validated;
}

async function assertLiveGraphWriterAuthority(
	event: Pick<EventV1, "eventType">,
	capability: GraphEventWriterCapability | undefined,
	leaseVerifier: RunLeaseVerifier | undefined,
): Promise<void> {
	if (!isGraphTransitionEvent(event.eventType)) return;
	if (capability?.kind !== "run") return;
	if (leaseVerifier === undefined) {
		throw new CtfError("stale_run_fence", "run graph transition append requires a live lease verifier", {
			retryable: true,
		});
	}
	await leaseVerifier.assertFence(capability.runId, capability.fencingToken);
}
/** Build a schema-validated event draft for the current canonical stream. */
export function makeEvent(draft: EventDraft, revision: number, previousEventDigest: Digest): EventV1 {
	const payloadDigest = eventPayloadDigest({ payload: draft.payload });
	return validateEvent({
		schemaVersion: CTF_SCHEMA_VERSIONS.event,
		eventId: draft.eventId ?? randomUUID(),
		eventType: draft.eventType,
		competitionId: draft.competitionId,
		challengeId: draft.challengeId,
		...(draft.runId === undefined ? {} : { runId: draft.runId }),
		previousRevision: revision - 1,
		revision,
		idempotencyKey: draft.idempotencyKey,
		payloadDigest,
		previousEventDigest,
		actor: draft.actor,
		occurredAt: draft.occurredAt ?? new Date().toISOString(),
		payload: draft.payload,
		evidenceRefs: [...draft.evidenceRefs],
	});
}

/**
 * Append-only, hash-chained event authority. All mutations go through RootedStore;
 * reads deliberately use the resolved path and never repair or truncate the log.
 */
export class CanonicalEventLog {
	readonly store: CtfStateStore;
	readonly path: string;
	readonly identity: EventLogIdentity;
	readonly leaseVerifier: RunLeaseVerifier | undefined;

	constructor(store: CtfStateStoreLike, identity: EventLogIdentity = {}, options?: CanonicalEventLogOptions) {
		this.store = createCtfStateStore(store, options);
		this.path = ctfEventLogPath(identity);
		this.identity = identity;
		this.leaseVerifier = options?.leaseVerifier ?? options?.leaseStore;
	}

	private async readRaw(): Promise<string> {
		try {
			return await fs.readFile(this.store.resolve(this.path), "utf8");
		} catch (error) {
			if (isErrno(error, "ENOENT")) return "";
			throw error;
		}
	}

	private validateIdentity(event: EventV1): void {
		if (this.identity.competitionId !== undefined && event.competitionId !== this.identity.competitionId) {
			throw new CtfError("cross_challenge_reference", "event competition does not belong to this event log");
		}
		if (this.identity.challengeId !== undefined && event.challengeId !== this.identity.challengeId) {
			throw new CtfError("cross_challenge_reference", "event challenge does not belong to this event log");
		}
	}

	private parseRaw(raw: string): EventLogReadResult {
		if (!raw) return { events: [], ...metadata([], 0), journalByteOffsets: [0] };
		if (!raw.endsWith("\n")) {
			throw new CtfError("integrity_error", "event log has a partial tail; refusing to truncate or append");
		}
		const lines = raw.split("\n");
		lines.pop();
		const events: EventV1[] = [];
		const journalByteOffsets = [0];
		let journalByteOffset = 0;
		let previousDigest = EMPTY_EVENT_DIGEST;
		const seenEventIds = new Set<string>();
		const seenIdempotencyKeys = new Set<string>();
		for (let index = 0; index < lines.length; index += 1) {
			const line = lines[index];
			if (!line.trim())
				throw new CtfError("integrity_error", `event log contains an empty line at line ${index + 1}`);
			journalByteOffset += Buffer.byteLength(line, "utf8") + 1;
			journalByteOffsets.push(journalByteOffset);
			const event = parseLine(line, index + 1);
			if (seenEventIds.has(event.eventId)) {
				throw new CtfError("integrity_error", `event log contains a duplicate event ID at line ${index + 1}`, {
					details: { eventId: event.eventId, line: index + 1 },
				});
			}
			if (seenIdempotencyKeys.has(event.idempotencyKey)) {
				throw new CtfError(
					"integrity_error",
					`event log contains a duplicate idempotency key at line ${index + 1}`,
					{
						details: { idempotencyKey: event.idempotencyKey, line: index + 1 },
					},
				);
			}
			seenEventIds.add(event.eventId);
			seenIdempotencyKeys.add(event.idempotencyKey);
			this.validateIdentity(event);
			const expectedRevision = events.length + 1;
			if (event.revision !== expectedRevision || event.previousRevision !== events.length) {
				throw new CtfError("revision_conflict", `event revision is not contiguous at line ${index + 1}`, {
					details: { expectedRevision, actualRevision: event.revision, previousRevision: event.previousRevision },
				});
			}
			if (!digestsEqual(event.previousEventDigest, previousDigest)) {
				throw new CtfError("integrity_error", `event hash chain mismatch at revision ${event.revision}`);
			}
			previousDigest = eventDigest(event);
			events.push(event);
		}
		return { events, ...metadata(events, journalByteOffset), journalByteOffsets };
	}

	async read(): Promise<EventLogReadResult> {
		return this.parseRaw(await this.readRaw());
	}

	async append(
		event: EventV1,
		options?: RootedStoreOperationOptions,
		capability?: GraphEventWriterCapability,
	): Promise<EventAppendResult> {
		validateEvent(event);
		this.validateIdentity(event);
		const validatedCapability = validateGraphWriterAuthority(event, capability);
		return this.store.withLock(
			this.path,
			async () => {
				await assertLiveGraphWriterAuthority(event, validatedCapability, this.leaseVerifier);
				const current = this.parseRaw(await this.readRaw());
				const existingById = current.events.find(candidate => candidate.eventId === event.eventId);
				const existing = current.events.find(candidate => candidate.idempotencyKey === event.idempotencyKey);
				if (existingById && (!existing || existingById.idempotencyKey !== event.idempotencyKey)) {
					throw new CtfError("integrity_error", `event ID already exists in the canonical log: ${event.eventId}`);
				}
				if (existing) {
					if (
						!equivalentEventIdentity(existing, event) ||
						!digestsEqual(existing.payloadDigest, event.payloadDigest)
					) {
						throw new CtfError(
							"idempotency_conflict",
							`idempotency key already represents a different event: ${event.idempotencyKey}`,
						);
					}
					const digest = eventDigest(existing);
					return { event: existing, digest, appended: false, metadata: current };
				}
				const expectedRevision = current.revision + 1;
				if (event.revision <= current.revision) {
					throw new CtfError("integrity_error", "event append would rewrite an existing canonical revision", {
						details: { revision: event.revision, currentRevision: current.revision },
					});
				}
				if (event.previousRevision !== current.revision || event.revision !== expectedRevision) {
					throw new CtfError(
						"revision_conflict",
						`event is based on revision ${event.previousRevision}, current revision is ${current.revision}`,
						{
							retryable: true,
							details: { expectedRevision, actualRevision: event.revision, currentRevision: current.revision },
						},
					);
				}
				if (!digestsEqual(event.previousEventDigest, current.digest)) {
					throw new CtfError("integrity_error", "event predecessor digest does not match canonical head");
				}
				await this.store.appendJsonl(this.path, event, options);
				const next = this.parseRaw(await this.readRaw());
				return { event, digest: eventDigest(event), appended: true, metadata: next };
			},
			options,
		);
	}

	async appendDraft(
		draft: EventDraft,
		options?: RootedStoreOperationOptions,
		expectedRevision?: number,
		capability?: GraphEventWriterCapability,
	): Promise<EventAppendResult> {
		const validatedCapability = validateGraphWriterAuthority(draft, capability);
		return this.store.withLock(
			this.path,
			async () => {
				await assertLiveGraphWriterAuthority(draft, validatedCapability, this.leaseVerifier);
				const current = this.parseRaw(await this.readRaw());
				const existingById =
					draft.eventId === undefined
						? undefined
						: current.events.find(candidate => candidate.eventId === draft.eventId);
				const existing = current.events.find(candidate => candidate.idempotencyKey === draft.idempotencyKey);
				if (existingById && (!existing || existingById.idempotencyKey !== draft.idempotencyKey)) {
					throw new CtfError("integrity_error", `event ID already exists in the canonical log: ${draft.eventId}`);
				}
				if (existing) {
					const payloadDigest = eventPayloadDigest({ payload: draft.payload });
					if (
						existing.eventType !== draft.eventType ||
						existing.competitionId !== draft.competitionId ||
						existing.challengeId !== draft.challengeId ||
						existing.runId !== draft.runId ||
						!digestsEqual(existing.payloadDigest, payloadDigest)
					) {
						throw new CtfError(
							"idempotency_conflict",
							`idempotency key already represents a different event: ${draft.idempotencyKey}`,
						);
					}
					return { event: existing, digest: eventDigest(existing), appended: false, metadata: current };
				}
				if (expectedRevision !== undefined && expectedRevision !== current.revision) {
					throw new CtfError(
						"revision_conflict",
						`event draft is based on revision ${expectedRevision}, current revision is ${current.revision}`,
						{
							retryable: true,
							details: { expectedRevision, currentRevision: current.revision },
						},
					);
				}
				const event = makeEvent(draft, current.revision + 1, current.digest);
				this.validateIdentity(event);
				validateGraphWriterAuthority(event, validatedCapability);
				await this.store.appendJsonl(this.path, event, options);
				const next = this.parseRaw(await this.readRaw());
				return { event, digest: eventDigest(event), appended: true, metadata: next };
			},
			options,
		);
	}
}

export const EventLog = CanonicalEventLog;
export const CanonicalEventWriter = CanonicalEventLog;
export const EventStore = CanonicalEventLog;
export function readCanonicalEvents(
	store: CtfStateStoreLike,
	identity: EventLogIdentity = {},
): Promise<EventLogReadResult> {
	return new CanonicalEventLog(store, identity).read();
}
export const readEventLog = readCanonicalEvents;
