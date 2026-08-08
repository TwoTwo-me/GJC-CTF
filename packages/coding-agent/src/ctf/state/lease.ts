import { randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as z from "zod/v4";
import type { RootedStoreOperationOptions } from "../../gjc-runtime/storage/rooted-store";
import { CtfIdSchema, PositiveIntegerSchema, TimestampSchema } from "../contracts/common";
import { CtfError } from "../contracts/errors";
import {
	type ProcessIdentity,
	type RunOwnerV1,
	type RunState,
	validateRunOwner,
	validateRunTransition,
} from "../contracts/run";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";
import { type CtfStateStore, type CtfStateStoreLike, createCtfStateStore } from "./storage";

export const CTF_LEASES_DIR = "leases" as const;
export const DEFAULT_LEASE_DURATION_MS = 30_000;

export interface LeaseAcquireInput {
	competitionId: string;
	challengeId: string;
	runId?: string;
	ownerId: string;
	gJCSessionId?: string;
	teamName?: string;
	teamStateRoot?: string;
	processIdentity: ProcessIdentity;
	state?: RunState;
	leaseDurationMs?: number;
	now?: Date | string;
	takeoverOf?: string;
}

export interface LeaseRenewInput {
	runId: string;
	expectedFencingToken: number;
	ownerId: string;
	leaseDurationMs?: number;
	now?: Date | string;
}

export interface LeaseFence {
	readonly runId: string;
	readonly fencingToken: number;
	readonly ownerId: string;
	readonly expiresAt: string;
}

export const LeaseFenceSchema = z
	.object({
		runId: CtfIdSchema,
		fencingToken: PositiveIntegerSchema,
		ownerId: CtfIdSchema,
		expiresAt: TimestampSchema,
	})
	.strict();
export type LeaseFenceV1 = z.infer<typeof LeaseFenceSchema>;
export interface RunLeaseVerifier {
	assertFence(runId: string, fencingToken: number, nowValue?: Date | string): Promise<unknown> | unknown;
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

function timestamp(now: Date | string | undefined): Date {
	const value = now instanceof Date ? now : new Date(now ?? Date.now());
	if (!Number.isFinite(value.getTime())) throw new CtfError("invalid_transition", "lease timestamp is invalid");
	return value;
}

function iso(value: Date): string {
	return value.toISOString();
}

function leasePath(owner: Pick<RunOwnerV1, "competitionId" | "challengeId">): string {
	return `${CTF_LEASES_DIR}/${encodeURIComponent(owner.competitionId)}/${encodeURIComponent(owner.challengeId)}.json`;
}

function duration(value: number | undefined): number {
	const result = value ?? DEFAULT_LEASE_DURATION_MS;
	if (!Number.isInteger(result) || result <= 0 || result > 24 * 60 * 60 * 1000) {
		throw new CtfError("invalid_transition", "lease duration must be a positive interval no longer than 24 hours");
	}
	return result;
}
const TERMINAL_RUN_STATES: readonly RunState[] = ["solved", "failed", "blocked", "aborted"];

function isTerminalRunState(state: RunState): boolean {
	return TERMINAL_RUN_STATES.includes(state);
}

/** Fenced, single-owner lease authority for one competition/challenge lane. */
export class RunLeaseStore implements RunLeaseVerifier {
	readonly store: CtfStateStore;
	readonly competitionId?: string;
	readonly challengeId?: string;

	constructor(
		store: CtfStateStoreLike,
		identity: { competitionId?: string; challengeId?: string } = {},
		options?: RootedStoreOperationOptions,
	) {
		this.store = createCtfStateStore(store, options);
		this.competitionId = identity.competitionId;
		this.challengeId = identity.challengeId;
	}

	private pathFor(run: Pick<RunOwnerV1, "competitionId" | "challengeId">): string {
		if (this.competitionId !== undefined && this.competitionId !== run.competitionId)
			throw new CtfError("cross_challenge_reference", "lease competition does not match store identity");
		if (this.challengeId !== undefined && this.challengeId !== run.challengeId)
			throw new CtfError("cross_challenge_reference", "lease challenge does not match store identity");
		return leasePath(run);
	}

	private async readPath(path: string): Promise<RunOwnerV1 | undefined> {
		try {
			const raw = await fs.readFile(this.store.resolve(path), "utf8");
			let parsed: unknown;
			try {
				parsed = JSON.parse(raw);
			} catch (error) {
				throw new CtfError("integrity_error", "lease file is not valid JSON", {
					details: { cause: error instanceof Error ? error.message : String(error) },
				});
			}
			const validated = validateRunOwner(withoutWriterReceipt(parsed));
			return validated;
		} catch (error) {
			if (isErrno(error, "ENOENT")) return undefined;
			if (error instanceof CtfError) throw error;
			throw new CtfError("integrity_error", "lease file could not be read", {
				details: { cause: error instanceof Error ? error.message : String(error) },
			});
		}
	}

	private assertActive(current: RunOwnerV1, now: Date): void {
		if (new Date(current.expiresAt).getTime() <= now.getTime())
			throw new CtfError("stale_run_fence", "run lease has expired", { retryable: true });
	}
	private assertMutable(current: RunOwnerV1, operation: string): void {
		if (isTerminalRunState(current.state)) {
			throw new CtfError("invalid_transition", `cannot ${operation} a terminal run lease`);
		}
	}

	async read(competitionId = this.competitionId, challengeId = this.challengeId): Promise<RunOwnerV1 | undefined> {
		if (!competitionId || !challengeId)
			throw new CtfError("invalid_manifest", "competitionId and challengeId are required to read a lease");
		if (competitionId !== this.competitionId || challengeId !== this.challengeId) {
			throw new CtfError("cross_challenge_reference", "lease identity does not match its store");
		}
		return this.readPath(leasePath({ competitionId, challengeId }));
	}

	async acquire(input: LeaseAcquireInput, options?: RootedStoreOperationOptions): Promise<RunOwnerV1> {
		const now = timestamp(input.now);
		const leaseDuration = duration(input.leaseDurationMs);
		const runId = input.runId ?? randomUUID();
		const target = leasePath({ competitionId: input.competitionId, challengeId: input.challengeId });
		return this.store.withLock(
			target,
			async () => {
				const current = await this.readPath(target);
				if (current) {
					this.assertMutable(current, "take over");
					if (input.takeoverOf !== current.runId || runId === current.runId) {
						throw new CtfError(
							"stale_run_fence",
							"active or stale lease requires an explicit takeover of its run",
							{ retryable: true },
						);
					}
					if (new Date(current.expiresAt).getTime() > now.getTime()) {
						throw new CtfError("stale_run_fence", "cannot take over an unexpired run lease", { retryable: true });
					}
				}
				const fencingToken = current ? current.fencingToken + 1 : 1;
				const owner: RunOwnerV1 = validateRunOwner({
					schemaVersion: CTF_SCHEMA_VERSIONS.runOwner,
					runId,
					competitionId: input.competitionId,
					challengeId: input.challengeId,
					ownerId: input.ownerId,
					fencingToken,
					...(input.gJCSessionId === undefined ? {} : { gJCSessionId: input.gJCSessionId }),
					...(input.teamName === undefined ? {} : { teamName: input.teamName }),
					...(input.teamStateRoot === undefined ? {} : { teamStateRoot: input.teamStateRoot }),
					processIdentity: input.processIdentity,
					state: input.state ?? "created",
					startedAt: iso(now),
					lastHeartbeat: iso(now),
					expiresAt: iso(new Date(now.getTime() + leaseDuration)),
					...(current ? { takeoverOf: current.runId, takeoverAt: iso(now) } : {}),
				});
				this.pathFor(owner);
				await this.store.writeJsonAtomic(target, owner, options);
				return owner;
			},
			options,
		);
	}

	async renew(input: LeaseRenewInput, options?: RootedStoreOperationOptions): Promise<RunOwnerV1> {
		const now = timestamp(input.now);
		const target = await this.pathForRun(input.runId);
		return this.store.withLock(
			target,
			async () => {
				const current = await this.readPath(target);
				if (
					!current ||
					current.runId !== input.runId ||
					current.ownerId !== input.ownerId ||
					current.fencingToken !== input.expectedFencingToken
				) {
					throw new CtfError("stale_run_fence", "lease owner or fencing token is stale", { retryable: true });
				}
				this.assertMutable(current, "renew");
				this.assertActive(current, now);
				const next = validateRunOwner({
					...current,
					lastHeartbeat: iso(now),
					expiresAt: iso(new Date(now.getTime() + duration(input.leaseDurationMs))),
				});
				await this.store.writeJsonAtomic(target, next, options);
				return next;
			},
			options,
		);
	}

	async transition(
		runId: string,
		expectedFencingToken: number,
		ownerId: string,
		state: RunState,
		nowValue: Date | string = new Date(),
		options?: RootedStoreOperationOptions,
	): Promise<RunOwnerV1> {
		const now = timestamp(nowValue);
		const target = await this.pathForRun(runId);
		return this.store.withLock(
			target,
			async () => {
				const current = await this.readPath(target);
				if (
					!current ||
					current.runId !== runId ||
					current.ownerId !== ownerId ||
					current.fencingToken !== expectedFencingToken
				)
					throw new CtfError("stale_run_fence", "lease owner or fencing token is stale", { retryable: true });
				this.assertMutable(current, "transition");
				this.assertActive(current, now);
				const next = validateRunTransition(
					current,
					validateRunOwner({ ...current, state, lastHeartbeat: iso(now) }),
				);
				await this.store.writeJsonAtomic(target, next, options);
				return next;
			},
			options,
		);
	}

	async assertFence(runId: string, fencingToken: number, nowValue: Date | string = new Date()): Promise<LeaseFenceV1> {
		const current = await this.findByRunId(runId);
		if (!current || current.runId !== runId || current.fencingToken !== fencingToken)
			throw new CtfError("stale_run_fence", "run fencing token is stale", { retryable: true });
		this.assertMutable(current, "authorize a fenced operation");
		this.assertActive(current, timestamp(nowValue));
		return {
			runId: current.runId,
			fencingToken: current.fencingToken,
			ownerId: current.ownerId,
			expiresAt: current.expiresAt,
		};
	}

	private async pathForRun(runId: string): Promise<string> {
		const current = await this.findByRunId(runId);
		if (!current) throw new CtfError("stale_run_fence", "run lease not found", { retryable: true });
		return this.pathFor(current);
	}

	private async findByRunId(runId: string): Promise<RunOwnerV1 | undefined> {
		if (this.competitionId && this.challengeId) {
			const current = await this.read(this.competitionId, this.challengeId);
			return current?.runId === runId ? current : undefined;
		}
		throw new CtfError("invalid_manifest", "lease store identity is required to resolve a run");
	}
}

export const FencedRunLease = RunLeaseStore;
export const RunLease = RunLeaseStore;
export const RunOwnershipStore = RunLeaseStore;
