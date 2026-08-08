import * as z from "zod/v4";
import { CtfIdSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const RunStateSchema = z.enum([
	"created",
	"running",
	"interrupted",
	"resuming",
	"solved",
	"failed",
	"blocked",
	"aborted",
]);
export type RunState = z.infer<typeof RunStateSchema>;

export const ProcessIdentitySchema = z
	.object({
		pid: PositiveIntegerSchema,
		hostFingerprint: z.string().min(1).max(256),
	})
	.strict();
export type ProcessIdentity = z.infer<typeof ProcessIdentitySchema>;

export const RunOwnerV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.runOwner),
		runId: CtfIdSchema,
		competitionId: CtfIdSchema,
		challengeId: CtfIdSchema,
		ownerId: CtfIdSchema,
		fencingToken: PositiveIntegerSchema,
		gJCSessionId: CtfIdSchema.optional(),
		teamName: CtfIdSchema.optional(),
		teamStateRoot: z.string().min(1).max(1024).optional(),
		processIdentity: ProcessIdentitySchema,
		state: RunStateSchema,
		startedAt: TimestampSchema,
		lastHeartbeat: TimestampSchema,
		expiresAt: TimestampSchema,
		takeoverOf: CtfIdSchema.optional(),
		takeoverAt: TimestampSchema.optional(),
	})
	.strict();
export type RunOwnerV1 = z.infer<typeof RunOwnerV1Schema>;

const RUN_TRANSITIONS: Readonly<Record<RunState, readonly RunState[]>> = {
	created: ["running", "aborted"],
	running: ["interrupted", "solved", "failed", "blocked", "aborted"],
	interrupted: ["resuming", "aborted"],
	resuming: ["running", "aborted"],
	solved: [],
	failed: [],
	blocked: [],
	aborted: [],
};

export function allowedRunTransition(from: RunState, to: RunState): boolean {
	return from === to || RUN_TRANSITIONS[from].includes(to);
}

export function validateRunOwner(value: unknown): RunOwnerV1 {
	const parsed = RunOwnerV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_manifest", "run owner is invalid", { details: { issues: parsed.error.issues } });
	const owner = parsed.data;
	assertKnownMajor(owner.schemaVersion, "runOwner");
	if (owner.takeoverOf === undefined && owner.takeoverAt !== undefined)
		throw new CtfError("invalid_transition", "takeoverAt requires takeoverOf");
	if (owner.takeoverOf !== undefined && owner.takeoverOf === owner.runId)
		throw new CtfError("invalid_transition", "run cannot take over itself");
	return owner;
}

export function validateRunTransition(from: RunOwnerV1, to: RunOwnerV1): RunOwnerV1 {
	validateRunOwner(from);
	validateRunOwner(to);
	if (from.runId !== to.runId || from.challengeId !== to.challengeId || from.competitionId !== to.competitionId) {
		throw new CtfError("invalid_transition", "run transition identity mismatch");
	}
	if (!allowedRunTransition(from.state, to.state))
		throw new CtfError("invalid_transition", `run cannot transition from ${from.state} to ${to.state}`);
	if (to.fencingToken < from.fencingToken) throw new CtfError("stale_run_fence", "run fencing token moved backwards");
	return to;
}

export function parseRunOwner(value: unknown): RunOwnerV1 {
	return validateRunOwner(value);
}
export const RunOwnerSchema = RunOwnerV1Schema;
export const parseRunOwnerV1 = parseRunOwner;
