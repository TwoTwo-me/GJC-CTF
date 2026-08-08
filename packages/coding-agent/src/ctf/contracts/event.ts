import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, NonNegativeIntegerSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

/**
 * A graph-event append is authorized by a typed writer capability rather
 * than by the free-form actor/authority strings carried in a transition
 * payload. The capability is bound to one run fence and actor.
 *
 * Fixture capabilities are deliberately branded by the factory below. This
 * keeps the unavailable/fixture path explicit and prevents a raw
 * `fencingToken: 0` object from being treated as authority.
 */
const GRAPH_EVENT_WRITER_CAPABILITY_SCHEMA_VERSION = "ctf-graph-writer-capability-1" as const;
const GRAPH_EVENT_WRITER_CAPABILITY_BRAND = Symbol("ctf.graph-event-writer-capability.fixture");

const GraphEventWriterCapabilityBaseSchema = z
	.object({
		schemaVersion: z.literal(GRAPH_EVENT_WRITER_CAPABILITY_SCHEMA_VERSION),
		kind: z.enum(["run", "fixture"]),
		competitionId: CtfIdSchema,
		challengeId: CtfIdSchema,
		runId: CtfIdSchema,
		actor: CtfIdSchema,
		fencingToken: NonNegativeIntegerSchema,
	})
	.strict();

const RunGraphEventWriterCapabilitySchema = GraphEventWriterCapabilityBaseSchema.extend({
	kind: z.literal("run"),
	fencingToken: PositiveIntegerSchema,
});

const FixtureGraphEventWriterCapabilitySchema = GraphEventWriterCapabilityBaseSchema.extend({
	kind: z.literal("fixture"),
	fencingToken: z.literal(0),
});

type FixtureGraphEventWriterCapabilityBrand = {
	readonly [GRAPH_EVENT_WRITER_CAPABILITY_BRAND]: true;
};

export type RunGraphEventWriterCapability = z.infer<typeof RunGraphEventWriterCapabilitySchema>;
export type FixtureGraphEventWriterCapability = z.infer<typeof FixtureGraphEventWriterCapabilitySchema> &
	FixtureGraphEventWriterCapabilityBrand;
export type GraphEventWriterCapability = RunGraphEventWriterCapability | FixtureGraphEventWriterCapability;

export const GraphEventWriterCapabilitySchema = z.union([
	RunGraphEventWriterCapabilitySchema,
	FixtureGraphEventWriterCapabilitySchema,
]);

function brandFixtureGraphEventWriterCapability(
	value: z.infer<typeof FixtureGraphEventWriterCapabilitySchema>,
): FixtureGraphEventWriterCapability {
	Object.defineProperty(value, GRAPH_EVENT_WRITER_CAPABILITY_BRAND, {
		configurable: false,
		enumerable: false,
		value: true,
		writable: false,
	});
	return value as FixtureGraphEventWriterCapability;
}

/** Validate and construct a graph writer capability; fixture authority is explicitly branded. */
export function createGraphEventWriterCapability(value: unknown): GraphEventWriterCapability {
	const parsed = GraphEventWriterCapabilitySchema.safeParse(value);
	if (!parsed.success) {
		throw new CtfError("stale_run_fence", "graph event writer capability is invalid", {
			details: { issues: parsed.error.issues },
		});
	}
	if (parsed.data.kind === "fixture") return brandFixtureGraphEventWriterCapability(parsed.data);
	return parsed.data;
}

/** Construct the explicit fixture/unavailable graph writer capability. */
export function createFixtureGraphEventWriterCapability(input: {
	competitionId: string;
	challengeId: string;
	runId: string;
	actor: string;
}): FixtureGraphEventWriterCapability {
	return createGraphEventWriterCapability({
		schemaVersion: GRAPH_EVENT_WRITER_CAPABILITY_SCHEMA_VERSION,
		kind: "fixture",
		...input,
		fencingToken: 0,
	}) as FixtureGraphEventWriterCapability;
}

/**
 * Parse and validate a capability supplied explicitly by a caller. Fixture
 * values returned from this validator are branded, so passing the returned
 * value into an event append is an explicit authority decision.
 */
export function validateGraphEventWriterCapability(value: unknown): GraphEventWriterCapability {
	return createGraphEventWriterCapability(value);
}

/** Reject an unvalidated fixture-shaped value at the event-log authority boundary. */
export function assertGraphEventWriterCapability(value: unknown): GraphEventWriterCapability {
	if (
		typeof value === "object" &&
		value !== null &&
		!Array.isArray(value) &&
		(value as { kind?: unknown }).kind === "fixture" &&
		!(GRAPH_EVENT_WRITER_CAPABILITY_BRAND in value)
	) {
		throw new CtfError("stale_run_fence", "fixture graph writer capability must be explicitly validated");
	}
	return createGraphEventWriterCapability(value);
}

export const GraphWriterCapabilitySchema = GraphEventWriterCapabilitySchema;
export const createGraphWriterCapability = createGraphEventWriterCapability;
export const createFixtureGraphWriterCapability = createFixtureGraphEventWriterCapability;
export const validateGraphWriterCapability = validateGraphEventWriterCapability;
export const assertGraphWriterCapability = assertGraphEventWriterCapability;

/**
 * A graph transition attributed to an oracle is not authorized by the actor
 * string in the event envelope. It must carry this typed, content-bound
 * proof. The proof intentionally contains digests rather than oracle bytes:
 * external registry/result material is not fabricated by graph replay.
 */
export const OracleTransitionProofSchema = z
	.object({
		schemaVersion: z.literal("ctf-oracle-transition-proof-1"),
		authority: z.enum(["oracle", "preflight"]),
		registryDigest: DigestSchema,
		oracleEntryDigest: DigestSchema,
		oracleResultDigest: DigestSchema.optional(),
		preflightReportDigest: DigestSchema.optional(),
		transitionDigest: DigestSchema,
		evidenceDigest: DigestSchema,
		signerKeyId: CtfIdSchema,
		signatureAlgorithm: z.literal("ed25519"),
		signature: z.string().min(1).max(16_384),
	})
	.strict()
	.superRefine((proof, ctx) => {
		if (proof.authority === "oracle" && proof.oracleResultDigest === undefined) {
			ctx.addIssue({
				code: "custom",
				path: ["oracleResultDigest"],
				message: "oracle proof requires an oracle result digest",
			});
		}
		if (proof.authority === "preflight" && proof.preflightReportDigest === undefined) {
			ctx.addIssue({
				code: "custom",
				path: ["preflightReportDigest"],
				message: "preflight proof requires a preflight report digest",
			});
		}
		if (proof.authority === "oracle" && proof.preflightReportDigest !== undefined) {
			ctx.addIssue({
				code: "custom",
				path: ["preflightReportDigest"],
				message: "oracle proof cannot carry a preflight report digest",
			});
		}
		if (proof.authority === "preflight" && proof.oracleResultDigest !== undefined) {
			ctx.addIssue({
				code: "custom",
				path: ["oracleResultDigest"],
				message: "preflight proof cannot carry an oracle result digest",
			});
		}
	});
export type OracleTransitionProof = z.infer<typeof OracleTransitionProofSchema>;

/** Digest of the complete node/edge transition represented by an event. */
export function oracleTransitionDigest(input: {
	eventType: "node_transition" | "edge_transition";
	before?: unknown;
	after: unknown;
}): Digest {
	return canonicalDigest({
		eventType: input.eventType,
		before: input.before ?? null,
		after: input.after,
	});
}

/** Digest binding the proof to the canonical event evidence references. */
export function oracleEvidenceDigest(evidenceRefs: readonly string[]): Digest {
	return canonicalDigest([...evidenceRefs]);
}

export function validateOracleTransitionProof(value: unknown): OracleTransitionProof {
	const parsed = OracleTransitionProofSchema.safeParse(value);
	if (!parsed.success) {
		throw new CtfError("oracle_integrity_error", "oracle transition proof is invalid", {
			details: { issues: parsed.error.issues },
		});
	}
	return parsed.data;
}
export const OracleProofSchema = OracleTransitionProofSchema;
export const OraclePreflightProofSchema = OracleTransitionProofSchema;
export const parseOracleTransitionProof = validateOracleTransitionProof;
export const EventTypeSchema = z.enum([
	"challenge_registered",
	"run_created",
	"run_started",
	"run_heartbeat",
	"run_interrupted",
	"run_takeover",
	"run_terminal",
	"intent_accepted",
	"intent_rejected",
	"node_transition",
	"edge_transition",
	"benchmark_locked",
]);
export type EventType = z.infer<typeof EventTypeSchema>;

export const EventV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.event),
		eventId: CtfIdSchema,
		eventType: EventTypeSchema,
		competitionId: CtfIdSchema,
		challengeId: CtfIdSchema,
		runId: CtfIdSchema.optional(),
		previousRevision: NonNegativeIntegerSchema,
		revision: PositiveIntegerSchema,
		idempotencyKey: CtfIdSchema,
		payloadDigest: DigestSchema,
		previousEventDigest: DigestSchema,
		actor: CtfIdSchema,
		occurredAt: TimestampSchema,
		payload: z.record(z.string(), z.unknown()),
		evidenceRefs: z.array(DigestSchema),
	})
	.strict()
	.superRefine((event, ctx) => {
		if (event.revision !== event.previousRevision + 1) {
			ctx.addIssue({
				code: "custom",
				path: ["revision"],
				message: "revision must advance exactly one step",
			});
		}
	});
export type EventV1 = z.infer<typeof EventV1Schema>;

export function eventPayloadDigest(event: Pick<EventV1, "payload">): Digest {
	return canonicalDigest(event.payload);
}

export function eventDigest(event: Omit<EventV1, "digest"> | EventV1): Digest {
	return canonicalDigest(event, ["digest"]);
}

function transitionPayloadValue(payload: Record<string, unknown>, names: readonly string[]): unknown {
	const present = names.filter(name => payload[name] !== undefined);
	if (present.length !== 1) return undefined;
	return payload[present[0]!];
}

function requiresOracleProof(event: EventV1): boolean {
	if (event.eventType === "edge_transition") return true;
	if (event.eventType !== "node_transition") return false;
	const before = transitionPayloadValue(event.payload, ["before", "current", "previous", "from"]);
	const after = transitionPayloadValue(event.payload, ["after", "next", "node", "to"]);
	if (typeof before !== "object" || before === null || typeof after !== "object" || after === null) return false;
	const current = before as { type?: unknown; state?: unknown };
	const next = after as { type?: unknown; state?: unknown };
	return (
		(current.type === "Evidence" && current.state === "observed" && next.state === "verified") ||
		(current.type === "Goal" && current.state === "open" && next.state === "satisfied") ||
		(current.type === "Blocker" && current.state === "open" && next.state === "resolved")
	);
}

function validateOracleProofEnvelope(event: EventV1): void {
	if (!requiresOracleProof(event)) return;
	const authorityValue = event.payload.authority;
	const authority =
		typeof authorityValue === "object" && authorityValue !== null && !Array.isArray(authorityValue)
			? (authorityValue as { authority?: unknown }).authority
			: authorityValue;
	if (authority !== "oracle" && authority !== "preflight") return;
	const proofValue = event.payload.oracleProof;
	if (proofValue === undefined) {
		throw new CtfError("invalid_transition", `${authority} transition requires a typed oracle proof`);
	}
	const proof = validateOracleTransitionProof(proofValue);
	if (proof.authority !== authority) {
		throw new CtfError("invalid_transition", "oracle proof authority does not match transition authority");
	}
	if (proof.evidenceDigest !== oracleEvidenceDigest(event.evidenceRefs)) {
		throw new CtfError("invalid_transition", "oracle proof evidence digest does not match canonical event evidence");
	}
	const boundDigest = proof.oracleResultDigest ?? proof.preflightReportDigest;
	if (boundDigest === undefined || !event.evidenceRefs.includes(boundDigest)) {
		throw new CtfError(
			"invalid_transition",
			"oracle proof result/preflight digest is not present in canonical evidence",
		);
	}
}
export function validateEvent(value: unknown): EventV1 {
	const parsed = EventV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("integrity_error", "event envelope is invalid", {
			details: { issues: parsed.error.issues },
		});
	const event = parsed.data;
	assertKnownMajor(event.schemaVersion, "event");
	if (!digestsEqual(eventPayloadDigest(event), event.payloadDigest))
		throw new CtfError("digest_mismatch", `event payload digest mismatch: ${event.eventId}`);
	validateOracleProofEnvelope(event);
	return event;
}

export function parseEvent(value: unknown): EventV1 {
	return validateEvent(value);
}
export const EventSchema = EventV1Schema;
export const parseEventV1 = parseEvent;
