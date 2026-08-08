import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, EvidenceRefsSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const IntentActionSchema = z
	.object({
		actionId: CtfIdSchema,
		kind: z.string().min(1).max(128),
		parameters: z.record(z.string(), z.unknown()),
	})
	.strict();
export type IntentAction = z.infer<typeof IntentActionSchema>;

export const ClaimLifecycleStateSchema = z.enum(["starting", "ready", "running", "completed", "released", "failed"]);
export type ClaimLifecycleState = z.infer<typeof ClaimLifecycleStateSchema>;

export const ClaimProofV1Schema = z
	.object({
		teamName: CtfIdSchema,
		taskId: CtfIdSchema,
		workerId: CtfIdSchema,
		claimToken: CtfIdSchema,
		lane: CtfIdSchema,
		requiredRole: CtfIdSchema,
		teamStateRevision: PositiveIntegerSchema,
		lifecycleState: ClaimLifecycleStateSchema,
		startupAckDigest: DigestSchema,
		claimDigest: DigestSchema,
		observedAt: TimestampSchema,
		expiresAt: TimestampSchema,
		source: z.literal("gjc-team-api"),
	})
	.strict();
export type ClaimProofV1 = z.infer<typeof ClaimProofV1Schema>;

export const IntentV2Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.intent),
		intentId: CtfIdSchema,
		intentVersion: PositiveIntegerSchema,
		competitionId: CtfIdSchema,
		challengeId: CtfIdSchema,
		runId: CtfIdSchema,
		runFencingToken: PositiveIntegerSchema,
		teamName: CtfIdSchema,
		taskId: CtfIdSchema,
		workerId: CtfIdSchema,
		lane: CtfIdSchema,
		requiredRole: CtfIdSchema,
		claimToken: CtfIdSchema,
		claimExpiresAt: TimestampSchema,
		claimProofDigest: DigestSchema,
		baseRevision: z.number().int().nonnegative(),
		idempotencyKey: CtfIdSchema,
		payloadDigest: DigestSchema,
		createdAt: TimestampSchema,
		action: IntentActionSchema,
		evidenceRefs: EvidenceRefsSchema,
		payload: z.record(z.string(), z.unknown()),
	})
	.strict();
export type IntentV2 = z.infer<typeof IntentV2Schema>;

export function intentPayloadDigest(intent: Pick<IntentV2, "payload">): Digest {
	return canonicalDigest(intent.payload);
}

export function claimProofDigest(proof: ClaimProofV1): Digest {
	return canonicalDigest(proof);
}

export function validateClaimProof(value: unknown): ClaimProofV1 {
	const parsed = ClaimProofV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("stale_claim", "claim proof is invalid", { details: { issues: parsed.error.issues } });
	const proof = parsed.data;
	if (proof.lifecycleState === "released" || proof.lifecycleState === "failed")
		throw new CtfError("stale_claim", "released or failed claim cannot authorize an intent");
	return proof;
}

export function validateIntent(value: unknown): IntentV2 {
	const parsed = IntentV2Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_registration", "worker intent is invalid", {
			details: { issues: parsed.error.issues },
		});
	const intent = parsed.data;
	assertKnownMajor(intent.schemaVersion, "intent");
	if (!digestsEqual(intentPayloadDigest(intent), intent.payloadDigest))
		throw new CtfError("digest_mismatch", `intent payload digest mismatch: ${intent.intentId}`);
	return intent;
}

export function parseIntent(value: unknown): IntentV2 {
	return validateIntent(value);
}
export const IntentSchema = IntentV2Schema;
export const ClaimProofSchema = ClaimProofV1Schema;
export const parseIntentV2 = parseIntent;
