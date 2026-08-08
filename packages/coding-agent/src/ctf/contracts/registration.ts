import * as z from "zod/v4";
import { CtfIdSchema, DigestSchema, PositiveIntegerSchema, TimestampSchema } from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { EventV1Schema } from "./event";
import { ChallengeDescriptorSchema } from "./manifest";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const RegistrationPhaseSchema = z.enum(["prepared", "committed", "aborted"]);
export type RegistrationPhase = z.infer<typeof RegistrationPhaseSchema>;

/** Durable transaction payload; descriptor and deterministic event are retained for crash replay. */
export const RegistrationTxnV1Schema = z
	.object({
		schemaVersion: z.literal(CTF_SCHEMA_VERSIONS.registration),
		txId: CtfIdSchema,
		idempotencyKey: CtfIdSchema,
		competitionId: CtfIdSchema,
		baseManifestRevision: z.number().int().nonnegative(),
		oldManifestDigest: DigestSchema,
		challengeId: CtfIdSchema,
		descriptorDigest: DigestSchema,
		challengeEventDigest: DigestSchema,
		newManifestRevision: PositiveIntegerSchema,
		newManifestDigest: DigestSchema,
		phase: RegistrationPhaseSchema,
		createdAt: TimestampSchema,
		actor: CtfIdSchema,
		descriptor: ChallengeDescriptorSchema,
		challengeEvent: EventV1Schema,
	})
	.strict();
export type RegistrationTxnV1 = z.infer<typeof RegistrationTxnV1Schema>;

export function registrationTxnDigest(txn: RegistrationTxnV1): Digest {
	return canonicalDigest(txn);
}

export function validateRegistrationTxn(value: unknown): RegistrationTxnV1 {
	const parsed = RegistrationTxnV1Schema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("invalid_registration", "registration transaction is invalid", {
			details: { issues: parsed.error.issues },
		});
	const txn = parsed.data;
	assertKnownMajor(txn.schemaVersion, "registration");
	const event = txn.challengeEvent;
	if (
		txn.descriptor.id !== txn.challengeId ||
		event.eventType !== "challenge_registered" ||
		event.competitionId !== txn.competitionId ||
		event.challengeId !== txn.challengeId ||
		event.actor !== txn.actor
	) {
		throw new CtfError("invalid_registration", "registration challenge identity is not linked to its event");
	}
	if (
		event.idempotencyKey !== txn.idempotencyKey ||
		event.payload.descriptorDigest !== txn.descriptorDigest ||
		event.payload.idempotencyKey !== txn.idempotencyKey
	) {
		throw new CtfError("invalid_registration", "registration event is not bound to the transaction");
	}
	if (
		txn.newManifestRevision !== txn.baseManifestRevision + 1 ||
		event.revision !== txn.newManifestRevision ||
		event.previousRevision !== txn.baseManifestRevision
	) {
		throw new CtfError("invalid_registration", "registration event revisions do not match the manifest transition");
	}
	if (!digestsEqual(canonicalDigest(txn.descriptor, ["descriptorDigest"]), txn.descriptorDigest)) {
		throw new CtfError("digest_mismatch", "registration descriptor digest mismatch");
	}
	if (!digestsEqual(canonicalDigest(event), txn.challengeEventDigest)) {
		throw new CtfError("digest_mismatch", "registration challenge event digest mismatch");
	}
	if (event.payload.challengeId !== undefined && event.payload.challengeId !== txn.challengeId) {
		throw new CtfError("invalid_registration", "challenge event payload challenge ID disagrees");
	}
	return txn;
}

export type RegistrationRecoveryInput = {
	transaction: RegistrationTxnV1;
	manifest: { revision: number; digest: string };
	challengeEventDigest?: string;
};
export type RegistrationRecoveryAction =
	| "replay_event_and_manifest"
	| "complete_manifest_and_commit"
	| "complete_event_and_commit"
	| "commit_noop"
	| "registration_repair_required";

/** Classify durable registration state without guessing or mutating bytes. */
export function classifyRegistrationRecovery(input: RegistrationRecoveryInput): RegistrationRecoveryAction {
	const txn = validateRegistrationTxn(input.transaction);
	const oldManifest =
		input.manifest.revision === txn.baseManifestRevision &&
		digestsEqual(input.manifest.digest, txn.oldManifestDigest);
	const newManifest =
		input.manifest.revision === txn.newManifestRevision && digestsEqual(input.manifest.digest, txn.newManifestDigest);
	const event =
		input.challengeEventDigest === undefined
			? false
			: digestsEqual(input.challengeEventDigest, txn.challengeEventDigest);
	if (txn.phase === "committed") return newManifest && event ? "commit_noop" : "registration_repair_required";
	if (txn.phase !== "prepared") return "registration_repair_required";
	if (oldManifest && !event) return "replay_event_and_manifest";
	if (oldManifest && event) return "complete_manifest_and_commit";
	if (newManifest && !event) return "complete_event_and_commit";
	if (newManifest && event) return "commit_noop";
	return "registration_repair_required";
}

export function parseRegistrationTxn(value: unknown): RegistrationTxnV1 {
	return validateRegistrationTxn(value);
}
export const RegistrationTxnSchema = RegistrationTxnV1Schema;
export const parseRegistrationTxnV1 = parseRegistrationTxn;
