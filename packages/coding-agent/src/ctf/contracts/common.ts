import * as z from "zod/v4";
import { DIGEST_HEX_PATTERN } from "./digest";

export const DigestSchema = z.string().regex(DIGEST_HEX_PATTERN, "expected lowercase SHA-256 digest");
export type DigestValue = z.infer<typeof DigestSchema>;
export const CtfIdSchema = z
	.string()
	.min(1)
	.max(256)
	.regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
export const PositiveIntegerSchema = z.number().int().positive();
export const NonNegativeIntegerSchema = z.number().int().nonnegative();
export const RatioSchema = z.number().finite().min(0).max(1);
export const TimestampSchema = z.string().datetime({ offset: true });

/** Provenance is explicit and content-addressed; paths are intentionally not accepted. */
export const ProvenanceSchema = z.object({
	challengeId: CtfIdSchema,
	source: z.string().min(1).max(256),
	actor: z.string().min(1).max(256),
	digest: DigestSchema,
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

export const EvidenceRefsSchema = z.array(DigestSchema).min(1);
export type EvidenceRefs = z.infer<typeof EvidenceRefsSchema>;

export function requireDistinctIds(ids: readonly string[], label: string): void {
	if (new Set(ids).size !== ids.length) throw new Error(`${label} contains duplicate IDs`);
}

export function requirePositiveFinite(value: number, label: string): void {
	if (!Number.isInteger(value) || value <= 0 || !Number.isFinite(value))
		throw new Error(`${label} must be a positive finite integer`);
}
