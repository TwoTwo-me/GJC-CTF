import { createHash, timingSafeEqual } from "node:crypto";

export type Digest = string & { readonly __ctfDigest: unique symbol };
export const DIGEST_HEX_PATTERN = /^[a-f0-9]{64}$/;

function canonicalizeValue(value: unknown, omitKeys: ReadonlySet<string>): string {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new TypeError("canonical JSON cannot contain a non-finite number");
		return JSON.stringify(value);
	}
	if (typeof value === "bigint") throw new TypeError("canonical JSON cannot contain bigint");
	if (value === undefined || typeof value === "function" || typeof value === "symbol") {
		throw new TypeError("canonical JSON cannot contain undefined or non-JSON values");
	}
	if (Array.isArray(value)) return `[${value.map(item => canonicalizeValue(item, new Set())).join(",")}]`;
	if (typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter(key => !omitKeys.has(key))
			.sort();
		return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalizeValue(record[key], new Set())}`).join(",")}}`;
	}
	throw new TypeError("canonical JSON contains an unsupported value");
}

/** Deterministic RFC-8785-style JSON for plain JSON data. */
export function canonicalJson(value: unknown, omitKeys: readonly string[] = []): string {
	return canonicalizeValue(value, new Set(omitKeys));
}

export function sha256Hex(value: string | Uint8Array): Digest {
	return createHash("sha256").update(value).digest("hex") as Digest;
}

export function canonicalDigest(value: unknown, omitKeys: readonly string[] = []): Digest {
	return sha256Hex(canonicalJson(value, omitKeys));
}

export function isDigest(value: unknown): value is Digest {
	return typeof value === "string" && DIGEST_HEX_PATTERN.test(value);
}

export function assertDigest(value: unknown, label = "digest"): asserts value is Digest {
	if (!isDigest(value)) throw new TypeError(`${label} must be a lowercase SHA-256 hex digest`);
}

export function digestsEqual(left: string, right: string): boolean {
	if (!DIGEST_HEX_PATTERN.test(left) || !DIGEST_HEX_PATTERN.test(right)) return false;
	return timingSafeEqual(Buffer.from(left, "ascii"), Buffer.from(right, "ascii"));
}

/** Verify a self-described digest without trusting its digest property as input. */
export function verifyCanonicalDigest(
	value: unknown,
	digest: unknown,
	omitKeys: readonly string[] = ["digest"],
): boolean {
	return isDigest(digest) && digestsEqual(canonicalDigest(value, omitKeys), digest);
}
export const canonicalize = canonicalJson;
export const digestCanonical = canonicalDigest;
export const sha256 = sha256Hex;
