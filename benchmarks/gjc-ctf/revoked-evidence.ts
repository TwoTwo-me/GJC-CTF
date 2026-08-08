import { digestsEqual, isDigest, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";

export type LactfEvidenceRevocation = Readonly<{
	digest: Digest;
	reasonCode: "clean_room_allowlist_exposed_plaintext_source";
	evidenceRef: "artifacts/ctf/lactf-expanded-v2-invalidation.json";
}>;

export const LACTF_REVOKED_EVIDENCE = Object.freeze([
	Object.freeze({
		digest: "3a834bd5cbb0a988e8c948ea454255d22ec3d3851b8617a64f6c1d920376e557",
		reasonCode: "clean_room_allowlist_exposed_plaintext_source",
		evidenceRef: "artifacts/ctf/lactf-expanded-v2-invalidation.json",
	}),
	Object.freeze({
		digest: "c79832bdc48d24983b525f40ac6587ccb21651a3bcb4d3e668d27c1d6ef8d13a",
		reasonCode: "clean_room_allowlist_exposed_plaintext_source",
		evidenceRef: "artifacts/ctf/lactf-expanded-v2-invalidation.json",
	}),
	Object.freeze({
		digest: "324f9efd0f9237b9fdcfd8d32c9d744929a878bceb48f4ffe575e4222c03f147",
		reasonCode: "clean_room_allowlist_exposed_plaintext_source",
		evidenceRef: "artifacts/ctf/lactf-expanded-v2-invalidation.json",
	}),
] as const satisfies readonly LactfEvidenceRevocation[]);

export function lactfEvidenceRevocation(digest: unknown): LactfEvidenceRevocation | undefined {
	if (!isDigest(digest)) return undefined;
	return LACTF_REVOKED_EVIDENCE.find(entry => digestsEqual(entry.digest, digest));
}

export function assertLactfEvidenceActive(digest: unknown): asserts digest is Digest {
	if (!isDigest(digest)) throw new Error("LA CTF evidence digest is invalid");
	const revocation = lactfEvidenceRevocation(digest);
	if (revocation !== undefined) {
		throw new Error(`LA CTF evidence is invalidated (${revocation.reasonCode}); see ${revocation.evidenceRef}`);
	}
}
