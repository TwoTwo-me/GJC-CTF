import { describe, expect, test } from "bun:test";
import { canonicalDigest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { validateLactfVersionStatisticsArtifact } from "./version-observation";

const artifact = (name: string): Promise<unknown> => Bun.file(`artifacts/ctf/${name}`).json();
const evidenceBindings = [
	["lactf-expanded-v2-invalidation.json", [], "gjc-ctf-campaign-invalidation-1"],
	["lactf-tier1-local-evidence-v1.json", [], "gjc-ctf-tier1-local-evidence-1"],
	["ctf-harness-v3-evidence.json", ["evidenceDigest"], "gjc-ctf-harness-evidence-1"],
] as const;

describe("LA CTF version statistics authority", () => {
	test("accepts only the sealed active v2 non-scored statistics artifact", async () => {
		const current = await artifact("lactf-version-observation-v2.json");
		const validated = validateLactfVersionStatisticsArtifact(current);
		expect(validated.comparison).toMatchObject({ benchmarkStatus: "unavailable", comparable: false });
		expect(validated.versions.every(version => version.independentlyVerifiedSolveCount === 0)).toBe(true);
	});

	test("binds every evidence edge to its reviewed canonical content", async () => {
		const current = validateLactfVersionStatisticsArtifact(await artifact("lactf-version-observation-v2.json"));
		for (const [name, selfDigestFields, schemaVersion] of evidenceBindings) {
			const evidence = await artifact(name) as Record<string, unknown>;
			const version = current.versions.find(candidate => candidate.evidenceRef === `artifacts/ctf/${name}`);
			expect(version).toBeDefined();
			expect(version?.evidenceSchemaVersion).toBe(schemaVersion);
			expect(version?.evidenceDigest).toBe(canonicalDigest(evidence, selfDigestFields));
		}
	});

	test("rejects both revoked observation artifacts through the machine revocation registry", async () => {
		for (const name of ["lactf-expanded-v2-version-observation.json", "lactf-deadline-version-observation-v1.json"]) {
			const superseded = await artifact(name);
			expect(() => validateLactfVersionStatisticsArtifact(superseded)).toThrow(/invalidated/u);
		}
	});

	test("rejects path-preserving evidence substitutions and invalid lineage", async () => {
		const current = validateLactfVersionStatisticsArtifact(await artifact("lactf-version-observation-v2.json"));
		const invalidated = current.versions.find(version => version.status === "invalidated")!;
		const harness = current.versions.find(version => version.status === "verified-harness-unscored")!;
		expect(() => validateLactfVersionStatisticsArtifact({
			...current,
			versions: current.versions.map(version => version === invalidated
				? { ...version, evidenceDigest: harness.evidenceDigest }
				: version),
		})).toThrow(/content binding/u);
		expect(() => validateLactfVersionStatisticsArtifact({
			...current,
			versions: current.versions.map(version => version === invalidated
				? { ...version, invalidatedCampaignDigest: harness.evidenceDigest }
				: version),
		})).toThrow(/invalidation receipt and campaign digest/u);
		expect(() => validateLactfVersionStatisticsArtifact({
			...current,
			versions: current.versions.map(version => version === harness
				? { ...version, supersedesObservationDigest: invalidated.evidenceDigest }
				: version),
		})).toThrow(/one current harness.*supersedes/u);
		expect(() => validateLactfVersionStatisticsArtifact({
			...current,
			versions: [...current.versions, { ...harness, versionId: "ctf-harness-v3-duplicate" }],
		})).toThrow(/one current harness/u);
	});

	test("rejects v2 digest and extra-field substitution", async () => {
		const current = validateLactfVersionStatisticsArtifact(await artifact("lactf-version-observation-v2.json"));
		expect(() => validateLactfVersionStatisticsArtifact({ ...current, generatedAt: "2026-08-08T08:00:00.000Z" })).toThrow(/digest/u);
		expect(() => validateLactfVersionStatisticsArtifact({ ...current, unexpected: true })).toThrow(/active v2 schema/u);
	});
});
