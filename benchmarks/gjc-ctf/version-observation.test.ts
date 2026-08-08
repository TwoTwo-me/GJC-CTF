import { describe, expect, test } from "bun:test";
import { validateLactfVersionStatisticsArtifact } from "./version-observation";

const artifact = (name: string): Promise<unknown> => Bun.file(`artifacts/ctf/${name}`).json();

describe("LA CTF version statistics authority", () => {
	test("accepts only the sealed active v2 non-scored statistics artifact", async () => {
		const current = await artifact("lactf-version-observation-v2.json");
		const validated = validateLactfVersionStatisticsArtifact(current);
		expect(validated.comparison).toMatchObject({ benchmarkStatus: "unavailable", comparable: false });
		expect(validated.versions.every(version => version.independentlyVerifiedSolveCount === 0)).toBe(true);
	});

	test("rejects both superseded observation artifacts through the machine revocation registry", async () => {
		for (const name of ["lactf-expanded-v2-version-observation.json", "lactf-deadline-version-observation-v1.json"]) {
			const superseded = await artifact(name);
			expect(() => validateLactfVersionStatisticsArtifact(superseded)).toThrow(/invalidated/u);
		}
	});

	test("rejects v2 digest or invalidation-reference substitution", async () => {
		const current = validateLactfVersionStatisticsArtifact(await artifact("lactf-version-observation-v2.json"));
		expect(() => validateLactfVersionStatisticsArtifact({ ...current, generatedAt: "2026-08-08T08:00:00.000Z" })).toThrow(/digest/u);
		expect(() => validateLactfVersionStatisticsArtifact({
			...current,
			versions: current.versions.map(version => version.status === "invalidated"
				? { ...version, evidenceRef: "artifacts/ctf/other.json" }
				: version),
		})).toThrow(/invalidation receipt|digest/u);
	});
});
