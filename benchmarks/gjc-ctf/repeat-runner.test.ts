import { describe, expect, test } from "bun:test";
import { runDeterministicFixtureBenchmark } from "./repeat-runner";

describe("deterministic fixture repeat runner", () => {
	test("retains unavailable status instead of inventing a report", () => {
		const result = runDeterministicFixtureBenchmark({
			manifest: undefined,
			lock: undefined,
			calibration: undefined,
			fixture: undefined,
			lineage: {
				backendPolicyDigest: `sha256:${"a".repeat(64)}`,
				oracleRegistryDigest: `sha256:${"b".repeat(64)}`,
				preflightDigest: `sha256:${"c".repeat(64)}`,
				effectiveSkillDigest: `sha256:${"d".repeat(64)}`,
			},
			oracleAdmission: "unavailable",
		});
		expect(result.status).toBe("unavailable");
	});
});
