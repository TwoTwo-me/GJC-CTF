import { describe, expect, it } from "bun:test";
import { type CtfSolverBackend, scheduleCtfRuns } from "../../src/ctf/runtime/scheduler";

describe("CTF scheduler integration contract", () => {
	it("orders results canonically and binds backend authority", async () => {
		const requests: string[] = [];
		const backend: CtfSolverBackend = {
			id: "backend-local",
			async solve(request) {
				requests.push(`${request.challengeId}:${request.authority.fencingToken}:${request.authority.intentId}`);
				return { status: "candidate", artifacts: ["visible.txt"] };
			},
		};

		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["zeta", "alpha"],
			mode: "competition",
			concurrency: 2,
			backend,
			authorityFor: async ({ challengeId }) => ({
				fencingToken: 7,
				intentId: `${challengeId}-intent`,
				skillDigest: "sha256:skill",
				sandboxPolicyDigest: "sha256:sandbox",
			}),
			createUnavailable: async () => {
				throw new Error("backend path expected");
			},
		});

		expect(result.status).toBe("complete");
		expect(result.results.map(run => run.challengeId)).toEqual(["alpha", "zeta"]);
		expect(requests.sort()).toEqual(["alpha:7:alpha-intent", "zeta:7:zeta-intent"]);
		expect(result.scheduler).toMatchObject({ concurrency: 2, backend: "backend-local" });
		expect(result.aggregationDigest).toMatch(/^[a-f0-9]{64}$/);
	});

	it("fails closed when run authority is absent", async () => {
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["challenge-1"],
			mode: "competition",
			concurrency: 1,
			backend: { id: "backend-local", solve: async () => ({ status: "candidate" }) },
			createUnavailable: async () => {
				throw new Error("backend path expected");
			},
		});

		expect(result.status).toBe("complete");
		expect(result.results[0]).toMatchObject({ status: "blocked", reason: "authority_unavailable" });
	});

	it("maps oversized solver diagnostics to a closed durable reason code", async () => {
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["challenge-1"],
			mode: "benchmark",
			concurrency: 1,
			backend: { id: "backend-local", solve: async () => ({ status: "failed", reason: "x".repeat(400) }) },
			authority: {
				fencingToken: 1,
				intentId: "intent-1",
				skillDigest: "sha256:skill",
				sandboxPolicyDigest: "sha256:sandbox",
			},
			createUnavailable: async () => {
				throw new Error("backend path expected");
			},
		});

		expect(result.results[0]?.reason).toBe("solver_failed");
	});

	it("rejects untrusted backend statuses and artifact paths", async () => {
		const execute = (outcome: unknown) =>
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["challenge-1"],
				mode: "competition",
				concurrency: 1,
				backend: {
					id: "backend-local",
					solve: async () => outcome as never,
				},
				authority: {
					fencingToken: 1,
					intentId: "intent-1",
					skillDigest: "sha256:skill",
					sandboxPolicyDigest: "sha256:sandbox",
				},
				createUnavailable: async () => {
					throw new Error("backend path expected");
				},
			});

		expect((await execute({ status: "solved" })).results[0]).toMatchObject({
			status: "failed",
			reason: "backend_invalid_result",
		});
		expect((await execute({ status: "candidate", artifacts: ["../../flag"] })).results[0]).toMatchObject({
			status: "failed",
			reason: "backend_invalid_result",
		});
	});
});
