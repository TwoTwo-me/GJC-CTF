import { describe, expect, it } from "bun:test";
import { canonicalDigest, sha256Hex } from "../../src/ctf/contracts";
import {
	type CtfTeamApiExecutor,
	type CtfTeamIndependenceEvidence,
	type CtfTeamInformationGainEvidence,
	type CtfTeamPreflightEvidence,
	createCtfTeamAdapter,
} from "../../src/ctf/integrations/team-adapter";

const completionTask = {
	id: "task-1",
	status: "completed",
	completion_evidence: { items: [{ kind: "inspection", status: "verified", summary: "persisted" }] },
};

function digestEvidence<T extends Record<string, unknown>>(value: T): T & { evidenceDigest: string } {
	return { ...value, evidenceDigest: sha256Hex(canonicalDigest(value)) };
}

function executorFor(
	input: { phase?: string; tasks?: unknown[]; recovered?: unknown[]; task?: unknown } = {},
): CtfTeamApiExecutor {
	return async operation => {
		switch (operation) {
			case "read-monitor-snapshot":
				return { phase: input.phase ?? "running" };
			case "list-tasks":
				return { tasks: input.tasks ?? [completionTask] };
			case "read-task":
				return { task: input.task ?? completionTask };
			case "read-worker-status":
				return { state: "done" };
			case "read-worker-heartbeat":
				return { alive: true };
			case "recover-stale-claims":
				return { recovered_claims: input.recovered ?? [] };
			default:
				throw new Error(`unexpected operation: ${operation}`);
		}
	};
}

const preflight = digestEvidence({
	kind: "preflight" as const,
	passed: true as const,
	summary: "sandbox checked",
	checks: ["network-off"],
}) as CtfTeamPreflightEvidence;
const independence = digestEvidence({
	kind: "independence" as const,
	independent: true as const,
	summary: "separate worker",
	sources: ["worker-2"],
}) as CtfTeamIndependenceEvidence;
const informationGain = digestEvidence({
	kind: "information_gain" as const,
	gain: 1,
	summary: "new fact",
}) as CtfTeamInformationGainEvidence;

const adapter = (execute: CtfTeamApiExecutor = executorFor()) =>
	createCtfTeamAdapter({ execute, clock: () => "2026-08-07T00:00:00.000Z" });

describe("CTF team verification and lifecycle helpers", () => {
	it("rejects empty verification evidence before consulting the team API", async () => {
		await expect(
			adapter().verify({
				teamName: "team",
				taskId: "task-1",
				disposition: "confirmed",
				summary: "",
				observations: [],
			}),
		).rejects.toMatchObject({ code: "invalid_api_request" });
	});

	it("confirms only a persisted completed task with digest-bound evidence", async () => {
		const evidence = await adapter().confirm({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
			summary: "completion persisted",
			observations: ["task receipt", "verified completion item"],
		});
		expect(evidence.disposition).toBe("confirmed");
		expect(evidence.evidenceDigest).toBe(sha256Hex(canonicalDigest(evidence, ["evidenceDigest"])));
	});

	it("records refutation and block as terminal worker observations", async () => {
		const refuted = await adapter(
			executorFor({ tasks: [{ id: "task-1", status: "failed" }], task: { id: "task-1", status: "failed" } }),
		).refute({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
			summary: "worker refuted the candidate",
			observations: ["failed task receipt"],
		});
		expect(refuted.disposition).toBe("refuted");
		const blocked = await adapter(
			executorFor({ tasks: [{ id: "task-1", status: "blocked" }], task: { id: "task-1", status: "blocked" } }),
		).block({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
			summary: "worker blocked the candidate",
			observations: ["blocked task receipt"],
		});
		expect(blocked.disposition).toBe("blocked");
	});
	it("rejects promotion when information gain is not positive", async () => {
		const zeroGain = digestEvidence({
			kind: "information_gain" as const,
			gain: 0,
			summary: "no new fact",
		}) as CtfTeamInformationGainEvidence;
		const decision = await adapter().promote({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
			verification: await adapter().confirm({
				teamName: "team",
				workerId: "worker-1",
				taskId: "task-1",
				summary: "done",
				observations: ["verified"],
			}),
			preflight,
			independence,
			informationGain: zeroGain,
		});
		expect(decision).toMatchObject({ promoted: false, reason: "information_gain_invalid" });
	});

	it("promotes only independently verified information-gain evidence", async () => {
		const verification = await adapter().confirm({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
			summary: "done",
			observations: ["verified"],
		});
		const decision = await adapter().promote({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
			verification,
			preflight,
			independence,
			informationGain,
		});
		expect(decision).toMatchObject({ promoted: true });
		if (decision.promoted)
			expect(decision.evidenceDigest).toBe(sha256Hex(canonicalDigest(decision, ["evidenceDigest"])));
	});
	it("requires an exhausted budget for budget termination", async () => {
		await expect(
			adapter().terminate({
				teamName: "team",
				reason: "budget_exhausted",
				summary: "budget",
				evidence: ["attempts"],
				budget: { used: 1, limit: 2 },
			}),
		).rejects.toMatchObject({ code: "invalid_api_request" });
	});

	it("records no-progress terminal evidence against the observed monitor digest", async () => {
		const digest = canonicalDigest({ state: "unchanged" });
		const evidence = await adapter().terminate({
			teamName: "team",
			reason: "no_progress",
			summary: "no progress after bounded attempts",
			evidence: ["two identical monitor observations"],
			progress: { beforeDigest: digest, afterDigest: digest, observations: ["same state"] },
		});
		expect(evidence.state).toBe("failed");
		expect(evidence.sourceDigest).toMatch(/^[a-f0-9]{64}$/);
		expect(evidence.evidenceDigest).toBe(sha256Hex(canonicalDigest(evidence, ["evidenceDigest"])));
	});

	it("requeues only the requested stale claim and never fabricates recovery", async () => {
		await expect(
			adapter().requeueStaleClaim({ teamName: "team", workerId: "worker-1", taskId: "task-1" }),
		).rejects.toMatchObject({ code: "stale_claim" });
		const evidence = await adapter(
			executorFor({ recovered: [{ task_id: "task-1", worker: "worker-1", reasons: ["claim_expired"] }] }),
		).requeueStaleClaim({
			teamName: "team",
			workerId: "worker-1",
			taskId: "task-1",
		});
		expect(evidence.requeued).toBe(true);
		expect(evidence.evidenceDigest).toBe(sha256Hex(canonicalDigest(evidence, ["evidenceDigest"])));
	});
});
