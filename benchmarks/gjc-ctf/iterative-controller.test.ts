import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import {
	CTF_CAMPAIGN_HARD_STOP,
	type CtfCampaignState,
} from "../../packages/coding-agent/src/ctf/campaign/controller";
import { canonicalDigest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import { LACTF_BENCHMARK_TIERS, type LactfTierAuthority } from "./tier-controller";
import {
	LACTF_ITERATION_LEDGER_PATH,
	LactfIterativeController,
} from "./iterative-controller";
import { authorizedVersionStatsRequest } from "./test-authority-fixture";

function campaignState(statuses: readonly CtfCampaignState["challenges"][number]["status"][]): CtfCampaignState {
	const challengeIds = LACTF_BENCHMARK_TIERS.flat();
	const basis = {
		schemaVersion: "ctf-campaign-1" as const,
		campaignId: "lactf-2026-expanded-v2",
		competitionId: "lactf-2026",
		createdAt: "2026-08-08T00:00:00.000Z",
		updatedAt: "2026-08-08T00:01:00.000Z",
		stopAt: CTF_CAMPAIGN_HARD_STOP,
		challenges: challengeIds.map((challengeId, index) => ({
			challengeId,
			status: statuses[index] ?? "pending",
			attempts: [],
		})),
	};
	return { ...basis, stateDigest: canonicalDigest(basis) };
}

describe("iterative LA CTF solver controller", () => {
	test("routes every independently-unverified active-tier challenge even when candidates exist", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-iterative-controller-"));
		try {
			const controller = new LactfIterativeController(root);
			const decision = await controller.run({
				campaignState: campaignState(["candidate", "candidate", "candidate", "failure", "failure", "failure"]),
			});
			expect(decision.action).toBe("retry-active-tier");
			expect(decision.unresolvedChallengeIds).toEqual(LACTF_BENCHMARK_TIERS[0]);
			expect(decision.routes.map(route => route.challengeId)).toEqual(LACTF_BENCHMARK_TIERS[0]);
			expect(decision.skillAction).toBe("retain-current-skill");
			expect(decision.tierState.activeTier).toBe(1);
			expect(decision.tierState.verifiedSolves["lactf-2026-misc-endians"]).toBe(false);
			const ledger = await Bun.file(join(root, LACTF_ITERATION_LEDGER_PATH)).text();
			expect(ledger).not.toContain("candidateValue");
			expect((await controller.readReceipts()).map(receipt => receipt.sequence)).toEqual([1]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	test("keeps malformed or unsigned benchmark reports fail-closed without tier expansion", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-iterative-controller-"));
		try {
			const controller = new LactfIterativeController(root);
			const decision = await controller.run({
				campaignState: campaignState(["candidate", "candidate", "candidate"]),
				benchmarkReportRequest: {},
			});
			expect(decision.action).toBe("retry-active-tier");
			expect(decision.tierState.activeTier).toBe(1);
			expect(decision.tierState.iteration).toBe(0);
			expect(decision.tierState.expansionHistory).toEqual([]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
	test("pins construction authority and rejects a different valid authority universe", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-iterative-controller-"));
		try {
			const pinnedRequest = authorizedVersionStatsRequest();
			const alternateRequest = authorizedVersionStatsRequest();
			const authority: LactfTierAuthority = {
				manifest: pinnedRequest.manifest,
				lock: pinnedRequest.lock,
				calibration: pinnedRequest.calibration,
				oracle: pinnedRequest.oracle,
			};
			const controller = new LactfIterativeController(root, undefined, authority);
			expect(controller.tierController.authority).toBeDefined();
			const decision = await controller.run({
				campaignState: campaignState(["candidate", "candidate", "candidate"]),
				benchmarkReportRequest: alternateRequest,
			});
			expect(decision.tierState).toEqual(await controller.tierController.load());
			expect(decision.tierState.iteration).toBe(0);
			expect(decision.tierState.expansionHistory).toEqual([]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	test("rejects campaign digest corruption and corpus substitution before writing a receipt", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-iterative-controller-"));
		try {
			const controller = new LactfIterativeController(root);
			const valid = campaignState([]);
			await expect(controller.run({ campaignState: { ...valid, stateDigest: "0".repeat(64) } })).rejects.toBeInstanceOf(CtfError);
			const basis = {
				...valid,
				challenges: valid.challenges.slice(1),
			};
			const { stateDigest: _ignored, ...unsigned } = basis;
			const substituted = { ...unsigned, stateDigest: canonicalDigest(unsigned) } as CtfCampaignState;
			await expect(controller.run({ campaignState: substituted })).rejects.toThrow(/immutable benchmark corpus/);
			expect(await Bun.file(join(root, LACTF_ITERATION_LEDGER_PATH)).exists()).toBe(false);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	test("chains digest-sealed receipts without exposing campaign attempts", async () => {
		const root = await mkdtemp(join(tmpdir(), "gjc-iterative-controller-"));
		try {
			const controller = new LactfIterativeController(root);
			const campaign = campaignState([]);
			await controller.run({ campaignState: campaign });
			await controller.run({ campaignState: campaign });
			const receipts = await controller.readReceipts();
			expect(receipts).toHaveLength(2);
			expect(receipts[1]?.previousReceiptDigest).toBe(receipts[0]?.receiptDigest);
			expect(Object.keys(receipts[0] ?? {})).not.toContain("campaignState");
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
});
