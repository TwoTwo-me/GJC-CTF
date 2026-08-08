import { canonicalDigest, digestsEqual, isDigest, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import {
	type CtfCampaignState,
	validateCampaignState,
} from "../../packages/coding-agent/src/ctf/campaign/controller";
import {
	type Candidate,
	type Evaluation,
	evaluateSkillCandidate,
	type ImprovementPolicy,
	type TrustedEvaluatorKey,
} from "../../packages/coding-agent/src/ctf/optimizer/skill-opt";
import { solverRouteFor, type SolverRoute } from "../../packages/coding-agent/src/ctf/solver/router";
import {
	createCtfStateStore,
	type CtfStateStore,
	type CtfStateStoreLike,
} from "../../packages/coding-agent/src/ctf/state/storage";
import {
	LACTF_BENCHMARK_TIERS,
	LactfTierController,
	type LactfTierAuthority,
	type LactfTierAuthoritySet,
	type LactfTierState,
} from "./tier-controller";
import { assertLactfEvidenceActive } from "./revoked-evidence";

export const LACTF_ITERATION_LEDGER_PATH = "benchmarks/gjc-ctf/iterations.jsonl" as const;

export type SkillOptimizationInput = Readonly<{
	candidate: Candidate;
	candidateReports: readonly unknown[];
	baselineReports: readonly unknown[];
	policy: ImprovementPolicy;
	trustedEvaluatorKeys: readonly TrustedEvaluatorKey[];
}>;

export type LactfIterationInput = Readonly<{
	campaignState: CtfCampaignState;
	benchmarkReportRequest?: unknown;
	skillOptimization?: SkillOptimizationInput;
}>;

export type LactfIterationAction = "retry-active-tier" | "expand-tier" | "terminal";
export type LactfSkillAction = "retain-current-skill" | "promote-eligible-candidate";

export type LactfIterationReceipt = Readonly<{
	schemaVersion: "gjc-lactf-iteration-receipt-1";
	sequence: number;
	campaignStateDigest: Digest;
	tierStateDigest: Digest;
	activeTier: 1 | 2;
	action: LactfIterationAction;
	unresolvedChallengeIds: readonly string[];
	routeDigests: readonly Digest[];
	skillAction: LactfSkillAction;
	skillEvaluationDigest?: Digest;
	previousReceiptDigest: Digest | null;
	receiptDigest: Digest;
}>;

export type LactfIterationDecision = Readonly<{
	action: LactfIterationAction;
	tierState: LactfTierState;
	unresolvedChallengeIds: readonly string[];
	routes: readonly SolverRoute[];
	skillAction: LactfSkillAction;
	skillEvaluation?: Evaluation;
	receipt: LactfIterationReceipt;
}>;

function fail(message: string): never {
	throw new CtfError("integrity_error", message);
}

function receiptDigest(value: Omit<LactfIterationReceipt, "receiptDigest">): Digest {
	return canonicalDigest(value);
}

function validateReceipt(value: unknown, expectedSequence: number, previousReceiptDigest: Digest | null): LactfIterationReceipt {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail("iteration receipt is invalid");
	const receipt = value as Record<string, unknown>;
	const allowed = new Set([
		"schemaVersion",
		"sequence",
		"campaignStateDigest",
		"tierStateDigest",
		"activeTier",
		"action",
		"unresolvedChallengeIds",
		"routeDigests",
		"skillAction",
		"skillEvaluationDigest",
		"previousReceiptDigest",
		"receiptDigest",
	]);
	if (Object.keys(receipt).some(key => !allowed.has(key))) fail("iteration receipt contains unknown fields");
	if (
		receipt.schemaVersion !== "gjc-lactf-iteration-receipt-1" ||
		receipt.sequence !== expectedSequence ||
		!isDigest(receipt.campaignStateDigest) ||
		!isDigest(receipt.tierStateDigest) ||
		(receipt.activeTier !== 1 && receipt.activeTier !== 2) ||
		!(["retry-active-tier", "expand-tier", "terminal"] as const).includes(receipt.action as LactfIterationAction) ||
		!Array.isArray(receipt.unresolvedChallengeIds) ||
		receipt.unresolvedChallengeIds.some(id => typeof id !== "string") ||
		!Array.isArray(receipt.routeDigests) ||
		receipt.routeDigests.some(digest => !isDigest(digest)) ||
		!(["retain-current-skill", "promote-eligible-candidate"] as const).includes(receipt.skillAction as LactfSkillAction) ||
		(receipt.skillEvaluationDigest !== undefined && !isDigest(receipt.skillEvaluationDigest)) ||
		(receipt.previousReceiptDigest !== null && !isDigest(receipt.previousReceiptDigest)) ||
		!isDigest(receipt.receiptDigest)
	) fail("iteration receipt shape is invalid");
	if (receipt.previousReceiptDigest !== previousReceiptDigest) fail("iteration receipt chain is invalid");
	const { receiptDigest: persistedDigest, ...basis } = receipt as LactfIterationReceipt;
	if (!digestsEqual(receiptDigest(basis), persistedDigest)) fail("iteration receipt digest is invalid");
	return receipt as LactfIterationReceipt;
}

function exactCampaign(campaign: CtfCampaignState): void {
	const expected = LACTF_BENCHMARK_TIERS.flat();
	const actual = campaign.challenges.map(challenge => challenge.challengeId);
	if (
		actual.length !== expected.length ||
		new Set(actual).size !== actual.length ||
		expected.some(id => !actual.includes(id))
	) fail("campaign state does not cover the immutable benchmark corpus");
}

function tierAuthoritySet(authority: LactfTierAuthority | LactfTierAuthoritySet): LactfTierAuthoritySet {
	if ("tier1" in authority && "tier2" in authority) return authority;
	return Object.freeze({ tier1: authority, tier2: authority });
}

export class LactfIterativeController {
	readonly store: CtfStateStore;
	readonly tierController: LactfTierController;
	readonly receiptPath: string;

	constructor(
		store: CtfStateStoreLike,
		receiptPath = LACTF_ITERATION_LEDGER_PATH,
		authority?: LactfTierAuthority | LactfTierAuthoritySet,
	) {
		this.store = createCtfStateStore(store, { durability: "ctf" });
		this.tierController = new LactfTierController(
			this.store,
			undefined,
			authority === undefined ? undefined : tierAuthoritySet(authority),
		);
		this.receiptPath = receiptPath;
	}

	async readReceipts(): Promise<readonly LactfIterationReceipt[]> {
		const file = Bun.file(this.store.resolve(this.receiptPath));
		if (!(await file.exists())) return [];
		const text = await file.text();
		const lines = text.split("\n").filter(line => line.trim().length > 0);
		const receipts: LactfIterationReceipt[] = [];
		let previous: Digest | null = null;
		for (const [index, line] of lines.entries()) {
			let parsed: unknown;
			try {
				parsed = JSON.parse(line) as unknown;
			} catch {
				fail("iteration receipt ledger is corrupt");
			}
			const receipt = validateReceipt(parsed, index + 1, previous);
			receipts.push(receipt);
			previous = receipt.receiptDigest;
		}
		return Object.freeze(receipts);
	}

	async run(input: LactfIterationInput): Promise<LactfIterationDecision> {
		assertLactfEvidenceActive(input.campaignState.stateDigest);
		const campaign = validateCampaignState(input.campaignState);
		assertLactfEvidenceActive(campaign.stateDigest);
		exactCampaign(campaign);
		const before = await this.tierController.load();
		const tierState = input.benchmarkReportRequest === undefined
			? before
			: await this.tierController.submitReport(input.benchmarkReportRequest);
		const activeIds = LACTF_BENCHMARK_TIERS[tierState.activeTier - 1];
		const unresolvedChallengeIds = activeIds.filter(id => !tierState.verifiedSolves[id]);
		const routes = unresolvedChallengeIds.map(id => solverRouteFor(id));
		const action: LactfIterationAction = tierState.terminal
			? "terminal"
			: before.activeTier !== tierState.activeTier
				? "expand-tier"
				: "retry-active-tier";
		const skillEvaluation = input.skillOptimization === undefined
			? undefined
			: evaluateSkillCandidate(
				input.skillOptimization.candidate,
				input.skillOptimization.candidateReports,
				input.skillOptimization.baselineReports,
				input.skillOptimization.policy,
				input.skillOptimization.trustedEvaluatorKeys,
			);
		const skillAction: LactfSkillAction = skillEvaluation?.status === "eligible"
			? "promote-eligible-candidate"
			: "retain-current-skill";
		const campaignStateDigest = campaign.stateDigest;
		const receipt = await this.store.withLock(this.receiptPath, async () => {
			const receipts = await this.readReceipts();
			const previous = receipts.at(-1)?.receiptDigest ?? null;
			assertLactfEvidenceActive(campaignStateDigest);
			const basis: Omit<LactfIterationReceipt, "receiptDigest"> = {
				schemaVersion: "gjc-lactf-iteration-receipt-1",
				sequence: receipts.length + 1,
				campaignStateDigest,
				tierStateDigest: tierState.stateDigest,
				activeTier: tierState.activeTier,
				action,
				unresolvedChallengeIds,
				routeDigests: routes.map(route => route.routeDigest),
				skillAction,
				...(skillEvaluation === undefined ? {} : { skillEvaluationDigest: skillEvaluation.evaluationDigest }),
				previousReceiptDigest: previous,
			};
			const next = Object.freeze({ ...basis, receiptDigest: receiptDigest(basis) });
			await this.store.appendJsonl(this.receiptPath, next, { durability: "ctf" });
			return next;
		}, { durability: "ctf" });
		return Object.freeze({
			action,
			tierState,
			unresolvedChallengeIds: Object.freeze([...unresolvedChallengeIds]),
			routes: Object.freeze([...routes]),
			skillAction,
			...(skillEvaluation === undefined ? {} : { skillEvaluation }),
			receipt,
		});
	}
}

export const createLactfIterativeController = (
	store: CtfStateStoreLike,
	receiptPath?: string,
	authority?: LactfTierAuthority | LactfTierAuthoritySet,
): LactfIterativeController => new LactfIterativeController(store, receiptPath, authority);
