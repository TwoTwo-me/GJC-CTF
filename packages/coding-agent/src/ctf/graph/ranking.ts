import { canonicalDigest, type Digest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";

export const CTF_RANK_POLICY = {
	version: CTF_SCHEMA_VERSIONS.ranking,
	weights: { evidenceSupport: 0.3, confidence: 0.25, informationGain: 0.2, pathFeasibility: 0.15, budgetFit: 0.1 },
	tieBreak: ["goalPathLength", "estimatedWallTimeMs", "estimatedTokenCost", "actionId"],
} as const;
export const CTF_RANK_POLICY_DIGEST: Digest = canonicalDigest(CTF_RANK_POLICY);

export type RankingCandidate = {
	actionId: string;
	blocked?: boolean;
	verifiedSupportingEvidence?: number;
	contradictingEvidence?: number;
	evidenceSupport?: number;
	confidence: number;
	informationGain: number;
	pathFeasibility: number;
	remainingBudget?: number;
	estimatedActionCost?: number;
	budgetFit?: number;
	goalPathLength: number;
	estimatedWallTimeMs: number;
	estimatedTokenCost: number;
};

export type RankedCandidate = RankingCandidate & {
	normalized: {
		evidenceSupport: number;
		confidence: number;
		informationGain: number;
		pathFeasibility: number;
		budgetFit: number;
	};
	score: number;
	rankingPolicyVersion: typeof CTF_SCHEMA_VERSIONS.ranking;
	rankingPolicyDigest: Digest;
};

function clamp(value: number, label = "score"): number {
	if (!Number.isFinite(value)) throw new CtfError("invalid_manifest", `${label} must be finite`);
	return Math.max(0, Math.min(1, value));
}

export function evidenceSupportScore(
	candidate: Pick<RankingCandidate, "verifiedSupportingEvidence" | "contradictingEvidence" | "evidenceSupport">,
): number {
	if (candidate.evidenceSupport !== undefined) return clamp(candidate.evidenceSupport);
	const supporting = candidate.verifiedSupportingEvidence ?? 0;
	const contradiction = candidate.contradictingEvidence ?? 0;
	if (!Number.isFinite(supporting) || !Number.isFinite(contradiction) || supporting < 0 || contradiction < 0)
		throw new CtfError("invalid_manifest", "evidence counts must be non-negative finite values");
	return supporting / (supporting + contradiction + 1);
}

export function budgetFitScore(
	candidate: Pick<RankingCandidate, "remainingBudget" | "estimatedActionCost" | "budgetFit">,
): number {
	if (candidate.budgetFit !== undefined) return clamp(candidate.budgetFit);
	if (candidate.remainingBudget === undefined || candidate.estimatedActionCost === undefined) return 0;
	if (
		!Number.isFinite(candidate.remainingBudget) ||
		!Number.isFinite(candidate.estimatedActionCost) ||
		candidate.remainingBudget < 0 ||
		candidate.estimatedActionCost < 0
	)
		throw new CtfError("invalid_manifest", "budget values must be non-negative finite values");
	return candidate.estimatedActionCost === 0 ? 1 : clamp(candidate.remainingBudget / candidate.estimatedActionCost);
}

export function scoreCandidate(candidate: RankingCandidate): RankedCandidate {
	if (
		!candidate.actionId ||
		!Number.isInteger(candidate.goalPathLength) ||
		candidate.goalPathLength < 0 ||
		!Number.isFinite(candidate.estimatedWallTimeMs) ||
		candidate.estimatedWallTimeMs < 0 ||
		!Number.isFinite(candidate.estimatedTokenCost) ||
		candidate.estimatedTokenCost < 0
	) {
		throw new CtfError("invalid_manifest", "ranking candidate has invalid tie-break fields");
	}
	const normalized = {
		evidenceSupport: evidenceSupportScore(candidate),
		confidence: clamp(candidate.confidence),
		informationGain: clamp(candidate.informationGain),
		pathFeasibility: clamp(candidate.pathFeasibility),
		budgetFit: budgetFitScore(candidate),
	};
	const score =
		0.3 * normalized.evidenceSupport +
		0.25 * normalized.confidence +
		0.2 * normalized.informationGain +
		0.15 * normalized.pathFeasibility +
		0.1 * normalized.budgetFit;
	return {
		...candidate,
		normalized,
		score,
		rankingPolicyVersion: CTF_SCHEMA_VERSIONS.ranking,
		rankingPolicyDigest: CTF_RANK_POLICY_DIGEST,
	};
}

export function rankCandidates(candidates: readonly RankingCandidate[]): RankedCandidate[] {
	return candidates
		.filter(candidate => candidate.blocked !== true)
		.map(scoreCandidate)
		.sort((left, right) => {
			if (right.score !== left.score) return right.score - left.score;
			if (left.goalPathLength !== right.goalPathLength) return left.goalPathLength - right.goalPathLength;
			if (left.estimatedWallTimeMs !== right.estimatedWallTimeMs)
				return left.estimatedWallTimeMs - right.estimatedWallTimeMs;
			if (left.estimatedTokenCost !== right.estimatedTokenCost)
				return left.estimatedTokenCost - right.estimatedTokenCost;
			return left.actionId < right.actionId ? -1 : left.actionId > right.actionId ? 1 : 0;
		});
}

export const rankActions = rankCandidates;
