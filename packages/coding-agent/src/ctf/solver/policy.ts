import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import type { OracleResultV1 } from "../contracts/oracle";
import type { VerifiedOracleResult } from "../runtime/oracle";

export type CandidateStatus = "proposed" | "testing" | "rejected" | "promotable" | "promoted";

export type SolverCandidate = Readonly<{
	candidateId: string;
	runId: string;
	challengeId: string;
	candidateDigest: Digest;
	artifactDigests: readonly Digest[];
	provenanceDigest: Digest;
	attempt: number;
	status: CandidateStatus;
	createdAt: string;
}>;

export type CandidatePolicy = Readonly<{
	maxCandidates: number;
	maxAttempts: number;
	allowPromotionWithoutOracle: false;
	requireArtifactProvenance: true;
}>;

export type PromotionDecision =
	| Readonly<{ promoted: true; candidate: SolverCandidate; oracle: VerifiedOracleResult }>
	| Readonly<{
			promoted: false;
			reason: "oracle_required" | "oracle_failed" | "identity_mismatch" | "candidate_invalid";
	  }>;

export type SolverTermination =
	| Readonly<{ kind: "solved"; candidateId: string; oracleResultDigest: Digest }>
	| Readonly<{ kind: "continue"; reason: "budget_remaining" | "candidates_remaining" }>
	| Readonly<{
			kind: "terminated";
			reason: "budget_exhausted" | "candidate_exhausted" | "oracle_unavailable" | "all_candidates_rejected";
	  }>;

export type SolverState = Readonly<{
	candidates: readonly SolverCandidate[];
	promotedCandidateId?: string;
	verifiedOracle?: VerifiedOracleResult;
	attemptsUsed: number;
	attemptBudget: number;
	candidateBudget: number;
	oracleAvailable: boolean;
}>;

function reject(message: string): never {
	throw new CtfError("missing_provenance", message);
}

function candidateValid(candidate: Partial<SolverCandidate>, policy: CandidatePolicy): candidate is SolverCandidate {
	const attempt = candidate.attempt;
	if (
		typeof candidate.candidateId !== "string" ||
		typeof candidate.runId !== "string" ||
		typeof candidate.challengeId !== "string" ||
		!isDigest(candidate.candidateDigest) ||
		!isDigest(candidate.provenanceDigest) ||
		!Array.isArray(candidate.artifactDigests) ||
		candidate.artifactDigests.length === 0 ||
		!candidate.artifactDigests.every(isDigest) ||
		typeof attempt !== "number" ||
		!Number.isInteger(attempt) ||
		attempt <= 0 ||
		attempt > policy.maxAttempts ||
		typeof candidate.createdAt !== "string" ||
		!Number.isFinite(Date.parse(candidate.createdAt)) ||
		!["proposed", "testing", "rejected", "promotable", "promoted"].includes(candidate.status ?? "proposed")
	)
		return false;
	return true;
}

export function validateCandidatePolicy(policy: unknown): CandidatePolicy {
	if (!policy || typeof policy !== "object") reject("solver candidate policy is missing");
	const value = policy as Partial<CandidatePolicy>;
	const maxCandidates = value.maxCandidates;
	const maxAttempts = value.maxAttempts;
	if (
		typeof maxCandidates !== "number" ||
		!Number.isInteger(maxCandidates) ||
		maxCandidates <= 0 ||
		typeof maxAttempts !== "number" ||
		!Number.isInteger(maxAttempts) ||
		maxAttempts <= 0 ||
		value.allowPromotionWithoutOracle !== false ||
		value.requireArtifactProvenance !== true
	) {
		reject("solver candidate policy is unsafe or incomplete");
	}
	return { maxCandidates, maxAttempts, allowPromotionWithoutOracle: false, requireArtifactProvenance: true };
}

export function validateSolverCandidate(value: unknown, policy: CandidatePolicy): SolverCandidate {
	if (!value || typeof value !== "object") reject("solver candidate is missing");
	const candidate = value as Partial<SolverCandidate>;
	if (!candidateValid(candidate, policy)) reject("solver candidate is invalid or lacks provenance");
	const artifactDigests = candidate.artifactDigests;
	if (new Set(artifactDigests).size !== artifactDigests.length)
		reject("solver candidate artifact provenance contains duplicates");
	if (!digestsEqual(solverCandidateDigest(candidate), candidate.candidateDigest))
		reject("solver candidate digest does not match its immutable content");
	return {
		candidateId: candidate.candidateId,
		runId: candidate.runId,
		challengeId: candidate.challengeId,
		candidateDigest: candidate.candidateDigest,
		artifactDigests: [...artifactDigests],
		provenanceDigest: candidate.provenanceDigest,
		attempt: candidate.attempt,
		status: candidate.status ?? "proposed",
		createdAt: candidate.createdAt,
	};
}

/** Candidate promotion requires an independently verified oracle pass. */
export function promoteCandidate(
	candidateValue: unknown,
	oracle: VerifiedOracleResult | undefined,
	policyValue: unknown,
): PromotionDecision {
	const policy = validateCandidatePolicy(policyValue);
	let candidate: SolverCandidate;
	try {
		candidate = validateSolverCandidate(candidateValue, policy);
	} catch {
		return { promoted: false, reason: "candidate_invalid" };
	}
	if (oracle === undefined || oracle.verified !== true) return { promoted: false, reason: "oracle_required" };
	const result: OracleResultV1 = oracle.result;
	if (result.verdict !== "pass") return { promoted: false, reason: "oracle_failed" };
	if (candidate.status === "rejected") return { promoted: false, reason: "candidate_invalid" };
	if (
		result.runId !== candidate.runId ||
		result.challengeId !== candidate.challengeId ||
		result.candidateDigest !== candidate.candidateDigest
	) {
		return { promoted: false, reason: "identity_mismatch" };
	}
	return { promoted: true, candidate: { ...candidate, status: "promoted" }, oracle };
}

/**
 * Termination is a state machine, not a success heuristic.  A solved result
 * can only be emitted when a verified oracle pass names the promoted candidate.
 */
export function evaluateSolverTermination(state: SolverState): SolverTermination {
	if (state.verifiedOracle?.verified === true && state.promotedCandidateId !== undefined) {
		const promoted = state.candidates.find(candidate => candidate.candidateId === state.promotedCandidateId);
		if (
			promoted?.status === "promoted" &&
			state.verifiedOracle.result.verdict === "pass" &&
			state.verifiedOracle.result.candidateDigest === promoted.candidateDigest
		) {
			return {
				kind: "solved",
				candidateId: state.promotedCandidateId,
				oracleResultDigest: canonicalDigest(state.verifiedOracle.result),
			};
		}
	}
	if (state.attemptsUsed >= state.attemptBudget) return { kind: "terminated", reason: "budget_exhausted" };
	if (state.candidates.length >= state.candidateBudget) return { kind: "terminated", reason: "candidate_exhausted" };
	if (!state.oracleAvailable) return { kind: "terminated", reason: "oracle_unavailable" };
	if (state.candidates.length === 0) return { kind: "continue", reason: "budget_remaining" };
	if (state.candidates.every(candidate => candidate.status === "rejected"))
		return { kind: "terminated", reason: "all_candidates_rejected" };
	return { kind: "continue", reason: "candidates_remaining" };
}

export function solverCandidateDigest(candidate: Omit<SolverCandidate, "candidateDigest"> | SolverCandidate): Digest {
	return canonicalDigest(candidate, ["candidateDigest", "status"]);
}

export const candidatePolicy = validateCandidatePolicy;
export const candidatePromotion = promoteCandidate;
export const terminationPolicy = evaluateSolverTermination;
