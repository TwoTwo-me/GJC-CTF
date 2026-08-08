import { describe, expect, it } from "bun:test";
import type { Digest } from "../../src/ctf/contracts/digest";
import {
	type CandidateEvaluationResultV1,
	type EvaluationLineageV1,
	type EvaluationResultV1,
	type EvaluationSpecV1,
	evaluationLineageDigest,
	evaluationResultDigest,
	evaluationSpecDigest,
	type UnavailableEvaluationResultV1,
	type VerifiedEvaluationResultV1,
	validateEvaluationLineage,
	validateEvaluationResult,
	validateEvaluationSpec,
} from "../../src/ctf/contracts/evaluation";

type EvaluationSpecInput = Omit<EvaluationSpecV1, "specDigest">;
type EvaluationLineageInput = Omit<EvaluationLineageV1, "lineageDigest">;
type CandidateEvaluationResultInput = Omit<CandidateEvaluationResultV1, "resultDigest">;
type VerifiedEvaluationResultInput = Omit<VerifiedEvaluationResultV1, "resultDigest">;
type UnavailableEvaluationResultInput = Omit<UnavailableEvaluationResultV1, "resultDigest">;

const DIGEST = "a".repeat(64) as Digest;

function spec(): EvaluationSpecV1 {
	const unsigned: EvaluationSpecInput = {
		schemaVersion: "ctf-evaluation-spec-1",
		evaluationId: "evaluation-1",
		challengeId: "challenge-1",
		descriptorDigest: DIGEST,
		secretPolicy: "not-feasible",
		candidate: { encoding: "utf8", maxBytes: 1024 },
		adapters: [
			{
				kind: "offline-checker",
				adapterId: "adapter-1",
				roles: ["checker"],
				checkerRef: "checkers/verify",
				checkerDigest: DIGEST,
				workingDirectory: "work",
				arguments: ["--candidate"],
			},
		],
	};
	return { ...unsigned, specDigest: evaluationSpecDigest(unsigned) };
}

function lineage(): EvaluationLineageV1 {
	const unsigned: EvaluationLineageInput = {
		schemaVersion: "ctf-evaluation-lineage-1",
		runId: "run-1",
		challengeId: "challenge-1",
		descriptorDigest: DIGEST,
		specDigest: spec().specDigest,
		corpusDigest: DIGEST,
		sourceDigest: DIGEST,
		visiblePolicyDigest: DIGEST,
		toolDigest: DIGEST,
		backendDigest: DIGEST,
		runtimeDigest: DIGEST,
		safetyDigest: DIGEST,
		limitsDigest: DIGEST,
		calibrationDigest: DIGEST,
		preflightDigest: DIGEST,
		candidateDigest: DIGEST,
		inputDigest: DIGEST,
		instanceCommitmentDigest: DIGEST,
		verifiedOracleDigest: DIGEST,
	};
	return { ...unsigned, lineageDigest: evaluationLineageDigest(unsigned) };
}

function result(kind: "candidate" | "verified" | "unavailable"): EvaluationResultV1 {
	const common = {
		schemaVersion: "ctf-evaluation-result-1" as const,
		evaluationId: "evaluation-1",
		lineage: lineage(),
	};
	if (kind === "candidate") {
		const unsigned: CandidateEvaluationResultInput = { ...common, kind: "candidate", candidateDigest: DIGEST };
		return { ...unsigned, resultDigest: evaluationResultDigest(unsigned) };
	}
	if (kind === "verified") {
		const unsigned: VerifiedEvaluationResultInput = {
			...common,
			kind: "verified",
			candidateDigest: DIGEST,
			verdict: "pass",
			oracleId: "oracle-1",
			verifiedOracleDigest: DIGEST,
		};
		return { ...unsigned, resultDigest: evaluationResultDigest(unsigned) };
	}
	const unsigned: UnavailableEvaluationResultInput = {
		...common,
		kind: "unavailable",
		phase: "preflight",
		code: "not_feasible",
		sanitizedReason: "local evaluator is unavailable",
	};
	return { ...unsigned, resultDigest: evaluationResultDigest(unsigned) };
}

describe("evaluation contracts", () => {
	it("accepts a valid candidate-only spec and rejects extra keys", () => {
		expect(validateEvaluationSpec(spec())).toEqual(spec());
		expect(() => validateEvaluationSpec({ ...spec(), secret: "never" })).toThrow();
		expect(() =>
			validateEvaluationSpec({ ...spec(), adapters: [{ ...spec().adapters[0], environment: { TOKEN: "never" } }] }),
		).toThrow();
	});

	it("checks the self-described spec digest", () => {
		expect(() => validateEvaluationSpec({ ...spec(), specDigest: "b".repeat(64) })).toThrow("digest mismatch");
	});

	it("rejects privileged roles, invalid transports, origins, and paths", () => {
		const base = spec().adapters[0];
		expect(() => validateEvaluationSpec({ ...spec(), adapters: [{ ...base, roles: ["oracle"] }] })).toThrow();
		expect(() =>
			validateEvaluationSpec({ ...spec(), adapters: [{ ...base, workingDirectory: "/host/work" }] }),
		).toThrow();
		expect(() =>
			validateEvaluationSpec({
				...spec(),
				adapters: [
					{
						kind: "process-service",
						adapterId: "adapter-1",
						roles: ["service"],
						serviceRef: "services/check",
						serviceDigest: DIGEST,
						transport: "tcp",
						workingDirectory: "work",
						arguments: [],
					},
				],
			}),
		).toThrow();
		expect(() =>
			validateEvaluationSpec({
				...spec(),
				adapters: [
					{
						kind: "container-service",
						adapterId: "adapter-1",
						roles: ["service"],
						imageDigest: DIGEST,
						transport: "http",
						origin: "https://example.test",
						entryPath: "app",
					},
				],
			}),
		).toThrow();
	});

	it("keeps candidate results distinct from verified oracle results", () => {
		const candidate = result("candidate");
		const verified = result("verified");
		expect(validateEvaluationResult(candidate).kind).toBe("candidate");
		expect(validateEvaluationResult(verified).kind).toBe("verified");
		expect(() => validateEvaluationResult({ ...candidate, kind: "verified" })).toThrow();
		expect(() => validateEvaluationResult({ ...verified, verifiedOracleDigest: "b".repeat(64) })).toThrow();
	});

	it("bounds and sanitizes unavailable reasons", () => {
		expect(validateEvaluationResult(result("unavailable")).kind).toBe("unavailable");
		expect(() =>
			validateEvaluationResult({ ...result("unavailable"), sanitizedReason: "/home/user/private stderr" }),
		).toThrow();
		expect(() => validateEvaluationResult({ ...result("unavailable"), sanitizedReason: "x".repeat(513) })).toThrow();
	});

	it("produces deterministic spec and lineage digests", () => {
		const first = spec();
		const second = spec();
		expect(evaluationSpecDigest(first)).toBe(evaluationSpecDigest(second));
		expect(evaluationLineageDigest(lineage())).toBe(evaluationLineageDigest(lineage()));
		expect(validateEvaluationLineage(lineage())).toEqual(lineage());
	});
});
