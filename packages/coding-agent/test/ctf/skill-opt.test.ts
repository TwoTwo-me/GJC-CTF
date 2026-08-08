import { afterEach, describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { canonicalDigest, canonicalJson, type Digest, sha256Hex } from "../../src/ctf/contracts/digest";
import { effectiveSkillDigest } from "../../src/ctf/contracts/skill";
import {
	type BenchmarkReport,
	benchmarkReportSigningPayload,
	type Candidate,
	createFailureContinuation,
	createSkillHoldoutGate,
	createSkillOptimizationRound,
	evaluateSkillCandidate,
	generateSkillCandidate,
	makeSkillArtifact,
	type RoundAuthorityKey,
	roundAuthorityKeyAnchorDigest,
	roundAuthorityRegistryDigest,
	type SkillHoldoutGateV1,
	SkillOptimizationRoundStore,
	type SkillOptimizationRoundV1,
	SkillPromotionStore,
	type SkillTrainingSelectionV1,
	selectSkillTrainingCandidate,
	serializePublicSkillOptimizationArtifact,
	skillHoldoutGateSigningPayload,
	skillTrainingSelectionSigningPayload,
	type TrustedEvaluatorKey,
	validateBenchmarkReport,
	validateSkillHoldoutGate,
	validateSkillOptimizationRound,
} from "../../src/ctf/optimizer/skill-opt";

const D = "a".repeat(64) as Digest;
const TRAINING = "b".repeat(64) as Digest;
const HOLDOUT = "c".repeat(64) as Digest;
const parent = {
	schemaVersion: "ctf-skill-1" as const,
	id: "skill-x",
	version: "1.0.0",
	contentDigest: D,
	loaderDigest: D,
	buildDigest: D,
	workspaceOverrideDigest: null,
	source: "embedded" as const,
	resolvedAt: "2026-08-07T00:00:00.000Z",
};
const policy = {
	metric: "score",
	minimumDelta: 0.1,
	holdoutMinimumDelta: 0,
	minimumSamples: 100,
	confidenceLevel: 0.95 as const,
	maximumUnknownCount: 0,
};
const roots: string[] = [];
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const key: TrustedEvaluatorKey = {
	keyId: "evaluator-1",
	algorithm: "ed25519",
	publicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
	active: true,
};
const { privateKey: holdoutPrivateKey, publicKey: holdoutPublicKey } = generateKeyPairSync("ed25519");
const TRAINING_ANCHOR = roundAuthorityKeyAnchorDigest({
	keyId: key.keyId,
	algorithm: key.algorithm,
	publicKey: key.publicKey,
	role: "training",
});
const HOLDOUT_ANCHOR = roundAuthorityKeyAnchorDigest({
	keyId: "holdout-authority",
	algorithm: "ed25519",
	publicKey: holdoutPublicKey.export({ format: "der", type: "spki" }).toString("base64"),
	role: "holdout",
});
const roundKeys: readonly RoundAuthorityKey[] = [
	{ ...key, role: "training", keyAnchorDigest: TRAINING_ANCHOR },
	{
		keyId: "holdout-authority",
		algorithm: "ed25519",
		publicKey: holdoutPublicKey.export({ format: "der", type: "spki" }).toString("base64"),
		active: true,
		role: "holdout",
		keyAnchorDigest: HOLDOUT_ANCHOR,
	},
];
const storeOptions = {
	baselineSkillDigest: effectiveSkillDigest(parent),
	trustedEvaluatorKeys: [key],
	roundAuthorityKeys: roundKeys,
	improvementPolicy: policy,
};

function digest(label: string): Digest {
	return sha256Hex(label);
}

function roundFor(...cohort: Candidate[]): SkillOptimizationRoundV1 {
	return roundForWithRegistry(roundKeys, ...cohort);
}

function roundForWithRegistry(
	authorityKeys: readonly RoundAuthorityKey[],
	...cohort: Candidate[]
): SkillOptimizationRoundV1 {
	return createSkillOptimizationRound({
		incumbentSkillDigest: effectiveSkillDigest(parent),
		committedCohortDigests: cohort.map(item => item.candidateDigest),
		benchmark: {
			benchmarkLockDigest: D,
			trainingCorpusDigest: TRAINING,
			holdoutCommitmentDigest: HOLDOUT,
			calibrationDigest: digest("calibration"),
			harnessDigest: digest("harness"),
			toolchainDigest: digest("toolchain"),
			modelFingerprint: digest("model"),
			backendFingerprint: digest("backend"),
			policyDigest: digest("policy"),
			trainingEvaluatorKeyAnchorDigest: TRAINING_ANCHOR,
			holdoutEvaluatorKeyAnchorDigest: HOLDOUT_ANCHOR,
		},
		scheduleDigest: digest("schedule"),
		tieBreakDigest: digest("tie-break"),
		authorityRegistryDigest: roundAuthorityRegistryDigest(authorityKeys),
		maximumContinuationBudget: 2,
		maximumHoldoutLooks: 1,
	});
}

function signedGate(
	round: SkillOptimizationRoundV1,
	selection: SkillTrainingSelectionV1,
	status: SkillHoldoutGateV1["status"],
): SkillHoldoutGateV1 {
	const unsigned = {
		schemaVersion: "ctf-skill-holdout-gate-1" as const,
		roundDigest: round.roundDigest,
		selectionDigest: selection.selectionDigest,
		selectedCandidateDigest: selection.selectedCandidateDigest,
		holdoutCommitmentDigest: HOLDOUT,
		authorizedEvidenceDigests: [digest(`holdout-evidence-${status}`)],
		evaluatorKeyId: "holdout-authority",
		evaluatorKeyAnchorDigest: HOLDOUT_ANCHOR,
		signatureAlgorithm: "ed25519" as const,
		status,
		looksUsed: 1 as const,
	};
	const signature = sign(
		null,
		Buffer.from(canonicalJson(skillHoldoutGateSigningPayload(unsigned))),
		holdoutPrivateKey,
	).toString("base64");
	return createSkillHoldoutGate({ ...unsigned, signature }, roundKeys);
}
function signedSelection(
	round: SkillOptimizationRoundV1,
	selectedCandidateDigest: Digest | null,
	trainingComparisonEvidenceDigests: readonly Digest[],
) {
	const unsigned = {
		schemaVersion: "ctf-skill-training-selection-2" as const,
		roundDigest: round.roundDigest,
		selectedCandidateDigest,
		trainingComparisonEvidenceDigests,
		evaluatorKeyId: key.keyId,
		evaluatorKeyAnchorDigest: TRAINING_ANCHOR,
		signatureAlgorithm: "ed25519" as const,
	};
	const signature = sign(
		null,
		Buffer.from(canonicalJson(skillTrainingSelectionSigningPayload(unsigned))),
		privateKey,
	).toString("base64");
	return {
		evaluatorKeyId: unsigned.evaluatorKeyId,
		evaluatorKeyAnchorDigest: unsigned.evaluatorKeyAnchorDigest,
		signatureAlgorithm: unsigned.signatureAlgorithm,
		signature,
	};
}

afterEach(async () => {
	await Promise.all(roots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});

function candidate(content = "candidate", parentSkill = parent, generation = 1): Candidate {
	return generateSkillCandidate(
		parentSkill,
		makeSkillArtifact(
			parentSkill.id,
			parentSkill.version,
			content,
			parentSkill.loaderDigest,
			parentSkill.buildDigest,
		),
		{
			benchmarkLockDigest: D,
			trainingCorpusDigest: TRAINING,
			holdoutCommitmentDigest: HOLDOUT,
			generationTraceDigest: sha256Hex(`trace-${generation}`),
			generation,
			createdAt: `2026-08-07T00:00:0${generation}.000Z`,
		},
	);
}

function report(
	subjectDigest: Digest,
	parentSkillDigest: Digest,
	split: "training" | "holdout",
	score: number,
	successCount: number,
	status: BenchmarkReport["status"] = "passed",
	unknownCount = 0,
): BenchmarkReport {
	const unsigned = {
		schemaVersion: "ctf-skill-opt-report-1" as const,
		subjectDigest,
		parentSkillDigest,
		benchmarkLockDigest: D,
		splitDigest: split === "training" ? TRAINING : HOLDOUT,
		split,
		status,
		sampleCount: 100,
		successCount,
		unknownCount,
		metrics: { score },
		createdAt: "2026-08-07T01:00:00.000Z",
		evaluatorKeyId: key.keyId,
		signatureAlgorithm: "ed25519" as const,
	};
	const signature = sign(
		null,
		Buffer.from(canonicalJson(benchmarkReportSigningPayload(unsigned))),
		privateKey,
	).toString("base64");
	const basis = { ...unsigned, signature };
	return { ...basis, reportDigest: canonicalDigest(basis) };
}

function reportsFor(c: Candidate, candidateHoldoutSuccesses = 100) {
	const baseline = [
		report(c.parentSkillDigest, c.parentSkillDigest, "training", 0.5, 0),
		report(c.parentSkillDigest, c.parentSkillDigest, "holdout", 0.5, 50),
	];
	const candidateReports = [
		report(c.candidateDigest, c.parentSkillDigest, "training", 1, 100),
		report(c.candidateDigest, c.parentSkillDigest, "holdout", 1, candidateHoldoutSuccesses),
	];
	return { baseline, candidateReports };
}

async function promoteThroughRound(root: string, promotion: SkillPromotionStore, c: Candidate): Promise<void> {
	const reports = reportsFor(c);
	await promotion.evaluateAndRecord(c, reports.candidateReports, reports.baseline);
	const round = roundFor(c);
	const rounds = new SkillOptimizationRoundStore(root, promotion);
	await rounds.open(round);
	const selection = await rounds.select(
		round.roundDigest,
		c.candidateDigest,
		[digest("training-comparison")],
		signedSelection(round, c.candidateDigest, [digest("training-comparison")]),
	);
	await rounds.finalize(signedGate(round, selection, "passed"));
}

describe("skill optimizer gates", () => {
	it("rejects forged or duplicate evaluator reports", () => {
		const c = candidate();
		const signed = report(c.candidateDigest, c.parentSkillDigest, "training", 1, 100);
		expect(() => validateBenchmarkReport({ ...signed, signature: "forged" }, [key])).toThrow("signature");
		const { baseline, candidateReports } = reportsFor(c);
		expect(() =>
			evaluateSkillCandidate(c, [...candidateReports, candidateReports[0]], baseline, policy, [key]),
		).toThrow("duplicate");
	});
	it("rejects inconsistent signed report counts while accepting valid reports", () => {
		const c = candidate();
		const valid = report(c.candidateDigest, c.parentSkillDigest, "holdout", 1, 99, "passed", 1);
		expect(validateBenchmarkReport(valid, [key])).toMatchObject({
			successCount: 99,
			unknownCount: 1,
		});

		for (const invalid of [
			report(c.candidateDigest, c.parentSkillDigest, "holdout", 1, 100, "passed", 1),
			report(c.candidateDigest, c.parentSkillDigest, "holdout", 1, 99.5),
			report(c.candidateDigest, c.parentSkillDigest, "holdout", 1, 99, "passed", -1),
		])
			expect(() => validateBenchmarkReport(invalid, [key])).toThrow("counts");
	});

	it("preserves unknown evidence and rejects holdout regression", () => {
		const c = candidate();
		const { baseline, candidateReports } = reportsFor(c, 40);
		expect(evaluateSkillCandidate(c, [candidateReports[0]], baseline, policy, [key]).status).toBe("unknown");
		expect(evaluateSkillCandidate(c, candidateReports, baseline, policy, [key])).toMatchObject({
			status: "failed",
			reason: "holdout confidence interval does not prove improvement",
		});
	});

	it("permits promotion only through a sealed round and rolls back with a chained audit", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-opt-"));
		roots.push(root);
		const first = candidate();
		const firstReports = reportsFor(first);
		const store = new SkillPromotionStore(root, storeOptions);
		await expect(store.promote(first, firstReports.candidateReports, firstReports.baseline)).rejects.toThrow(
			"diagnostic only",
		);
		await expect(store.promoteFinalized(first, Object.freeze({}) as never)).rejects.toThrow("sealed round authority");
		await promoteThroughRound(root, store, first);
		expect(await store.active()).toMatchObject({ candidateDigest: first.candidateDigest });

		const rollback = await store.rollback(first.candidateDigest);
		expect(rollback).toMatchObject({ action: "rollback", phase: "committed" });
		const receipts = await store.receipts();
		expect(receipts.map(receipt => receipt.phase)).toEqual(["prepared", "committed", "prepared", "committed"]);
		expect((await new SkillPromotionStore(root, storeOptions).active())?.candidateDigest).toBe(first.candidateDigest);
	});

	it("recovers interrupted promotions without inventing success", async () => {
		const firstRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-opt-before-"));
		const secondRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-opt-after-"));
		roots.push(firstRoot, secondRoot);
		const c = candidate();
		const before = new SkillPromotionStore(firstRoot, {
			...storeOptions,
			faultInjection: {
				afterPrepared: () => {
					throw new Error("crash-before-active");
				},
			},
		});
		await expect(promoteThroughRound(firstRoot, before, c)).rejects.toThrow("crash-before-active");
		const beforeRecovered = new SkillPromotionStore(firstRoot, storeOptions);
		await beforeRecovered.recover();
		expect(await beforeRecovered.active()).toBeUndefined();
		expect((await beforeRecovered.receipts()).at(-1)?.phase).toBe("aborted");

		const after = new SkillPromotionStore(secondRoot, {
			...storeOptions,
			faultInjection: {
				afterActiveWrite: () => {
					throw new Error("crash-after-active");
				},
			},
		});
		await expect(promoteThroughRound(secondRoot, after, c)).rejects.toThrow("crash-after-active");
		const afterRecovered = new SkillPromotionStore(secondRoot, storeOptions);
		await afterRecovered.recover();
		expect(await afterRecovered.active()).toMatchObject({ candidateDigest: c.candidateDigest });
		expect((await afterRecovered.receipts()).at(-1)?.phase).toBe("committed");
	});
	describe("blinded one-look rounds", () => {
		it("commits deterministic identities and exactly one selected cohort member", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-round-"));
			roots.push(root);
			const first = candidate("first");
			const runnerUp = candidate("runner-up", parent, 2);
			const round = roundFor(first, runnerUp);
			expect(roundFor(first, runnerUp)).toEqual(round);
			expect(() =>
				validateSkillOptimizationRound({
					...round,
					benchmark: { ...round.benchmark, harnessDigest: digest("other-harness") },
				}),
			).toThrow("digest mismatch");
			const rounds = new SkillOptimizationRoundStore(root, new SkillPromotionStore(root, storeOptions));
			await rounds.open(round);
			await rounds.select(
				round.roundDigest,
				first.candidateDigest,
				[digest("training-comparison")],
				signedSelection(round, first.candidateDigest, [digest("training-comparison")]),
			);
			await expect(
				rounds.select(
					round.roundDigest,
					runnerUp.candidateDigest,
					[digest("different-training-comparison")],
					signedSelection(round, runnerUp.candidateDigest, [digest("different-training-comparison")]),
				),
			).rejects.toThrow("already has a training selection");
			const openContinuation = createFailureContinuation({
				roundDigest: round.roundDigest,
				trainingProblemDigest: digest("open-problem"),
				trainingEvidenceDigests: [digest("open-evidence")],
				category: "unknown",
				budget: 0,
				disposition: "stop",
			});
			await expect(rounds.continueTraining(openContinuation)).rejects.toThrow("terminal round");
		});

		it("requires active independently anchored signatures and rejects gate replay tampering", () => {
			const c = candidate();
			const round = roundFor(c);
			const selection = selectSkillTrainingCandidate(
				round,
				c.candidateDigest,
				[digest("training-proof")],
				signedSelection(round, c.candidateDigest, [digest("training-proof")]),
				roundKeys,
			);
			const gate = signedGate(round, selection, "passed");
			expect(validateSkillHoldoutGate(gate, roundKeys)).toEqual(gate);
			expect(() => validateSkillHoldoutGate({ ...gate, status: "failed" }, roundKeys)).toThrow("signature");
			expect(() =>
				validateSkillHoldoutGate({ ...gate, evaluatorKeyAnchorDigest: TRAINING_ANCHOR }, roundKeys),
			).toThrow("active for this role");
			expect(() => validateSkillHoldoutGate(gate, [{ ...roundKeys[1]!, active: false }])).toThrow("uniquely active");
			expect(() => validateSkillHoldoutGate({ ...gate, metrics: { score: 1 } }, roundKeys)).toThrow(
				"forbidden field",
			);
		});
		it("requires signed training authority bound to the committed training anchor", () => {
			const c = candidate();
			const round = roundFor(c);
			const authority = signedSelection(round, c.candidateDigest, [digest("training-proof")]);
			const selection = selectSkillTrainingCandidate(
				round,
				c.candidateDigest,
				[digest("training-proof")],
				authority,
				roundKeys,
			);
			expect(selection.evaluatorKeyAnchorDigest).toBe(TRAINING_ANCHOR);
			expect(() =>
				selectSkillTrainingCandidate(round, c.candidateDigest, [digest("tampered-proof")], authority, roundKeys),
			).toThrow("signature");
			expect(() =>
				selectSkillTrainingCandidate(
					round,
					c.candidateDigest,
					[digest("training-proof")],
					{ ...authority, evaluatorKeyAnchorDigest: HOLDOUT_ANCHOR },
					roundKeys,
				),
			).toThrow("training evaluator anchor mismatch");
			expect(() =>
				selectSkillTrainingCandidate(round, c.candidateDigest, [digest("training-proof")], authority, [
					roundKeys[1]!,
				]),
			).toThrow("uniquely active");
			expect(() =>
				selectSkillTrainingCandidate(round, c.candidateDigest, [digest("training-proof")], authority, [
					...roundKeys,
					roundKeys[0]!,
				]),
			).toThrow("uniquely active");
		});

		it("closes missing external holdout authority without a gate or a look", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-no-holdout-"));
			roots.push(root);
			const c = candidate("unscored");
			const rounds = new SkillOptimizationRoundStore(
				root,
				new SkillPromotionStore(root, { ...storeOptions, roundAuthorityKeys: [roundKeys[0]!] }),
			);
			const round = roundForWithRegistry([roundKeys[0]!], c);
			await rounds.open(round);
			const decision = await rounds.finalizeUnavailable(round.roundDigest);
			expect(decision).toMatchObject({ status: "unavailable", gateDigest: null, holdoutLooksUsed: 0 });
			await expect(rounds.finalizeUnavailable(round.roundDigest)).resolves.toEqual(decision);
			await expect(
				rounds.finalize(
					signedGate(
						round,
						selectSkillTrainingCandidate(
							round,
							c.candidateDigest,
							[digest("late-training")],
							signedSelection(round, c.candidateDigest, [digest("late-training")]),
							roundKeys,
						),
						"passed",
					),
				),
			).rejects.toThrow("already been consumed");
			const continuation = createFailureContinuation({
				roundDigest: round.roundDigest,
				trainingProblemDigest: digest("unavailable-problem"),
				trainingEvidenceDigests: [digest("unavailable-evidence")],
				category: "unknown",
				budget: 1,
				disposition: "continue-training",
			});
			await expect(rounds.continueTraining(continuation)).resolves.toEqual(continuation);
			expect(serializePublicSkillOptimizationArtifact(decision)).not.toContain("unscored");
		});
		it("rejects forged labels, duplicate IDs, invalid public keys, and cross-root stores", async () => {
			expect(
				() =>
					new SkillPromotionStore("/tmp/skill-opt-invalid", {
						...storeOptions,
						roundAuthorityKeys: [{ ...roundKeys[0]!, keyAnchorDigest: digest("forged") }],
					}),
			).toThrow("registry key");
			expect(
				() =>
					new SkillPromotionStore("/tmp/skill-opt-duplicate", {
						...storeOptions,
						roundAuthorityKeys: [roundKeys[0]!, roundKeys[0]!],
					}),
			).toThrow("registry key");
			expect(
				() =>
					new SkillPromotionStore("/tmp/skill-opt-invalid-public-key", {
						...storeOptions,
						roundAuthorityKeys: [
							{
								...roundKeys[0]!,
								publicKey: Buffer.from("not-spki").toString("base64"),
								keyAnchorDigest: roundAuthorityKeyAnchorDigest({
									...roundKeys[0]!,
									publicKey: Buffer.from("not-spki").toString("base64"),
								}),
							},
						],
					}),
			).toThrow("public key");
			const reusedPublicKey: RoundAuthorityKey = {
				...roundKeys[0]!,
				keyId: "reused-as-holdout",
				role: "holdout",
				keyAnchorDigest: roundAuthorityKeyAnchorDigest({
					...roundKeys[0]!,
					keyId: "reused-as-holdout",
					role: "holdout",
				}),
			};
			expect(
				() =>
					new SkillPromotionStore("/tmp/skill-opt-reused-public-key", {
						...storeOptions,
						roundAuthorityKeys: [roundKeys[0]!, reusedPublicKey],
					}),
			).toThrow("duplicate public key");
			const { publicKey: rsaPublicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
			const wrongTypeBasis = {
				...roundKeys[0]!,
				keyId: "rsa-training",
				publicKey: rsaPublicKey.export({ format: "der", type: "spki" }).toString("base64"),
			};
			const wrongType: RoundAuthorityKey = {
				...wrongTypeBasis,
				keyAnchorDigest: roundAuthorityKeyAnchorDigest(wrongTypeBasis),
			};
			expect(
				() =>
					new SkillPromotionStore("/tmp/skill-opt-wrong-key-type", {
						...storeOptions,
						roundAuthorityKeys: [wrongType],
					}),
			).toThrow("must be Ed25519");
			const firstRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-root-a-"));
			const secondRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-root-b-"));
			roots.push(firstRoot, secondRoot);
			expect(
				() => new SkillOptimizationRoundStore(firstRoot, new SkillPromotionStore(secondRoot, storeOptions)),
			).toThrow("share one root");
		});

		it("burns the single look on failed and unavailable gates and permits only those continuations", async () => {
			for (const status of ["failed", "unavailable"] as const) {
				const root = await fs.mkdtemp(path.join(os.tmpdir(), `gjc-skill-${status}-`));
				roots.push(root);
				const c = candidate(status, parent, status === "failed" ? 3 : 4);
				const rounds = new SkillOptimizationRoundStore(root, new SkillPromotionStore(root, storeOptions));
				const round = roundFor(c);
				await rounds.open(round);
				const selection = await rounds.select(
					round.roundDigest,
					c.candidateDigest,
					[digest(`training-${status}`)],
					signedSelection(round, c.candidateDigest, [digest(`training-${status}`)]),
				);
				const decision = await rounds.finalize(signedGate(round, selection, status));
				expect(decision).toMatchObject({
					status: status === "failed" ? "rejected" : "unavailable",
					holdoutLooksUsed: 1,
				});
				await expect(rounds.finalize(signedGate(round, selection, status))).resolves.toEqual(decision);
				await expect(
					rounds.finalize(signedGate(round, selection, status === "failed" ? "unavailable" : "failed")),
				).rejects.toThrow("already been consumed");
				const continuation = createFailureContinuation({
					roundDigest: round.roundDigest,
					trainingProblemDigest: digest(`problem-${status}`),
					trainingEvidenceDigests: [digest(`evidence-${status}`)],
					category: status === "failed" ? "failed" : "unknown",
					budget: 1,
					disposition: "continue-training",
				});
				await expect(rounds.continueTraining(continuation)).resolves.toEqual(continuation);
			}
		});

		it("promotes only through a pass gate and serializes no skill or metric content", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-pass-"));
			roots.push(root);
			const c = candidate("secret skill artifact");
			const promotion = new SkillPromotionStore(root, storeOptions);
			const reports = reportsFor(c);
			await promotion.evaluateAndRecord(c, reports.candidateReports, reports.baseline);
			const rounds = new SkillOptimizationRoundStore(root, promotion);
			const round = roundFor(c);
			await rounds.open(round);
			const selection = await rounds.select(
				round.roundDigest,
				c.candidateDigest,
				[digest("training-pass")],
				signedSelection(round, c.candidateDigest, [digest("training-pass")]),
			);
			const decision = await rounds.finalize(signedGate(round, selection, "passed"));
			expect(decision.status).toBe("promoted");
			expect((await promotion.active())?.candidateDigest).toBe(c.candidateDigest);
			const continuation = createFailureContinuation({
				roundDigest: round.roundDigest,
				trainingProblemDigest: digest("problem"),
				trainingEvidenceDigests: [digest("evidence")],
				category: "failed",
				budget: 0,
				disposition: "stop",
			});
			await expect(rounds.continueTraining(continuation)).rejects.toThrow("failed or unavailable");
			const publicText = serializePublicSkillOptimizationArtifact(decision);
			expect(publicText).not.toContain("secret skill artifact");
			expect(publicText).not.toContain("metrics");
			expect(publicText).not.toContain("successCount");
			expect(() =>
				serializePublicSkillOptimizationArtifact({ ...decision, candidateContent: "secret" } as never),
			).toThrow("forbidden field");
			const gate = signedGate(round, selection, "passed");
			expect(rounds.serializePublicArtifact(gate)).not.toContain("secret skill artifact");
			expect(() => rounds.serializePublicArtifact({ ...gate, candidateContent: "secret" } as never)).toThrow(
				"forbidden field",
			);
		});

		it("serializes concurrent signed selection to one immutable winner", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-selection-race-"));
			roots.push(root);
			const first = candidate("race-first", parent, 5);
			const second = candidate("race-second", parent, 6);
			const rounds = new SkillOptimizationRoundStore(root, new SkillPromotionStore(root, storeOptions));
			const round = roundFor(first, second);
			await rounds.open(round);
			const attempts = await Promise.allSettled([
				rounds.select(
					round.roundDigest,
					first.candidateDigest,
					[digest("race-first-proof")],
					signedSelection(round, first.candidateDigest, [digest("race-first-proof")]),
				),
				rounds.select(
					round.roundDigest,
					second.candidateDigest,
					[digest("race-second-proof")],
					signedSelection(round, second.candidateDigest, [digest("race-second-proof")]),
				),
			]);
			expect(attempts.filter(result => result.status === "fulfilled")).toHaveLength(1);
			expect(attempts.filter(result => result.status === "rejected")).toHaveLength(1);
			expect((await rounds.roundAudit()).filter(receipt => receipt.action === "selected")).toHaveLength(1);
		});

		it("enforces cumulative continuation budget, stop, exact replay, and accounting integrity", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-continuation-"));
			roots.push(root);
			const c = candidate("continuation", parent, 7);
			const rounds = new SkillOptimizationRoundStore(root, new SkillPromotionStore(root, storeOptions));
			const round = roundFor(c);
			await rounds.open(round);
			const selection = await rounds.select(
				round.roundDigest,
				c.candidateDigest,
				[digest("continuation-training")],
				signedSelection(round, c.candidateDigest, [digest("continuation-training")]),
			);
			await rounds.finalize(signedGate(round, selection, "failed"));
			const first = createFailureContinuation({
				roundDigest: round.roundDigest,
				trainingProblemDigest: digest("continuation-problem-1"),
				trainingEvidenceDigests: [digest("continuation-evidence-1")],
				category: "failed",
				budget: 1,
				disposition: "continue-training",
			});
			await expect(rounds.continueTraining(first)).resolves.toEqual(first);
			await expect(rounds.continueTraining(first)).resolves.toEqual(first);
			const stop = createFailureContinuation({
				roundDigest: round.roundDigest,
				trainingProblemDigest: digest("continuation-problem-2"),
				trainingEvidenceDigests: [digest("continuation-evidence-2")],
				category: "failed",
				budget: 1,
				disposition: "stop",
			});
			await expect(rounds.continueTraining(stop)).resolves.toEqual(stop);
			const afterStop = createFailureContinuation({
				roundDigest: round.roundDigest,
				trainingProblemDigest: digest("continuation-problem-3"),
				trainingEvidenceDigests: [digest("continuation-evidence-3")],
				category: "unknown",
				budget: 1,
				disposition: "continue-training",
			});
			await expect(rounds.continueTraining(afterStop)).rejects.toThrow("exhausted");
			expect(() =>
				createFailureContinuation({
					roundDigest: round.roundDigest,
					trainingProblemDigest: digest("zero-budget"),
					trainingEvidenceDigests: [digest("zero-evidence")],
					category: "unknown",
					budget: 0,
					disposition: "continue-training",
				}),
			).toThrow("invalid");
			await fs.writeFile(
				path.join(root, "skill-opt/continuation-state", `${round.roundDigest}.json`),
				JSON.stringify({
					used: 1,
					stopped: true,
					appliedDigests: [first.continuationDigest, stop.continuationDigest],
				}),
			);
			await expect(rounds.continueTraining(stop)).rejects.toThrow("accounting mismatch");
		});

		it("repairs missing audit tails and blocks corrupt audit chains before mutation", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-audit-"));
			roots.push(root);
			const c = candidate("audit", parent, 8);
			const rounds = new SkillOptimizationRoundStore(root, new SkillPromotionStore(root, storeOptions));
			const round = roundFor(c);
			await rounds.open(round);
			const auditPath = path.join(root, "skill-opt/round-audit.jsonl");
			await fs.writeFile(auditPath, "");
			await expect(rounds.open(round)).resolves.toEqual(round);
			const repaired = await rounds.roundAudit();
			expect(repaired).toHaveLength(1);
			await fs.writeFile(
				auditPath,
				`${JSON.stringify({ ...repaired[0], artifactDigest: digest("tampered-audit") })}\n`,
			);
			await expect(rounds.roundAudit()).rejects.toThrow("corrupt");
			await expect(
				rounds.select(
					round.roundDigest,
					c.candidateDigest,
					[digest("audit-training")],
					signedSelection(round, c.candidateDigest, [digest("audit-training")]),
				),
			).rejects.toThrow("corrupt");
			await expect(
				fs.access(path.join(root, "skill-opt/selections", `${round.roundDigest}.json`)),
			).rejects.toThrow();
		});

		it("rejects a valid candidate whose lineage differs from the sealed round", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-lineage-"));
			roots.push(root);
			const alternateParent = { ...parent, contentDigest: digest("alternate-parent") };
			const c = candidate("lineage", alternateParent, 9);
			const promotion = new SkillPromotionStore(root, storeOptions);
			const reports = reportsFor(c);
			await promotion.evaluateAndRecord(c, reports.candidateReports, reports.baseline);
			const rounds = new SkillOptimizationRoundStore(root, promotion);
			const round = roundFor(c);
			await rounds.open(round);
			const selection = await rounds.select(
				round.roundDigest,
				c.candidateDigest,
				[digest("lineage-training")],
				signedSelection(round, c.candidateDigest, [digest("lineage-training")]),
			);
			const gate = signedGate(round, selection, "passed");
			await expect(rounds.finalize(gate)).rejects.toThrow("sealed round lineage");
			expect(await promotion.active()).toBeUndefined();
			await expect(
				fs.access(path.join(root, "skill-opt/finalizations", `${round.roundDigest}.json`)),
			).rejects.toThrow();
			await expect(
				fs.access(path.join(root, "skill-opt/holdout-gates", `${gate.gateDigest}.json`)),
			).rejects.toThrow();
		});
		it("recovers an exact passed finalization after promotion commits before closure", async () => {
			const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-finalize-recovery-"));
			roots.push(root);
			const c = candidate("recovery candidate");
			const reports = reportsFor(c);
			const promotion = new SkillPromotionStore(root, {
				...storeOptions,
				faultInjection: {
					afterActiveWrite: () => {
						throw new Error("crash-after-promotion");
					},
				},
			});
			await promotion.evaluateAndRecord(c, reports.candidateReports, reports.baseline);
			const rounds = new SkillOptimizationRoundStore(root, promotion);
			const round = roundFor(c);
			await rounds.open(round);
			const selection = await rounds.select(
				round.roundDigest,
				c.candidateDigest,
				[digest("training-recovery")],
				signedSelection(round, c.candidateDigest, [digest("training-recovery")]),
			);
			const gate = signedGate(round, selection, "passed");
			await expect(rounds.finalize(gate)).rejects.toThrow("crash-after-promotion");
			await expect(rounds.finalize(gate)).resolves.toMatchObject({
				status: "promoted",
				holdoutLooksUsed: 1,
			});
			await expect(rounds.finalize(signedGate(round, selection, "failed"))).rejects.toThrow("already been consumed");
		});
	});
});
