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
	evaluateSkillCandidate,
	generateSkillCandidate,
	makeSkillArtifact,
	SkillPromotionStore,
	type TrustedEvaluatorKey,
	validateBenchmarkReport,
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
const storeOptions = {
	baselineSkillDigest: effectiveSkillDigest(parent),
	trustedEvaluatorKeys: [key],
	improvementPolicy: policy,
};

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

	it("persists eligible promotion, rejects stale parents, and rolls back with a chained audit", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-skill-opt-"));
		roots.push(root);
		const first = candidate();
		const firstReports = reportsFor(first);
		const store = new SkillPromotionStore(root, storeOptions);
		const promoted = await store.promote(first, firstReports.candidateReports, firstReports.baseline);
		expect(promoted).toMatchObject({ action: "promote", phase: "committed" });
		expect(await store.active()).toMatchObject({ candidateDigest: first.candidateDigest });

		const stale = candidate("stale", parent, 2);
		const staleReports = reportsFor(stale);
		await expect(store.promote(stale, staleReports.candidateReports, staleReports.baseline)).rejects.toThrow("stale");
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
		const evidence = reportsFor(c);
		const before = new SkillPromotionStore(firstRoot, {
			...storeOptions,
			faultInjection: {
				afterPrepared: () => {
					throw new Error("crash-before-active");
				},
			},
		});
		await expect(before.promote(c, evidence.candidateReports, evidence.baseline)).rejects.toThrow(
			"crash-before-active",
		);
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
		await expect(after.promote(c, evidence.candidateReports, evidence.baseline)).rejects.toThrow(
			"crash-after-active",
		);
		const afterRecovered = new SkillPromotionStore(secondRoot, storeOptions);
		await afterRecovered.recover();
		expect(await afterRecovered.active()).toMatchObject({ candidateDigest: c.candidateDigest });
		expect((await afterRecovered.receipts()).at(-1)?.phase).toBe("committed");
	});
});
