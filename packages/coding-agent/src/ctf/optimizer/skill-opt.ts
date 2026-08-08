import { createPublicKey, randomUUID, verify } from "node:crypto";
import { RootedStore } from "../../gjc-runtime/storage/rooted-store";
import { canonicalDigest, canonicalJson, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type EffectiveSkillV1,
	effectiveSkillDigest,
	type SkillArtifactV1,
	skillContentDigest,
	validateEffectiveSkill,
	validateSkillArtifact,
} from "../contracts/skill";

export type Candidate = Readonly<{
	schemaVersion: "ctf-skill-opt-candidate-1";
	candidateDigest: Digest;
	parentSkillDigest: Digest;
	benchmarkLockDigest: Digest;
	trainingCorpusDigest: Digest;
	holdoutCommitmentDigest: Digest;
	generationTraceDigest: Digest;
	generation: number;
	artifact: SkillArtifactV1;
	createdAt: string;
}>;

export type CandidateGenerationEvidence = Readonly<{
	benchmarkLockDigest: Digest;
	trainingCorpusDigest: Digest;
	holdoutCommitmentDigest: Digest;
	generationTraceDigest: Digest;
	generation: number;
	createdAt: string;
}>;

export type TrustedEvaluatorKey = Readonly<{
	keyId: string;
	algorithm: "ed25519";
	publicKey: string;
	active: boolean;
}>;

export type BenchmarkReport = Readonly<{
	schemaVersion: "ctf-skill-opt-report-1";
	reportDigest: Digest;
	subjectDigest: Digest;
	parentSkillDigest: Digest;
	benchmarkLockDigest: Digest;
	splitDigest: Digest;
	split: "training" | "holdout";
	status: "passed" | "failed" | "unknown";
	sampleCount: number;
	successCount: number;
	unknownCount: number;
	metrics: Readonly<Record<string, number>>;
	createdAt: string;
	evaluatorKeyId: string;
	signatureAlgorithm: "ed25519";
	signature: string;
}>;

export type ImprovementPolicy = Readonly<{
	metric: string;
	minimumDelta: number;
	holdoutMinimumDelta: number;
	minimumSamples: number;
	confidenceLevel: 0.9 | 0.95 | 0.99;
	maximumUnknownCount: number;
}>;

export type Evaluation = Readonly<{
	schemaVersion: "ctf-skill-opt-evaluation-1";
	evaluationDigest: Digest;
	candidateDigest: Digest;
	parentSkillDigest: Digest;
	benchmarkLockDigest: Digest;
	status: "eligible" | "unknown" | "failed";
	reason: string;
	training?: Readonly<Record<string, number>>;
	holdout?: Readonly<Record<string, number>>;
}>;

export type AuditReceipt = Readonly<{
	schemaVersion: "ctf-skill-opt-audit-1";
	operationId: string;
	sequence: number;
	phase: "prepared" | "committed" | "aborted";
	action: "promote" | "rollback";
	fromDigest: Digest | null;
	toDigest: Digest;
	candidateDigest: Digest;
	previousReceiptDigest: Digest | null;
	receiptDigest: Digest;
}>;

export type ActiveSkillCandidate = Readonly<{
	schemaVersion: "ctf-skill-opt-active-1";
	candidateDigest: Digest;
	skillDigest: Digest;
	artifact: SkillArtifactV1;
	updatedAt: string;
}>;

export type SkillPromotionStoreOptions = Readonly<{
	baselineSkillDigest: Digest;
	trustedEvaluatorKeys: readonly TrustedEvaluatorKey[];
	improvementPolicy: ImprovementPolicy;
	faultInjection?: Readonly<{
		afterPrepared?: () => void | Promise<void>;
		afterActiveWrite?: () => void | Promise<void>;
	}>;
}>;

const CANDIDATE_PATH = (digest: Digest) => `skill-opt/candidates/${digest}.json`;
const EVALUATION_PATH = (digest: Digest) => `skill-opt/evaluations/${digest}.json`;
const ACTIVE_PATH = "skill-opt/active.json";
const AUDIT_PATH = "skill-opt/audit.jsonl";
const TRANSACTION_PATH = "skill-opt/transaction.json";
const LOCK_PATH = "skill-opt/promotion";
const ZERO: Digest | null = null;

function reject(message: string): never {
	throw new CtfError("integrity_error", message);
}

function requireDigest(value: unknown, label: string): Digest {
	if (!isDigest(value)) reject(`${label} is invalid`);
	return value;
}

function requireTimestamp(value: string, label: string): void {
	if (!value.trim() || Number.isNaN(Date.parse(value))) reject(`${label} is invalid`);
}

function candidateBasis(candidate: Omit<Candidate, "candidateDigest">): Omit<Candidate, "candidateDigest"> {
	return candidate;
}

export function generateSkillCandidate(
	parent: EffectiveSkillV1,
	artifactInput: unknown,
	evidence: CandidateGenerationEvidence,
): Candidate {
	const parentSkill = validateEffectiveSkill(parent);
	const artifact = validateSkillArtifact(artifactInput);
	if (artifact.id !== parentSkill.id || artifact.version !== parentSkill.version) {
		reject("candidate artifact identity does not match its parent skill");
	}
	if (artifact.loaderDigest !== parentSkill.loaderDigest || artifact.buildDigest !== parentSkill.buildDigest) {
		reject("candidate may change skill content only, not loader or build identity");
	}
	if (!Number.isSafeInteger(evidence.generation) || evidence.generation < 1) reject("candidate generation is invalid");
	requireTimestamp(evidence.createdAt, "candidate timestamp");
	const core = {
		schemaVersion: "ctf-skill-opt-candidate-1" as const,
		parentSkillDigest: effectiveSkillDigest(parentSkill),
		benchmarkLockDigest: requireDigest(evidence.benchmarkLockDigest, "benchmark lock digest"),
		trainingCorpusDigest: requireDigest(evidence.trainingCorpusDigest, "training corpus digest"),
		holdoutCommitmentDigest: requireDigest(evidence.holdoutCommitmentDigest, "holdout commitment digest"),
		generationTraceDigest: requireDigest(evidence.generationTraceDigest, "generation trace digest"),
		generation: evidence.generation,
		artifact,
		createdAt: evidence.createdAt,
	};
	return Object.freeze({ ...core, candidateDigest: canonicalDigest(core) });
}

export function validateSkillCandidate(value: unknown): Candidate {
	if (value === null || typeof value !== "object") reject("skill candidate is invalid");
	const candidate = value as Candidate;
	const artifact = validateSkillArtifact(candidate.artifact);
	if (candidate.schemaVersion !== "ctf-skill-opt-candidate-1") reject("skill candidate schema is invalid");
	for (const [label, digest] of [
		["candidate digest", candidate.candidateDigest],
		["parent skill digest", candidate.parentSkillDigest],
		["benchmark lock digest", candidate.benchmarkLockDigest],
		["training corpus digest", candidate.trainingCorpusDigest],
		["holdout commitment digest", candidate.holdoutCommitmentDigest],
		["generation trace digest", candidate.generationTraceDigest],
	] as const)
		requireDigest(digest, label);
	if (!Number.isSafeInteger(candidate.generation) || candidate.generation < 1)
		reject("candidate generation is invalid");
	requireTimestamp(candidate.createdAt, "candidate timestamp");
	const basis = candidateBasis({
		schemaVersion: candidate.schemaVersion,
		parentSkillDigest: candidate.parentSkillDigest,
		benchmarkLockDigest: candidate.benchmarkLockDigest,
		trainingCorpusDigest: candidate.trainingCorpusDigest,
		holdoutCommitmentDigest: candidate.holdoutCommitmentDigest,
		generationTraceDigest: candidate.generationTraceDigest,
		generation: candidate.generation,
		artifact,
		createdAt: candidate.createdAt,
	});
	if (!digestsEqual(canonicalDigest(basis), candidate.candidateDigest)) reject("skill candidate digest mismatch");
	return Object.freeze({ ...basis, candidateDigest: candidate.candidateDigest });
}

export function benchmarkReportSigningPayload(report: Omit<BenchmarkReport, "reportDigest" | "signature">): unknown {
	return report;
}

function reportBasis(report: BenchmarkReport): Omit<BenchmarkReport, "reportDigest"> {
	const { reportDigest: _ignored, ...basis } = report;
	return basis;
}

export function validateBenchmarkReport(value: unknown, keys: readonly TrustedEvaluatorKey[]): BenchmarkReport {
	if (typeof value !== "object" || value === null) reject("benchmark report is not an object");
	const report = value as BenchmarkReport;
	if (report.schemaVersion !== "ctf-skill-opt-report-1") reject("benchmark report schema is invalid");
	for (const [label, digest] of [
		["report digest", report.reportDigest],
		["subject digest", report.subjectDigest],
		["parent skill digest", report.parentSkillDigest],
		["benchmark lock digest", report.benchmarkLockDigest],
		["split digest", report.splitDigest],
	] as const)
		requireDigest(digest, label);
	if (report.split !== "training" && report.split !== "holdout") reject("benchmark report split is invalid");
	if (!["passed", "failed", "unknown"].includes(report.status)) reject("benchmark report status is invalid");
	if (
		!Number.isSafeInteger(report.sampleCount) ||
		report.sampleCount < 1 ||
		!Number.isSafeInteger(report.successCount) ||
		report.successCount < 0 ||
		report.successCount > report.sampleCount ||
		!Number.isSafeInteger(report.unknownCount) ||
		report.unknownCount < 0 ||
		report.unknownCount > report.sampleCount ||
		report.successCount + report.unknownCount > report.sampleCount
	)
		reject("benchmark report counts are invalid");
	if (typeof report.metrics !== "object" || report.metrics === null) reject("benchmark report metrics are invalid");
	for (const [key, metric] of Object.entries(report.metrics)) {
		if (!key.trim() || typeof metric !== "number" || !Number.isFinite(metric))
			reject("benchmark report metric is invalid");
	}
	requireTimestamp(report.createdAt, "benchmark report timestamp");
	if (report.signatureAlgorithm !== "ed25519" || !report.signature) reject("benchmark report signature is missing");
	const key = keys.find(candidate => candidate.keyId === report.evaluatorKeyId && candidate.active);
	if (key === undefined || key.algorithm !== "ed25519") reject("benchmark evaluator key is not trusted");
	const { reportDigest: _digest, signature, ...unsigned } = report;
	let verified = false;
	try {
		verified = verify(
			null,
			Buffer.from(canonicalJson(benchmarkReportSigningPayload(unsigned))),
			createPublicKey({ key: Buffer.from(key.publicKey, "base64"), format: "der", type: "spki" }),
			Buffer.from(signature, "base64"),
		);
	} catch {
		verified = false;
	}
	if (!verified) reject("benchmark report signature is invalid");
	if (!digestsEqual(canonicalDigest(reportBasis(report)), report.reportDigest))
		reject("benchmark report digest mismatch");
	return Object.freeze({ ...report, metrics: Object.freeze({ ...report.metrics }) });
}

function zScore(confidence: ImprovementPolicy["confidenceLevel"]): number {
	if (confidence === 0.9) return 1.6448536269514722;
	if (confidence === 0.95) return 1.959963984540054;
	return 2.5758293035489004;
}

function wilson(
	successes: number,
	samples: number,
	confidence: ImprovementPolicy["confidenceLevel"],
): readonly [number, number] {
	const z = zScore(confidence);
	const rate = successes / samples;
	const denominator = 1 + (z * z) / samples;
	const center = (rate + (z * z) / (2 * samples)) / denominator;
	const margin = (z / denominator) * Math.sqrt((rate * (1 - rate)) / samples + (z * z) / (4 * samples * samples));
	return [Math.max(0, center - margin), Math.min(1, center + margin)];
}

function evaluationResult(
	candidate: Candidate,
	status: Evaluation["status"],
	reason: string,
	training?: Readonly<Record<string, number>>,
	holdout?: Readonly<Record<string, number>>,
): Evaluation {
	const basis = {
		schemaVersion: "ctf-skill-opt-evaluation-1" as const,
		candidateDigest: candidate.candidateDigest,
		parentSkillDigest: candidate.parentSkillDigest,
		benchmarkLockDigest: candidate.benchmarkLockDigest,
		status,
		reason,
		...(training === undefined ? {} : { training }),
		...(holdout === undefined ? {} : { holdout }),
	};
	return Object.freeze({ ...basis, evaluationDigest: canonicalDigest(basis) });
}

function exactlyOne(
	reports: readonly BenchmarkReport[],
	subjectDigest: Digest,
	split: BenchmarkReport["split"],
): BenchmarkReport | undefined {
	const matches = reports.filter(report => report.subjectDigest === subjectDigest && report.split === split);
	if (matches.length > 1) reject("duplicate benchmark reports are not permitted");
	return matches[0];
}

export function evaluateSkillCandidate(
	candidateInput: Candidate,
	candidateReports: readonly unknown[],
	baselineReports: readonly unknown[],
	policy: ImprovementPolicy,
	keys: readonly TrustedEvaluatorKey[],
): Evaluation {
	const candidate = validateSkillCandidate(candidateInput);
	if (
		!policy.metric.trim() ||
		!Number.isFinite(policy.minimumDelta) ||
		!Number.isFinite(policy.holdoutMinimumDelta) ||
		!Number.isSafeInteger(policy.minimumSamples) ||
		policy.minimumSamples < 1 ||
		!Number.isSafeInteger(policy.maximumUnknownCount) ||
		policy.maximumUnknownCount < 0
	)
		reject("improvement policy is invalid");
	const checkedCandidate = candidateReports.map(report => validateBenchmarkReport(report, keys));
	const checkedBaseline = baselineReports.map(report => validateBenchmarkReport(report, keys));
	const candidateTraining = exactlyOne(checkedCandidate, candidate.candidateDigest, "training");
	const candidateHoldout = exactlyOne(checkedCandidate, candidate.candidateDigest, "holdout");
	const baselineTraining = exactlyOne(checkedBaseline, candidate.parentSkillDigest, "training");
	const baselineHoldout = exactlyOne(checkedBaseline, candidate.parentSkillDigest, "holdout");
	if (!candidateTraining || !candidateHoldout || !baselineTraining || !baselineHoldout) {
		return evaluationResult(
			candidate,
			"unknown",
			"signed training and holdout reports are required for candidate and baseline",
		);
	}
	const reports = [candidateTraining, candidateHoldout, baselineTraining, baselineHoldout];
	if (reports.some(report => report.benchmarkLockDigest !== candidate.benchmarkLockDigest)) {
		return evaluationResult(candidate, "failed", "benchmark lock lineage mismatch");
	}
	if (
		reports.some(report => report.parentSkillDigest !== candidate.parentSkillDigest) ||
		candidateTraining.splitDigest !== candidate.trainingCorpusDigest ||
		candidateHoldout.splitDigest !== candidate.holdoutCommitmentDigest ||
		candidateTraining.splitDigest !== baselineTraining.splitDigest ||
		candidateHoldout.splitDigest !== baselineHoldout.splitDigest ||
		candidateTraining.splitDigest === candidateHoldout.splitDigest
	) {
		return evaluationResult(candidate, "failed", "benchmark split or candidate lineage mismatch");
	}
	if (reports.some(report => report.status !== "passed"))
		return evaluationResult(candidate, "failed", "benchmark report failed");
	if (reports.some(report => report.sampleCount < policy.minimumSamples)) {
		return evaluationResult(candidate, "unknown", "sample count is below policy minimum");
	}
	if (reports.some(report => report.unknownCount > policy.maximumUnknownCount)) {
		return evaluationResult(candidate, "unknown", "unknown outcomes exceed policy maximum");
	}
	const candidateMetric = candidateTraining.metrics[policy.metric];
	const baselineMetric = baselineTraining.metrics[policy.metric];
	if (candidateMetric === undefined || baselineMetric === undefined)
		return evaluationResult(candidate, "unknown", "metric is unknown");
	if (candidateMetric - baselineMetric < policy.minimumDelta) {
		return evaluationResult(candidate, "failed", "training improvement is below policy");
	}
	const [candidateLower] = wilson(candidateHoldout.successCount, candidateHoldout.sampleCount, policy.confidenceLevel);
	const [, baselineUpper] = wilson(baselineHoldout.successCount, baselineHoldout.sampleCount, policy.confidenceLevel);
	if (candidateLower - baselineUpper < policy.holdoutMinimumDelta) {
		return evaluationResult(candidate, "failed", "holdout confidence interval does not prove improvement");
	}
	return evaluationResult(
		candidate,
		"eligible",
		"signed train and frozen-holdout evidence meets policy",
		candidateTraining.metrics,
		candidateHoldout.metrics,
	);
}

function activeSkillDigest(candidate: Candidate): Digest {
	return effectiveSkillDigest({
		schemaVersion: "ctf-skill-1",
		id: candidate.artifact.id,
		version: candidate.artifact.version,
		contentDigest: candidate.artifact.contentDigest,
		loaderDigest: candidate.artifact.loaderDigest,
		buildDigest: candidate.artifact.buildDigest,
		workspaceOverrideDigest: candidate.artifact.contentDigest,
		source: "workspace-override",
		resolvedAt: candidate.createdAt,
	});
}

async function readJson<T>(store: RootedStore, relative: string): Promise<T | undefined> {
	const file = Bun.file(store.resolve(relative));
	if (!(await file.exists())) return undefined;
	return file.json() as Promise<T>;
}

async function readJsonl<T>(store: RootedStore, relative: string): Promise<T[]> {
	const file = Bun.file(store.resolve(relative));
	if (!(await file.exists())) return [];
	const text = await file.text();
	return text
		.split("\n")
		.filter(Boolean)
		.map(line => JSON.parse(line) as T);
}

export class SkillPromotionStore {
	readonly #store: RootedStore;
	readonly #baselineSkillDigest: Digest;
	readonly #faultInjection: SkillPromotionStoreOptions["faultInjection"];
	readonly #trustedEvaluatorKeys: readonly TrustedEvaluatorKey[];
	readonly #improvementPolicy: ImprovementPolicy;

	constructor(root: string | RootedStore, options: SkillPromotionStoreOptions) {
		this.#store = typeof root === "string" ? new RootedStore(root, { durability: "ctf" }) : root;
		this.#baselineSkillDigest = requireDigest(options.baselineSkillDigest, "baseline skill digest");
		this.#trustedEvaluatorKeys = [...options.trustedEvaluatorKeys];
		this.#improvementPolicy = options.improvementPolicy;
		this.#faultInjection = options.faultInjection;
	}

	async active(): Promise<ActiveSkillCandidate | undefined> {
		return readJson<ActiveSkillCandidate>(this.#store, ACTIVE_PATH);
	}

	async receipts(): Promise<readonly AuditReceipt[]> {
		const receipts = await readJsonl<AuditReceipt>(this.#store, AUDIT_PATH);
		let previous: Digest | null = null;
		for (const [index, receipt] of receipts.entries()) {
			const { receiptDigest, ...basis } = receipt;
			if (
				receipt.sequence !== index + 1 ||
				receipt.previousReceiptDigest !== previous ||
				canonicalDigest(basis) !== receiptDigest
			) {
				reject("skill optimization audit chain is corrupt");
			}
			previous = receiptDigest;
		}
		return receipts;
	}

	async evaluateAndRecord(
		candidateInput: Candidate,
		candidateReports: readonly unknown[],
		baselineReports: readonly unknown[],
	): Promise<Evaluation> {
		const candidate = validateSkillCandidate(candidateInput);
		const evaluation = evaluateSkillCandidate(
			candidate,
			candidateReports,
			baselineReports,
			this.#improvementPolicy,
			this.#trustedEvaluatorKeys,
		);
		await this.#record(candidate, evaluation);
		return evaluation;
	}

	async #record(candidateInput: Candidate, evaluation: Evaluation): Promise<void> {
		const candidate = validateSkillCandidate(candidateInput);
		if (
			evaluation.candidateDigest !== candidate.candidateDigest ||
			evaluation.parentSkillDigest !== candidate.parentSkillDigest ||
			evaluation.benchmarkLockDigest !== candidate.benchmarkLockDigest
		) {
			reject("candidate evaluation identity mismatch");
		}
		const { evaluationDigest, ...basis } = evaluation;
		if (canonicalDigest(basis) !== evaluationDigest) reject("candidate evaluation digest mismatch");
		await this.#store.writeJsonAtomic(CANDIDATE_PATH(candidate.candidateDigest), candidate, { durability: "ctf" });
		await this.#store.writeJsonAtomic(EVALUATION_PATH(candidate.candidateDigest), evaluation, { durability: "ctf" });
	}

	async promote(
		candidateInput: Candidate,
		candidateReports: readonly unknown[],
		baselineReports: readonly unknown[],
	): Promise<AuditReceipt> {
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.recover();
			const candidate = validateSkillCandidate(candidateInput);
			const evaluation = evaluateSkillCandidate(
				candidate,
				candidateReports,
				baselineReports,
				this.#improvementPolicy,
				this.#trustedEvaluatorKeys,
			);
			await this.#record(candidate, evaluation);
			if (evaluation.status !== "eligible") reject("candidate is not eligible for promotion");
			const active = await this.active();
			const expectedParent = active?.skillDigest ?? this.#baselineSkillDigest;
			if (candidate.parentSkillDigest !== expectedParent) reject("candidate parent is stale");
			return this.#commit("promote", candidate, active?.candidateDigest ?? null);
		});
	}

	async rollback(targetDigest: Digest): Promise<AuditReceipt> {
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.recover();
			const candidate = await readJson<Candidate>(
				this.#store,
				CANDIDATE_PATH(requireDigest(targetDigest, "rollback target")),
			);
			if (candidate === undefined) reject("rollback target was not previously recorded");
			const receipts = await this.receipts();
			if (!receipts.some(receipt => receipt.phase === "committed" && receipt.toDigest === targetDigest)) {
				reject("rollback target was not previously promoted");
			}
			return this.#commit(
				"rollback",
				validateSkillCandidate(candidate),
				(await this.active())?.candidateDigest ?? null,
			);
		});
	}

	async recover(): Promise<void> {
		const transaction = await readJson<{
			schemaVersion: "ctf-skill-opt-transaction-1";
			operationId: string;
			action: AuditReceipt["action"];
			candidateDigest: Digest;
			fromDigest: Digest | null;
			phase: "prepared" | "committed" | "aborted";
		}>(this.#store, TRANSACTION_PATH);
		if (transaction === undefined || transaction.phase !== "prepared") return;
		const candidate = await readJson<Candidate>(this.#store, CANDIDATE_PATH(transaction.candidateDigest));
		if (candidate === undefined) reject("prepared promotion candidate is missing");
		const active = await this.active();
		if (active?.candidateDigest === transaction.candidateDigest) {
			await this.#appendReceipt(
				transaction.operationId,
				transaction.action,
				"committed",
				transaction.fromDigest,
				candidate,
			);
			await this.#store.writeJsonAtomic(
				TRANSACTION_PATH,
				{ ...transaction, phase: "committed" },
				{ durability: "ctf" },
			);
		} else {
			await this.#appendReceipt(
				transaction.operationId,
				transaction.action,
				"aborted",
				transaction.fromDigest,
				candidate,
			);
			await this.#store.writeJsonAtomic(
				TRANSACTION_PATH,
				{ ...transaction, phase: "aborted" },
				{ durability: "ctf" },
			);
		}
	}

	async #commit(
		action: AuditReceipt["action"],
		candidate: Candidate,
		fromDigest: Digest | null,
	): Promise<AuditReceipt> {
		const operationId = canonicalDigest({
			action,
			fromDigest,
			candidateDigest: candidate.candidateDigest,
			nonce: randomUUID(),
		});
		const transaction = {
			schemaVersion: "ctf-skill-opt-transaction-1" as const,
			operationId,
			action,
			candidateDigest: candidate.candidateDigest,
			fromDigest,
			phase: "prepared" as const,
		};
		await this.#store.writeJsonAtomic(TRANSACTION_PATH, transaction, { durability: "ctf" });
		await this.#appendReceipt(operationId, action, "prepared", fromDigest, candidate);
		await this.#faultInjection?.afterPrepared?.();
		const active: ActiveSkillCandidate = {
			schemaVersion: "ctf-skill-opt-active-1",
			candidateDigest: candidate.candidateDigest,
			skillDigest: activeSkillDigest(candidate),
			artifact: candidate.artifact,
			updatedAt: candidate.createdAt,
		};
		await this.#store.writeJsonAtomic(ACTIVE_PATH, active, { durability: "ctf" });
		await this.#faultInjection?.afterActiveWrite?.();
		const receipt = await this.#appendReceipt(operationId, action, "committed", fromDigest, candidate);
		await this.#store.writeJsonAtomic(
			TRANSACTION_PATH,
			{ ...transaction, phase: "committed" },
			{ durability: "ctf" },
		);
		return receipt;
	}

	async #appendReceipt(
		operationId: string,
		action: AuditReceipt["action"],
		phase: AuditReceipt["phase"],
		fromDigest: Digest | null,
		candidate: Candidate,
	): Promise<AuditReceipt> {
		const receipts = await this.receipts();
		const duplicate = receipts.find(receipt => receipt.operationId === operationId && receipt.phase === phase);
		if (duplicate !== undefined) return duplicate;
		const basis = {
			schemaVersion: "ctf-skill-opt-audit-1" as const,
			operationId,
			sequence: receipts.length + 1,
			phase,
			action,
			fromDigest,
			toDigest: candidate.candidateDigest,
			candidateDigest: candidate.candidateDigest,
			previousReceiptDigest: receipts.at(-1)?.receiptDigest ?? ZERO,
		};
		const receipt = Object.freeze({ ...basis, receiptDigest: canonicalDigest(basis) });
		await this.#store.appendJsonl(AUDIT_PATH, receipt, { durability: "ctf" });
		return receipt;
	}
}

export function makeSkillArtifact(
	id: string,
	version: string,
	content: string,
	loaderDigest: Digest,
	buildDigest: Digest,
): SkillArtifactV1 {
	return {
		schemaVersion: "ctf-skill-1",
		id,
		version,
		content,
		contentDigest: skillContentDigest(content),
		loaderDigest,
		buildDigest,
	};
}
