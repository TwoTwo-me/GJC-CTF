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
	roundAuthorityKeys: readonly RoundAuthorityKey[];
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
const FINALIZED_PROMOTION_AUTHORITY = Object.freeze({});
type FinalizedPromotionAuthority = typeof FINALIZED_PROMOTION_AUTHORITY;

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
	readonly #roundAuthorityKeys: readonly RoundAuthorityKey[];
	readonly #improvementPolicy: ImprovementPolicy;

	constructor(root: string | RootedStore, options: SkillPromotionStoreOptions) {
		this.#store = typeof root === "string" ? new RootedStore(root, { durability: "ctf" }) : root;
		this.#baselineSkillDigest = requireDigest(options.baselineSkillDigest, "baseline skill digest");
		this.#trustedEvaluatorKeys = [...options.trustedEvaluatorKeys];
		this.#roundAuthorityKeys = validateRoundAuthorityRegistry(options.roundAuthorityKeys);
		this.#improvementPolicy = options.improvementPolicy;
		this.#faultInjection = options.faultInjection;
	}

	get storageRoot(): string {
		return this.#store.root;
	}

	get roundAuthorityKeys(): readonly RoundAuthorityKey[] {
		return this.#roundAuthorityKeys;
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
		_candidateInput: Candidate,
		_candidateReports: readonly unknown[],
		_baselineReports: readonly unknown[],
	): Promise<AuditReceipt> {
		reject("legacy optimizer-local benchmark reports are diagnostic only and cannot promote a skill");
	}

	/** Module-confined commit primitive; only a validated sealed round can supply its authority. */
	async promoteFinalized(candidateInput: Candidate, authority: FinalizedPromotionAuthority): Promise<AuditReceipt> {
		if (authority !== FINALIZED_PROMOTION_AUTHORITY) reject("skill promotion requires sealed round authority");
		const candidate = validateSkillCandidate(candidateInput);
		const active = await this.active();
		const expectedParent = active?.skillDigest ?? this.#baselineSkillDigest;
		if (candidate.parentSkillDigest !== expectedParent) reject("candidate parent is stale");
		await this.#store.writeJsonAtomic(CANDIDATE_PATH(candidate.candidateDigest), candidate, { durability: "ctf" });
		return this.#commit("promote", candidate, active?.candidateDigest ?? null);
	}

	get baselineSkillDigest(): Digest {
		return this.#baselineSkillDigest;
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
/**
 * The round contracts deliberately contain only identities and evidence
 * digests.  Benchmark observations and candidate artifacts never cross this
 * boundary.
 */
export type SkillBenchmarkIdentityV1 = Readonly<{
	benchmarkLockDigest: Digest;
	trainingCorpusDigest: Digest;
	holdoutCommitmentDigest: Digest;
	calibrationDigest: Digest;
	harnessDigest: Digest;
	toolchainDigest: Digest;
	modelFingerprint: Digest;
	backendFingerprint: Digest;
	policyDigest: Digest;
	trainingEvaluatorKeyAnchorDigest: Digest;
	holdoutEvaluatorKeyAnchorDigest: Digest;
}>;

export type SkillOptimizationRoundV1 = Readonly<{
	schemaVersion: "ctf-skill-opt-round-2";
	roundDigest: Digest;
	incumbentSkillDigest: Digest;
	committedCohortDigests: readonly Digest[];
	benchmark: SkillBenchmarkIdentityV1;
	authorityRegistryDigest: Digest;
	maximumContinuationBudget: number;
	scheduleDigest: Digest;
	tieBreakDigest: Digest;
	maximumHoldoutLooks: 1;
	status: "open" | "closed";
}>;

export type SkillTrainingSelectionV1 = Readonly<{
	schemaVersion: "ctf-skill-training-selection-2";
	selectionDigest: Digest;
	roundDigest: Digest;
	selectedCandidateDigest: Digest | null;
	trainingComparisonEvidenceDigests: readonly Digest[];
	evaluatorKeyId: string;
	evaluatorKeyAnchorDigest: Digest;
	signatureAlgorithm: "ed25519";
	signature: string;
}>;

export type SkillHoldoutGateV1 = Readonly<{
	schemaVersion: "ctf-skill-holdout-gate-1";
	gateDigest: Digest;
	roundDigest: Digest;
	selectionDigest: Digest;
	selectedCandidateDigest: Digest | null;
	holdoutCommitmentDigest: Digest;
	authorizedEvidenceDigests: readonly Digest[];
	evaluatorKeyId: string;
	evaluatorKeyAnchorDigest: Digest;
	signatureAlgorithm: "ed25519";
	signature: string;
	status: "passed" | "failed" | "unavailable";
	looksUsed: 1;
}>;

export type FailureContinuationV1 = Readonly<{
	schemaVersion: "ctf-skill-failure-continuation-1";
	continuationDigest: Digest;
	roundDigest: Digest;
	trainingProblemDigest: Digest;
	trainingEvidenceDigests: readonly Digest[];
	category: "failed" | "unknown";
	budget: number;
	disposition: "continue-training" | "stop";
	scored: false;
}>;

export type SkillOptimizationDecisionV1 = Readonly<{
	schemaVersion: "ctf-skill-optimization-decision-2";
	decisionDigest: Digest;
	roundDigest: Digest;
	gateDigest: Digest | null;
	status: "promoted" | "rejected" | "unavailable";
	cohortCount: number;
	holdoutLooksUsed: 0 | 1;
}>;

export type RoundAuthorityKey = TrustedEvaluatorKey &
	Readonly<{
		role: "training" | "holdout";
		keyAnchorDigest: Digest;
	}>;

export type SkillRoundAuditReceiptV1 = Readonly<{
	schemaVersion: "ctf-skill-opt-round-audit-1";
	receiptDigest: Digest;
	roundDigest: Digest;
	action: "opened" | "selected" | "finalized" | "continued";
	artifactDigest: Digest;
	previousReceiptDigest: Digest | null;
}>;

const ROUND_PATH = (digest: Digest) => `skill-opt/rounds/${digest}.json`;
const SELECTION_PATH = (roundDigest: Digest) => `skill-opt/selections/${roundDigest}.json`;
const HOLDOUT_GATE_PATH = (digest: Digest) => `skill-opt/holdout-gates/${digest}.json`;
const DECISION_PATH = (roundDigest: Digest) => `skill-opt/decisions/${roundDigest}.json`;
const CONTINUATION_PATH = (digest: Digest) => `skill-opt/continuations/${digest}.json`;
const ROUND_AUDIT_PATH = "skill-opt/round-audit.jsonl";
const FINALIZATION_PATH = (roundDigest: Digest) => `skill-opt/finalizations/${roundDigest}.json`;
const CONTINUATION_STATE_PATH = (roundDigest: Digest) => `skill-opt/continuation-state/${roundDigest}.json`;
type ContinuationState = Readonly<{
	used: number;
	stopped: boolean;
	appliedDigests: readonly Digest[];
}>;

export function roundAuthorityKeyAnchorDigest(
	key: Pick<RoundAuthorityKey, "keyId" | "algorithm" | "publicKey" | "role">,
): Digest {
	if (
		!key.keyId ||
		key.algorithm !== "ed25519" ||
		!key.publicKey ||
		(key.role !== "training" && key.role !== "holdout")
	)
		reject("round authority key material is invalid");
	return canonicalDigest({ keyId: key.keyId, algorithm: key.algorithm, publicKey: key.publicKey, role: key.role });
}

export function roundAuthorityRegistryDigest(keys: readonly RoundAuthorityKey[]): Digest {
	return canonicalDigest(
		[...keys]
			.map(key => ({
				keyId: key.keyId,
				algorithm: key.algorithm,
				publicKey: key.publicKey,
				active: key.active,
				role: key.role,
				keyAnchorDigest: key.keyAnchorDigest,
			}))
			.sort((left, right) => left.keyId.localeCompare(right.keyId)),
	);
}

function validateRoundAuthorityRegistry(keys: readonly RoundAuthorityKey[]): readonly RoundAuthorityKey[] {
	const active = keys.filter(key => key.active);
	const keyIds = new Set<string>();
	const publicKeyFingerprints = new Set<string>();
	const normalized: RoundAuthorityKey[] = [];
	for (const key of keys) {
		if (
			!key.keyId ||
			keyIds.has(key.keyId) ||
			key.algorithm !== "ed25519" ||
			!key.publicKey ||
			!digestsEqual(key.keyAnchorDigest, roundAuthorityKeyAnchorDigest(key))
		)
			reject("round authority registry key is invalid");
		let publicKeyFingerprint: string;
		try {
			const parsed = createPublicKey({ key: Buffer.from(key.publicKey, "base64"), format: "der", type: "spki" });
			if (parsed.asymmetricKeyType !== "ed25519") reject("round authority registry public key must be Ed25519");
			publicKeyFingerprint = canonicalDigest(
				Buffer.from(parsed.export({ format: "der", type: "spki" })).toString("base64"),
			);
		} catch (error) {
			if (error instanceof CtfError) throw error;
			reject("round authority registry public key is invalid");
		}
		if (publicKeyFingerprints.has(publicKeyFingerprint))
			reject("round authority registry has duplicate public key material");
		keyIds.add(key.keyId);
		publicKeyFingerprints.add(publicKeyFingerprint);
		normalized.push(Object.freeze({ ...key }));
	}
	const identities = active.map(key => `${key.role}:${key.keyAnchorDigest}`);
	if (new Set(identities).size !== identities.length)
		reject("round authority registry has duplicate active role anchor");
	return Object.freeze(normalized);
}

function requireDigestList(value: unknown, label: string, allowEmpty = false): readonly Digest[] {
	if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) reject(`${label} is invalid`);
	const digests = value.map((digest, index) => requireDigest(digest, `${label}[${index}]`));
	if (new Set(digests).size !== digests.length) reject(`${label} contains duplicates`);
	return Object.freeze(digests);
}
function rejectUnknownKeys(value: object, allowed: readonly string[], label: string): void {
	for (const key of Object.keys(value)) if (!allowed.includes(key)) reject(`${label} contains a forbidden field`);
}

function validateBenchmarkIdentity(value: unknown): SkillBenchmarkIdentityV1 {
	if (value === null || typeof value !== "object") reject("benchmark identity is invalid");
	rejectUnknownKeys(
		value,
		[
			"benchmarkLockDigest",
			"trainingCorpusDigest",
			"holdoutCommitmentDigest",
			"calibrationDigest",
			"harnessDigest",
			"toolchainDigest",
			"modelFingerprint",
			"backendFingerprint",
			"policyDigest",
			"trainingEvaluatorKeyAnchorDigest",
			"holdoutEvaluatorKeyAnchorDigest",
		],
		"benchmark identity",
	);
	const identity = value as SkillBenchmarkIdentityV1;
	for (const [label, digest] of Object.entries(identity)) requireDigest(digest, `benchmark ${label}`);
	if (digestsEqual(identity.trainingEvaluatorKeyAnchorDigest, identity.holdoutEvaluatorKeyAnchorDigest))
		reject("training and holdout evaluator anchors must differ");
	return Object.freeze({ ...identity });
}

function roundBasis(
	round: Omit<SkillOptimizationRoundV1, "roundDigest">,
): Omit<SkillOptimizationRoundV1, "roundDigest" | "status"> {
	const { status: _status, ...basis } = round;
	return basis;
}

export function createSkillOptimizationRound(
	input: Omit<SkillOptimizationRoundV1, "schemaVersion" | "roundDigest" | "status">,
): SkillOptimizationRoundV1 {
	const cohort = requireDigestList(input.committedCohortDigests, "committed cohort");
	if (cohort.length < 1) reject("committed cohort is empty");
	const basis = {
		schemaVersion: "ctf-skill-opt-round-2" as const,
		incumbentSkillDigest: requireDigest(input.incumbentSkillDigest, "incumbent skill digest"),
		committedCohortDigests: cohort,
		benchmark: validateBenchmarkIdentity(input.benchmark),
		authorityRegistryDigest: requireDigest(input.authorityRegistryDigest, "authority registry digest"),
		maximumContinuationBudget: input.maximumContinuationBudget,
		scheduleDigest: requireDigest(input.scheduleDigest, "schedule digest"),
		tieBreakDigest: requireDigest(input.tieBreakDigest, "tie break digest"),
		maximumHoldoutLooks: 1 as const,
		status: "open" as const,
	};
	if (!Number.isSafeInteger(basis.maximumContinuationBudget) || basis.maximumContinuationBudget < 0)
		reject("maximum continuation budget is invalid");
	return Object.freeze({ ...basis, roundDigest: canonicalDigest(roundBasis(basis)) });
}

export function validateSkillOptimizationRound(value: unknown): SkillOptimizationRoundV1 {
	if (value === null || typeof value !== "object") reject("skill optimization round is invalid");
	const round = value as SkillOptimizationRoundV1;
	if (round.schemaVersion !== "ctf-skill-opt-round-2" || (round.status !== "open" && round.status !== "closed"))
		reject("skill optimization round schema is invalid");
	rejectUnknownKeys(
		round,
		[
			"schemaVersion",
			"roundDigest",
			"incumbentSkillDigest",
			"committedCohortDigests",
			"benchmark",
			"authorityRegistryDigest",
			"maximumContinuationBudget",
			"scheduleDigest",
			"tieBreakDigest",
			"maximumHoldoutLooks",
			"status",
		],
		"skill optimization round",
	);
	if (round.maximumHoldoutLooks !== 1) reject("maximum holdout looks must be exactly one");
	const normalized: Omit<SkillOptimizationRoundV1, "roundDigest"> = {
		schemaVersion: round.schemaVersion,
		incumbentSkillDigest: requireDigest(round.incumbentSkillDigest, "incumbent skill digest"),
		committedCohortDigests: requireDigestList(round.committedCohortDigests, "committed cohort"),
		benchmark: validateBenchmarkIdentity(round.benchmark),
		authorityRegistryDigest: requireDigest(round.authorityRegistryDigest, "authority registry digest"),
		maximumContinuationBudget: round.maximumContinuationBudget,
		scheduleDigest: requireDigest(round.scheduleDigest, "schedule digest"),
		tieBreakDigest: requireDigest(round.tieBreakDigest, "tie break digest"),
		maximumHoldoutLooks: 1,
		status: round.status,
	};
	if (!Number.isSafeInteger(normalized.maximumContinuationBudget) || normalized.maximumContinuationBudget < 0)
		reject("maximum continuation budget is invalid");
	if (!digestsEqual(canonicalDigest(roundBasis(normalized)), requireDigest(round.roundDigest, "round digest")))
		reject("round digest mismatch");
	return Object.freeze({ ...normalized, roundDigest: round.roundDigest });
}

export function skillTrainingSelectionSigningPayload(
	selection: Omit<SkillTrainingSelectionV1, "selectionDigest" | "signature">,
): unknown {
	const { signature: _ignored, ...payload } = selection as Omit<SkillTrainingSelectionV1, "selectionDigest">;
	return payload;
}

export function selectSkillTrainingCandidate(
	roundInput: SkillOptimizationRoundV1,
	selectedCandidateDigest: Digest | null,
	trainingComparisonEvidenceDigests: readonly Digest[],
	authority: Pick<
		SkillTrainingSelectionV1,
		"evaluatorKeyId" | "evaluatorKeyAnchorDigest" | "signatureAlgorithm" | "signature"
	>,
	keys: readonly RoundAuthorityKey[],
): SkillTrainingSelectionV1 {
	const round = validateSkillOptimizationRound(roundInput);
	if (round.status !== "open") reject("round is closed");
	if (
		selectedCandidateDigest !== null &&
		!round.committedCohortDigests.includes(requireDigest(selectedCandidateDigest, "selected candidate digest"))
	)
		reject("selected candidate is not committed to the round");
	const basis = {
		schemaVersion: "ctf-skill-training-selection-2" as const,
		roundDigest: round.roundDigest,
		selectedCandidateDigest,
		trainingComparisonEvidenceDigests: requireDigestList(
			trainingComparisonEvidenceDigests,
			"training comparison evidence",
		),
		evaluatorKeyId: authority.evaluatorKeyId,
		evaluatorKeyAnchorDigest: requireDigest(authority.evaluatorKeyAnchorDigest, "training evaluator key anchor"),
		signatureAlgorithm: "ed25519" as const,
		signature: authority.signature,
	};
	if (authority.signatureAlgorithm !== "ed25519" || !basis.evaluatorKeyId || !basis.signature)
		reject("training selection signer is invalid");
	if (!digestsEqual(basis.evaluatorKeyAnchorDigest, round.benchmark.trainingEvaluatorKeyAnchorDigest))
		reject("training evaluator anchor mismatch");
	verifyRoundAuthoritySignature(
		skillTrainingSelectionSigningPayload(basis),
		basis.evaluatorKeyId,
		basis.evaluatorKeyAnchorDigest,
		basis.signature,
		"training",
		keys,
	);
	return Object.freeze({ ...basis, selectionDigest: canonicalDigest(basis) });
}

export function validateSkillTrainingSelection(
	value: unknown,
	round: SkillOptimizationRoundV1,
	keys: readonly RoundAuthorityKey[],
): SkillTrainingSelectionV1 {
	if (value === null || typeof value !== "object") reject("training selection is invalid");
	const selection = value as SkillTrainingSelectionV1;
	if (selection.schemaVersion !== "ctf-skill-training-selection-2") reject("training selection schema is invalid");
	rejectUnknownKeys(
		selection,
		[
			"schemaVersion",
			"selectionDigest",
			"roundDigest",
			"selectedCandidateDigest",
			"trainingComparisonEvidenceDigests",
			"evaluatorKeyId",
			"evaluatorKeyAnchorDigest",
			"signatureAlgorithm",
			"signature",
		],
		"training selection",
	);
	if (!digestsEqual(requireDigest(selection.roundDigest, "selection round digest"), round.roundDigest))
		reject("training selection round mismatch");
	const rebuilt = selectSkillTrainingCandidate(
		round,
		selection.selectedCandidateDigest,
		selection.trainingComparisonEvidenceDigests,
		{
			evaluatorKeyId: selection.evaluatorKeyId,
			evaluatorKeyAnchorDigest: selection.evaluatorKeyAnchorDigest,
			signatureAlgorithm: selection.signatureAlgorithm,
			signature: selection.signature,
		},
		keys,
	);
	if (!digestsEqual(rebuilt.selectionDigest, requireDigest(selection.selectionDigest, "selection digest")))
		reject("selection digest mismatch");
	return Object.freeze({ ...rebuilt, selectionDigest: selection.selectionDigest });
}

export function skillHoldoutGateSigningPayload(gate: Omit<SkillHoldoutGateV1, "gateDigest" | "signature">): unknown {
	const { signature: _ignored, ...payload } = gate as Omit<SkillHoldoutGateV1, "gateDigest">;
	return payload;
}

function verifyRoundAuthoritySignature(
	payload: unknown,
	keyId: string,
	anchor: Digest,
	signature: string,
	role: RoundAuthorityKey["role"],
	keys: readonly RoundAuthorityKey[],
): void {
	const matches = keys.filter(candidate => candidate.keyId === keyId);
	const key = matches[0];
	if (
		matches.length !== 1 ||
		key === undefined ||
		!key.active ||
		key.algorithm !== "ed25519" ||
		key.role !== role ||
		!digestsEqual(key.keyAnchorDigest, anchor)
	)
		reject("round authority key is not uniquely active for this role");
	let decoded: Uint8Array;
	try {
		decoded = Buffer.from(signature, "base64");
		if (decoded.length === 0) reject("round authority signature is invalid");
	} catch {
		reject("round authority signature is invalid");
	}
	try {
		if (
			!verify(
				null,
				Buffer.from(canonicalJson(payload)),
				createPublicKey({ key: Buffer.from(key.publicKey, "base64"), format: "der", type: "spki" }),
				decoded,
			)
		)
			reject("round authority signature verification failed");
	} catch (error) {
		if (error instanceof CtfError) throw error;
		reject("round authority signature verification failed");
	}
}

export function createSkillHoldoutGate(
	input: Omit<SkillHoldoutGateV1, "schemaVersion" | "gateDigest">,
	keys: readonly RoundAuthorityKey[],
): SkillHoldoutGateV1 {
	if (input.looksUsed !== 1 || !["passed", "failed", "unavailable"].includes(input.status))
		reject("holdout gate status is invalid");
	const basis = {
		schemaVersion: "ctf-skill-holdout-gate-1" as const,
		roundDigest: requireDigest(input.roundDigest, "gate round digest"),
		selectionDigest: requireDigest(input.selectionDigest, "gate selection digest"),
		selectedCandidateDigest:
			input.selectedCandidateDigest === null
				? null
				: requireDigest(input.selectedCandidateDigest, "gate candidate digest"),
		holdoutCommitmentDigest: requireDigest(input.holdoutCommitmentDigest, "holdout commitment digest"),
		authorizedEvidenceDigests: requireDigestList(input.authorizedEvidenceDigests, "authorized holdout evidence"),
		evaluatorKeyId: input.evaluatorKeyId,
		evaluatorKeyAnchorDigest: requireDigest(input.evaluatorKeyAnchorDigest, "evaluator key anchor"),
		signatureAlgorithm: "ed25519" as const,
		signature: input.signature,
		status: input.status,
		looksUsed: 1 as const,
	};
	if (input.signatureAlgorithm !== "ed25519" || !basis.evaluatorKeyId || !basis.signature)
		reject("holdout gate signer is invalid");
	verifyRoundAuthoritySignature(
		skillHoldoutGateSigningPayload(basis),
		basis.evaluatorKeyId,
		basis.evaluatorKeyAnchorDigest,
		basis.signature,
		"holdout",
		keys,
	);
	return Object.freeze({ ...basis, gateDigest: canonicalDigest(basis) });
}

export function validateSkillHoldoutGate(value: unknown, keys: readonly RoundAuthorityKey[]): SkillHoldoutGateV1 {
	if (value === null || typeof value !== "object") reject("holdout gate is invalid");
	const gate = value as SkillHoldoutGateV1;
	if (gate.schemaVersion !== "ctf-skill-holdout-gate-1") reject("holdout gate schema is invalid");
	rejectUnknownKeys(
		gate,
		[
			"schemaVersion",
			"gateDigest",
			"roundDigest",
			"selectionDigest",
			"selectedCandidateDigest",
			"holdoutCommitmentDigest",
			"authorizedEvidenceDigests",
			"evaluatorKeyId",
			"evaluatorKeyAnchorDigest",
			"signatureAlgorithm",
			"signature",
			"status",
			"looksUsed",
		],
		"holdout gate",
	);
	const rebuilt = createSkillHoldoutGate(
		{
			roundDigest: gate.roundDigest,
			selectionDigest: gate.selectionDigest,
			selectedCandidateDigest: gate.selectedCandidateDigest,
			holdoutCommitmentDigest: gate.holdoutCommitmentDigest,
			authorizedEvidenceDigests: gate.authorizedEvidenceDigests,
			evaluatorKeyId: gate.evaluatorKeyId,
			evaluatorKeyAnchorDigest: gate.evaluatorKeyAnchorDigest,
			signatureAlgorithm: gate.signatureAlgorithm,
			signature: gate.signature,
			status: gate.status,
			looksUsed: gate.looksUsed,
		},
		keys,
	);
	if (!digestsEqual(rebuilt.gateDigest, requireDigest(gate.gateDigest, "gate digest")))
		reject("holdout gate digest mismatch");
	return Object.freeze({ ...rebuilt, gateDigest: gate.gateDigest });
}

export function createFailureContinuation(
	input: Omit<FailureContinuationV1, "schemaVersion" | "continuationDigest" | "scored">,
): FailureContinuationV1 {
	if (
		!["failed", "unknown"].includes(input.category) ||
		!["continue-training", "stop"].includes(input.disposition) ||
		!Number.isSafeInteger(input.budget) ||
		input.budget < 0 ||
		(input.disposition === "continue-training" && input.budget === 0)
	)
		reject("failure continuation is invalid");
	const basis = {
		schemaVersion: "ctf-skill-failure-continuation-1" as const,
		roundDigest: requireDigest(input.roundDigest, "continuation round digest"),
		trainingProblemDigest: requireDigest(input.trainingProblemDigest, "training problem digest"),
		trainingEvidenceDigests: requireDigestList(input.trainingEvidenceDigests, "training evidence"),
		category: input.category,
		budget: input.budget,
		disposition: input.disposition,
		scored: false as const,
	};
	return Object.freeze({ ...basis, continuationDigest: canonicalDigest(basis) });
}

export function validateFailureContinuation(value: unknown): FailureContinuationV1 {
	if (value === null || typeof value !== "object") reject("failure continuation is invalid");
	const continuation = value as FailureContinuationV1;
	if (continuation.schemaVersion !== "ctf-skill-failure-continuation-1" || continuation.scored !== false)
		reject("failure continuation schema is invalid");
	rejectUnknownKeys(
		continuation,
		[
			"schemaVersion",
			"continuationDigest",
			"roundDigest",
			"trainingProblemDigest",
			"trainingEvidenceDigests",
			"category",
			"budget",
			"disposition",
			"scored",
		],
		"failure continuation",
	);
	const rebuilt = createFailureContinuation({
		roundDigest: continuation.roundDigest,
		trainingProblemDigest: continuation.trainingProblemDigest,
		trainingEvidenceDigests: continuation.trainingEvidenceDigests,
		category: continuation.category,
		budget: continuation.budget,
		disposition: continuation.disposition,
	});
	if (!digestsEqual(rebuilt.continuationDigest, requireDigest(continuation.continuationDigest, "continuation digest")))
		reject("failure continuation digest mismatch");
	return Object.freeze({ ...rebuilt, continuationDigest: continuation.continuationDigest });
}
function createSkillOptimizationDecision(
	input: Omit<SkillOptimizationDecisionV1, "schemaVersion" | "decisionDigest">,
): SkillOptimizationDecisionV1 {
	if (
		!["promoted", "rejected", "unavailable"].includes(input.status) ||
		!Number.isSafeInteger(input.cohortCount) ||
		input.cohortCount < 1
	)
		reject("skill optimization decision is invalid");
	const isUnattemptedUnavailable =
		input.status === "unavailable" && input.holdoutLooksUsed === 0 && input.gateDigest === null;
	const isSignedGateDecision = input.holdoutLooksUsed === 1 && input.gateDigest !== null;
	if (!isUnattemptedUnavailable && !isSignedGateDecision) reject("skill optimization decision authority is invalid");
	if (input.status === "promoted" && !isSignedGateDecision) reject("promotion requires a signed holdout gate");
	const basis = {
		schemaVersion: "ctf-skill-optimization-decision-2" as const,
		roundDigest: requireDigest(input.roundDigest, "decision round digest"),
		gateDigest: input.gateDigest === null ? null : requireDigest(input.gateDigest, "decision gate digest"),
		status: input.status,
		cohortCount: input.cohortCount,
		holdoutLooksUsed: input.holdoutLooksUsed,
	};
	return Object.freeze({ ...basis, decisionDigest: canonicalDigest(basis) });
}

export function validateSkillOptimizationDecision(value: unknown): SkillOptimizationDecisionV1 {
	if (value === null || typeof value !== "object") reject("skill optimization decision is invalid");
	const decision = value as SkillOptimizationDecisionV1;
	rejectUnknownKeys(
		decision,
		["schemaVersion", "decisionDigest", "roundDigest", "gateDigest", "status", "cohortCount", "holdoutLooksUsed"],
		"skill optimization decision",
	);
	if (decision.schemaVersion !== "ctf-skill-optimization-decision-2")
		reject("skill optimization decision schema is invalid");
	const rebuilt = createSkillOptimizationDecision({
		roundDigest: decision.roundDigest,
		gateDigest: decision.gateDigest,
		status: decision.status,
		cohortCount: decision.cohortCount,
		holdoutLooksUsed: decision.holdoutLooksUsed,
	});
	if (!digestsEqual(rebuilt.decisionDigest, requireDigest(decision.decisionDigest, "decision digest")))
		reject("decision digest mismatch");
	return Object.freeze({ ...rebuilt, decisionDigest: decision.decisionDigest });
}

export function serializePublicSkillOptimizationArtifact(
	value: FailureContinuationV1 | SkillOptimizationDecisionV1 | SkillRoundAuditReceiptV1,
): string {
	if (value.schemaVersion === "ctf-skill-failure-continuation-1")
		return canonicalJson(validateFailureContinuation(value));
	if (value.schemaVersion === "ctf-skill-optimization-decision-2")
		return canonicalJson(validateSkillOptimizationDecision(value));
	if (value.schemaVersion === "ctf-skill-opt-round-audit-1") {
		rejectUnknownKeys(
			value,
			["schemaVersion", "receiptDigest", "roundDigest", "action", "artifactDigest", "previousReceiptDigest"],
			"round audit receipt",
		);
		const receipt = value as SkillRoundAuditReceiptV1;
		const basis = {
			schemaVersion: receipt.schemaVersion,
			roundDigest: requireDigest(receipt.roundDigest, "round audit digest"),
			action: receipt.action,
			artifactDigest: requireDigest(receipt.artifactDigest, "round audit artifact digest"),
			previousReceiptDigest:
				receipt.previousReceiptDigest === null
					? null
					: requireDigest(receipt.previousReceiptDigest, "previous receipt digest"),
		};
		if (
			!["opened", "selected", "finalized", "continued"].includes(basis.action) ||
			!digestsEqual(canonicalDigest(basis), requireDigest(receipt.receiptDigest, "round audit receipt digest"))
		)
			reject("round audit receipt is invalid");
		return canonicalJson({ ...basis, receiptDigest: receipt.receiptDigest });
	}
	reject("public skill optimization artifact is invalid");
}

export class SkillOptimizationRoundStore {
	readonly #store: RootedStore;
	readonly #promotion: SkillPromotionStore;

	constructor(root: string | RootedStore, promotion: SkillPromotionStore) {
		this.#store = typeof root === "string" ? new RootedStore(root, { durability: "ctf" }) : root;
		if (this.#store.root !== promotion.storageRoot) reject("round and promotion stores must share one root");
		this.#promotion = promotion;
	}

	serializePublicArtifact(
		value: SkillHoldoutGateV1 | FailureContinuationV1 | SkillOptimizationDecisionV1 | SkillRoundAuditReceiptV1,
	): string {
		if (value.schemaVersion !== "ctf-skill-holdout-gate-1") return serializePublicSkillOptimizationArtifact(value);
		return canonicalJson(validateSkillHoldoutGate(value, this.#promotion.roundAuthorityKeys));
	}

	async open(roundInput: SkillOptimizationRoundV1): Promise<SkillOptimizationRoundV1> {
		const round = validateSkillOptimizationRound(roundInput);
		if (round.status !== "open") reject("only open rounds may be created");
		if (
			!digestsEqual(round.authorityRegistryDigest, roundAuthorityRegistryDigest(this.#promotion.roundAuthorityKeys))
		)
			reject("round authority registry mismatch");
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.roundAudit();
			const existing = await readJson<SkillOptimizationRoundV1>(this.#store, ROUND_PATH(round.roundDigest));
			if (existing !== undefined) {
				const prior = validateSkillOptimizationRound(existing);
				await this.#ensureAudit(prior.roundDigest, "opened", prior.roundDigest);
				return prior;
			}
			await this.#store.writeJsonAtomic(ROUND_PATH(round.roundDigest), round, { durability: "ctf" });
			await this.#appendAudit(round.roundDigest, "opened", round.roundDigest);
			return round;
		});
	}

	async select(
		roundDigest: Digest,
		selectedCandidateDigest: Digest | null,
		evidence: readonly Digest[],
		authority: Pick<
			SkillTrainingSelectionV1,
			"evaluatorKeyId" | "evaluatorKeyAnchorDigest" | "signatureAlgorithm" | "signature"
		>,
	): Promise<SkillTrainingSelectionV1> {
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.roundAudit();
			const round = await this.#round(roundDigest);
			const selection = selectSkillTrainingCandidate(
				round,
				selectedCandidateDigest,
				evidence,
				authority,
				this.#promotion.roundAuthorityKeys,
			);
			const path = SELECTION_PATH(round.roundDigest);
			const existing = await readJson<SkillTrainingSelectionV1>(this.#store, path);
			if (existing !== undefined) {
				const prior = validateSkillTrainingSelection(existing, round, this.#promotion.roundAuthorityKeys);
				if (!digestsEqual(prior.selectionDigest, selection.selectionDigest))
					reject("round already has a training selection");
				await this.#ensureAudit(round.roundDigest, "selected", prior.selectionDigest);
				return prior;
			}
			await this.#store.writeJsonAtomic(path, selection, { durability: "ctf" });
			await this.#appendAudit(round.roundDigest, "selected", selection.selectionDigest);
			return selection;
		});
	}

	async finalize(gateInput: SkillHoldoutGateV1): Promise<SkillOptimizationDecisionV1> {
		const claimedRoundDigest = requireDigest(gateInput.roundDigest, "gate round digest");
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.roundAudit();
			await this.#promotion.recover();
			const round = await this.#round(claimedRoundDigest);
			const finalization = await readJson<{ gateDigest: Digest }>(this.#store, FINALIZATION_PATH(round.roundDigest));
			if (round.status !== "open" && finalization === undefined)
				reject("holdout commitment has already been consumed");
			const gate = validateSkillHoldoutGate(gateInput, this.#promotion.roundAuthorityKeys);
			if (
				finalization !== undefined &&
				!digestsEqual(requireDigest(finalization.gateDigest, "finalization gate digest"), gate.gateDigest)
			)
				reject("holdout commitment has already been consumed");
			const existingDecision = await readJson<SkillOptimizationDecisionV1>(
				this.#store,
				DECISION_PATH(round.roundDigest),
			);
			if (existingDecision !== undefined) {
				const decision = validateSkillOptimizationDecision(existingDecision);
				const expectedStatus =
					gate.status === "passed" ? "promoted" : gate.status === "failed" ? "rejected" : "unavailable";
				if (
					decision.gateDigest !== gate.gateDigest ||
					decision.status !== expectedStatus ||
					decision.holdoutLooksUsed !== 1
				)
					reject("holdout commitment has already been consumed");
				if (round.status === "open")
					await this.#store.writeJsonAtomic(
						ROUND_PATH(round.roundDigest),
						Object.freeze({ ...round, status: "closed" as const }),
						{ durability: "ctf" },
					);
				await this.#ensureAudit(round.roundDigest, "finalized", decision.decisionDigest);
				return decision;
			}
			if (round.status !== "open") reject("holdout commitment has already been consumed");
			if (
				!digestsEqual(gate.holdoutCommitmentDigest, round.benchmark.holdoutCommitmentDigest) ||
				!digestsEqual(gate.evaluatorKeyAnchorDigest, round.benchmark.holdoutEvaluatorKeyAnchorDigest)
			)
				reject("holdout commitment or evaluator anchor mismatch");
			const selection = await readJson<SkillTrainingSelectionV1>(this.#store, SELECTION_PATH(round.roundDigest));
			if (selection === undefined) reject("holdout gate selection is missing");
			const validSelection = validateSkillTrainingSelection(selection, round, this.#promotion.roundAuthorityKeys);
			if (
				validSelection.roundDigest !== round.roundDigest ||
				validSelection.selectionDigest !== gate.selectionDigest ||
				validSelection.selectedCandidateDigest !== gate.selectedCandidateDigest
			)
				reject("holdout gate selection mismatch");
			const status = gate.status === "passed" ? "promoted" : gate.status === "failed" ? "rejected" : "unavailable";
			let promotableCandidate: Candidate | undefined;
			let alreadyPromoted = false;
			if (status === "promoted") {
				if (gate.selectedCandidateDigest === null) reject("a passed gate requires a selected candidate");
				const candidate = await readJson<Candidate>(this.#store, CANDIDATE_PATH(gate.selectedCandidateDigest));
				if (candidate === undefined) reject("selected candidate was not recorded");
				const validCandidate = validateSkillCandidate(candidate);
				const active = await this.#promotion.active();
				alreadyPromoted = active?.candidateDigest === validCandidate.candidateDigest;
				const expectedParent = active?.skillDigest ?? this.#promotion.baselineSkillDigest;
				if (
					(!alreadyPromoted && !digestsEqual(validCandidate.parentSkillDigest, expectedParent)) ||
					!digestsEqual(validCandidate.parentSkillDigest, round.incumbentSkillDigest) ||
					!digestsEqual(validCandidate.benchmarkLockDigest, round.benchmark.benchmarkLockDigest) ||
					!digestsEqual(validCandidate.trainingCorpusDigest, round.benchmark.trainingCorpusDigest) ||
					!digestsEqual(validCandidate.holdoutCommitmentDigest, round.benchmark.holdoutCommitmentDigest)
				)
					reject("selected candidate does not match sealed round lineage");
				promotableCandidate = validCandidate;
			}
			await this.#store.writeJsonAtomic(
				FINALIZATION_PATH(round.roundDigest),
				{ gateDigest: gate.gateDigest },
				{ durability: "ctf" },
			);
			await this.#store.writeJsonAtomic(HOLDOUT_GATE_PATH(gate.gateDigest), gate, { durability: "ctf" });
			if (promotableCandidate !== undefined && !alreadyPromoted)
				await this.#promotion.promoteFinalized(promotableCandidate, FINALIZED_PROMOTION_AUTHORITY);
			const decision = createSkillOptimizationDecision({
				roundDigest: round.roundDigest,
				gateDigest: gate.gateDigest,
				status,
				cohortCount: round.committedCohortDigests.length,
				holdoutLooksUsed: 1,
			});
			await this.#store.writeJsonAtomic(HOLDOUT_GATE_PATH(gate.gateDigest), gate, { durability: "ctf" });
			await this.#store.writeJsonAtomic(DECISION_PATH(round.roundDigest), decision, { durability: "ctf" });
			await this.#store.writeJsonAtomic(
				ROUND_PATH(round.roundDigest),
				Object.freeze({ ...round, status: "closed" as const }),
				{ durability: "ctf" },
			);
			await this.#appendAudit(round.roundDigest, "finalized", decision.decisionDigest);
			return decision;
		});
	}

	async finalizeUnavailable(roundDigest: Digest): Promise<SkillOptimizationDecisionV1> {
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.roundAudit();
			const round = await this.#round(roundDigest);
			const existing = await readJson<SkillOptimizationDecisionV1>(this.#store, DECISION_PATH(round.roundDigest));
			if (existing !== undefined) {
				const decision = validateSkillOptimizationDecision(existing);
				if (decision.status !== "unavailable" || decision.holdoutLooksUsed !== 0 || decision.gateDigest !== null)
					reject("holdout commitment has already been consumed");
				if (round.status === "open")
					await this.#store.writeJsonAtomic(
						ROUND_PATH(round.roundDigest),
						Object.freeze({ ...round, status: "closed" as const }),
						{ durability: "ctf" },
					);
				await this.#ensureAudit(round.roundDigest, "finalized", decision.decisionDigest);
				return decision;
			}
			if (round.status !== "open") reject("holdout commitment has already been consumed");
			if (
				this.#promotion.roundAuthorityKeys.some(
					key =>
						key.active &&
						key.role === "holdout" &&
						digestsEqual(key.keyAnchorDigest, round.benchmark.holdoutEvaluatorKeyAnchorDigest),
				)
			)
				reject("holdout authority is available");
			const decision = createSkillOptimizationDecision({
				roundDigest: round.roundDigest,
				gateDigest: null,
				status: "unavailable",
				cohortCount: round.committedCohortDigests.length,
				holdoutLooksUsed: 0,
			});
			await this.#store.writeJsonAtomic(DECISION_PATH(round.roundDigest), decision, { durability: "ctf" });
			await this.#store.writeJsonAtomic(
				ROUND_PATH(round.roundDigest),
				Object.freeze({ ...round, status: "closed" as const }),
				{ durability: "ctf" },
			);
			await this.#appendAudit(round.roundDigest, "finalized", decision.decisionDigest);
			return decision;
		});
	}

	async continueTraining(continuationInput: FailureContinuationV1): Promise<FailureContinuationV1> {
		const continuation = validateFailureContinuation(continuationInput);
		return this.#store.withLock(LOCK_PATH, async () => {
			await this.roundAudit();
			const round = await this.#round(continuation.roundDigest);
			if (round.status !== "closed") reject("failure continuation requires a terminal round");
			const decision = await readJson<SkillOptimizationDecisionV1>(this.#store, DECISION_PATH(round.roundDigest));
			if (decision === undefined || validateSkillOptimizationDecision(decision).status === "promoted")
				reject("failure continuation requires a failed or unavailable gate");
			const state = await this.#continuationState(round);
			const existing = await readJson<FailureContinuationV1>(
				this.#store,
				CONTINUATION_PATH(continuation.continuationDigest),
			);
			if (existing !== undefined) {
				const prior = validateFailureContinuation(existing);
				if (!digestsEqual(prior.continuationDigest, continuation.continuationDigest))
					reject("continuation replay mismatch");
				if (state.appliedDigests.includes(prior.continuationDigest)) {
					await this.#ensureAudit(round.roundDigest, "continued", prior.continuationDigest);
					return prior;
				}
			}
			if (state.stopped || state.used + continuation.budget > round.maximumContinuationBudget)
				reject("continuation budget is exhausted");
			await this.#store.writeJsonAtomic(CONTINUATION_PATH(continuation.continuationDigest), continuation, {
				durability: "ctf",
			});
			await this.#store.writeJsonAtomic(
				CONTINUATION_STATE_PATH(round.roundDigest),
				{
					used: state.used + continuation.budget,
					stopped: continuation.disposition === "stop",
					appliedDigests: [...state.appliedDigests, continuation.continuationDigest],
				},
				{ durability: "ctf" },
			);
			await this.#appendAudit(round.roundDigest, "continued", continuation.continuationDigest);
			return continuation;
		});
	}
	async roundAudit(): Promise<readonly SkillRoundAuditReceiptV1[]> {
		const receipts = await readJsonl<SkillRoundAuditReceiptV1>(this.#store, ROUND_AUDIT_PATH);
		let previous: Digest | null = null;
		for (const receipt of receipts) {
			rejectUnknownKeys(
				receipt,
				["schemaVersion", "receiptDigest", "roundDigest", "action", "artifactDigest", "previousReceiptDigest"],
				"round audit receipt",
			);
			const basis = {
				schemaVersion: receipt.schemaVersion,
				roundDigest: requireDigest(receipt.roundDigest, "round audit digest"),
				action: receipt.action,
				artifactDigest: requireDigest(receipt.artifactDigest, "round audit artifact digest"),
				previousReceiptDigest:
					receipt.previousReceiptDigest === null
						? null
						: requireDigest(receipt.previousReceiptDigest, "previous receipt digest"),
			};
			if (
				receipt.schemaVersion !== "ctf-skill-opt-round-audit-1" ||
				!["opened", "selected", "finalized", "continued"].includes(basis.action) ||
				previous !== basis.previousReceiptDigest ||
				!digestsEqual(canonicalDigest(basis), requireDigest(receipt.receiptDigest, "round audit receipt digest"))
			)
				reject("round audit chain is corrupt");
			previous = receipt.receiptDigest;
		}
		return Object.freeze(receipts);
	}
	async #ensureAudit(
		roundDigest: Digest,
		action: SkillRoundAuditReceiptV1["action"],
		artifactDigest: Digest,
	): Promise<void> {
		const audit = await this.roundAudit();
		if (
			!audit.some(
				receipt =>
					receipt.roundDigest === roundDigest &&
					receipt.action === action &&
					digestsEqual(receipt.artifactDigest, artifactDigest),
			)
		)
			await this.#appendAudit(roundDigest, action, artifactDigest);
	}

	async #continuationState(round: SkillOptimizationRoundV1): Promise<ContinuationState> {
		const value = await readJson<Record<string, unknown>>(this.#store, CONTINUATION_STATE_PATH(round.roundDigest));
		if (value === undefined) return { used: 0, stopped: false, appliedDigests: [] };
		rejectUnknownKeys(value, ["used", "stopped", "appliedDigests"], "continuation state");
		if (
			!Number.isSafeInteger(value.used) ||
			typeof value.used !== "number" ||
			value.used < 0 ||
			value.used > round.maximumContinuationBudget ||
			typeof value.stopped !== "boolean"
		)
			reject("continuation state is invalid");
		const appliedDigests = requireDigestList(value.appliedDigests, "applied continuation digests", true);
		let used = 0;
		let stopped = false;
		for (const digest of appliedDigests) {
			if (stopped) reject("continuation state applies work after stop");
			const stored = await readJson<FailureContinuationV1>(this.#store, CONTINUATION_PATH(digest));
			if (stored === undefined) reject("applied continuation is missing");
			const continuation = validateFailureContinuation(stored);
			if (!digestsEqual(continuation.roundDigest, round.roundDigest)) reject("applied continuation round mismatch");
			used += continuation.budget;
			stopped = continuation.disposition === "stop";
		}
		if (used !== value.used || stopped !== value.stopped) reject("continuation state accounting mismatch");
		return Object.freeze({ used, stopped, appliedDigests });
	}
	async #round(digest: Digest): Promise<SkillOptimizationRoundV1> {
		const round = await readJson<SkillOptimizationRoundV1>(
			this.#store,
			ROUND_PATH(requireDigest(digest, "round digest")),
		);
		if (round === undefined) reject("skill optimization round is missing");
		const validated = validateSkillOptimizationRound(round);
		if (
			!digestsEqual(
				validated.authorityRegistryDigest,
				roundAuthorityRegistryDigest(this.#promotion.roundAuthorityKeys),
			)
		)
			reject("round authority registry mismatch");
		return validated;
	}

	async #appendAudit(
		roundDigest: Digest,
		action: SkillRoundAuditReceiptV1["action"],
		artifactDigest: Digest,
	): Promise<void> {
		const audit = await this.roundAudit();
		const basis = {
			schemaVersion: "ctf-skill-opt-round-audit-1" as const,
			roundDigest,
			action,
			artifactDigest: requireDigest(artifactDigest, "round audit artifact digest"),
			previousReceiptDigest: audit.at(-1)?.receiptDigest ?? null,
		};
		await this.#store.appendJsonl(
			ROUND_AUDIT_PATH,
			{ ...basis, receiptDigest: canonicalDigest(basis) },
			{ durability: "ctf" },
		);
	}
}
