import {
	assertBenchmarkLockMatchesManifest,
	benchmarkBudgetDigest,
	benchmarkCorpusDigest,
	benchmarkEligibilityDigest,
	benchmarkHoldoutDigest,
	benchmarkLockDigest,
	benchmarkManifestDigest,
	BenchmarkImplementationIdentitySchema,
	SkillLockIdentitySchema,
	validateBenchmarkLock,
	validateBenchmarkManifest,
	type BenchmarkImplementationIdentity,
	type BenchmarkLockV1,
	type BenchmarkManifestV1,
} from "../../packages/coding-agent/src/ctf/contracts/benchmark";
import { validateEffectiveSkill } from "../../packages/coding-agent/src/ctf/contracts/skill";
import { canonicalDigest, digestsEqual, isDigest, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import {
	validateOperationalLimits,
	validateSafetyMaxima,
	type OperationalLimitsV1,
	type SafetyMaximaV1,
} from "../../packages/coding-agent/src/ctf/contracts/sandbox";
import { oracleEntryDigest, oracleRegistryDigest, type OracleTrustAnchorsV1 } from "../../packages/coding-agent/src/ctf/contracts/oracle";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import {
	validateAnchoredOracleRegistry,
	validateTrustedOracleRegistry,
	type TrustedOracleRegistry,
} from "../../packages/coding-agent/src/ctf/runtime/oracle";
import {
	validateBenchmarkCalibration,
	type BenchmarkCalibrationPolicy,
} from "../../packages/coding-agent/src/ctf/runtime/policy";
import {
	validateOracleTransitionProof,
	type OracleTransitionProof,
} from "../../packages/coding-agent/src/ctf/contracts/event";
import { verifyOracleTransitionProofSignature } from "../../packages/coding-agent/src/ctf/graph/ontology";

export {
	type LactfCorpusSource,
	LACTF_2026_CORPUS_SOURCE,
	LACTF_2026_CORPUS_SOURCES,
} from "../../packages/coding-agent/src/ctf/corpus";

export type BenchmarkCalibrationRef = Readonly<{
	schemaVersion?: "ctf-benchmark-calibration-1";
	calibrationId: string;
	operationalLimitsDigest: Digest;
	selectedFor?: "fixture" | "benchmark";
	eligibleDenominator?: number;
	thresholds?: Readonly<Record<string, number>>;
	targetPassCount?: number;
	floorPassCount?: number;
	calibrationDigest?: Digest;
}>;

export type BenchmarkOracleRef = Readonly<{
	/**
	 * Every scored objective requires a signed trusted registry; digest-only
	 * authority cannot establish a validated benchmark solve.
	 */
	registryDigest?: Digest;
	trustedRegistry?: TrustedOracleRegistry;
	/** Runtime naming used by existing callers. */
	oracleRegistry?: TrustedOracleRegistry;
	/** Fixture-authority naming used by existing callers. */
	registry?: TrustedOracleRegistry;
	/** Selected registry entry, when this benchmark binds an oracle. */
	oracleId?: string;
	oracleDigest?: Digest;
}>;
export type BenchmarkOracleProofContext = Readonly<{
	eventType: "node" | "edge";
	challengeId: string;
	before?: unknown;
	after: unknown;
}>;
export type BenchmarkEvaluatorCapability = Readonly<{
	/** Operator-owned roots supplied outside the benchmark evidence request. */
	oracleTrustAnchors: OracleTrustAnchorsV1;
	/** Externally reviewed implementation identities allowed for scored publication. */
	reviewedImplementationIdentities?: readonly BenchmarkImplementationIdentity[];
}>;

export type BenchmarkPreflightRequest = Readonly<{
	manifest: unknown;
	lock: unknown;
	calibration: BenchmarkCalibrationRef;
	oracle: BenchmarkOracleRef;
	safetyPolicyDigest: Digest;
	/** Stable implementation identity; external evaluator review is required for scoring. */
	implementationIdentity?: unknown;
	/** Explicit count of non-holdout corpus entries; never inferred by scoring. */
	eligibleDenominator?: number;
	/** Numeric acceptance thresholds bound to the calibration digest. */
	thresholds?: Readonly<Record<string, number>>;
	targetPassCount?: number;
	floorPassCount?: number;
	/** Signed preflight/runtime attestations; required for scored preflight. */
	preflightReportDigest?: Digest;
	runtimeEvidenceDigest?: Digest;
	evidenceRefs?: readonly Digest[];
	preflightProof?: unknown;
	oracleProof?: unknown;
	runtimeProof?: unknown;
	effectiveSkill?: unknown;
	skill?: unknown;
	operationalLimits?: unknown;
	limits?: unknown;
	safetyMaxima?: unknown;
	safety?: unknown;
	/** Signed transition context used to verify benchmark evidence signatures. */
	oracleProofContext?: BenchmarkOracleProofContext;
}>;

export type BenchmarkPreflight = Readonly<{
	manifest: BenchmarkManifestV1;
	lock: BenchmarkLockV1;
	manifestDigest: Digest;
	lockDigest: Digest;
	calibration: BenchmarkCalibrationPolicy;
	eligibleDenominator: number;
	thresholds: Readonly<Record<string, number>>;
	calibrationDigest: Digest;
	targetPassCount: number;
	floorPassCount: number;
}>;

function reject(code: "benchmark_provenance_missing" | "benchmark_lock_mismatch" | "uncalibrated_limits" | "oracle_integrity_error", message: string): never {
	throw new CtfError(code, message);
}
export function validateReviewedImplementationIdentity(
	value: unknown,
	evaluatorCapability: BenchmarkEvaluatorCapability | undefined,
): BenchmarkImplementationIdentity {
	const identity = BenchmarkImplementationIdentitySchema.safeParse(value);
	if (!identity.success) {
		reject("benchmark_provenance_missing", "scored benchmark requires a valid implementation identity");
	}
	const reviewed = evaluatorCapability?.reviewedImplementationIdentities;
	if (!Array.isArray(reviewed)) {
		reject("benchmark_provenance_missing", "scored benchmark requires externally reviewed implementation identity authority");
	}
	for (const candidate of reviewed) {
		const parsed = BenchmarkImplementationIdentitySchema.safeParse(candidate);
		if (!parsed.success) {
			reject("benchmark_provenance_missing", "external implementation identity authority is invalid");
		}
		if (canonicalDigest(parsed.data) === canonicalDigest(identity.data)) return identity.data;
	}
	reject("benchmark_provenance_missing", "implementation identity is not externally reviewed");
}

function freeze<T>(value: T): T {
	if (value && typeof value === "object") {
		for (const child of Object.values(value as Record<string, unknown>)) {
			if (child && typeof child === "object" && !Object.isFrozen(child)) freeze(child);
		}
		Object.freeze(value);
	}
	return value;
}
function eligibleChallengeIds(manifest: BenchmarkManifestV1): readonly string[] {
	const corpusIds = new Set(manifest.corpus.map(entry => entry.challengeId));
	for (const holdoutId of manifest.holdoutChallengeIds) {
		if (!corpusIds.has(holdoutId)) reject("benchmark_provenance_missing", `holdout challenge is absent from benchmark corpus: ${holdoutId}`);
	}
	if (new Set(manifest.holdoutChallengeIds).size !== manifest.holdoutChallengeIds.length) {
		reject("benchmark_provenance_missing", "benchmark holdout challenge IDs must be unique");
	}
	if (manifest.objective === "benchmark-fixed-budget") {
		const nonLocalEntry = manifest.corpus.find(
			entry => entry.executionClass !== "fixture/static" && entry.executionClass !== "verified-local/rootless-podman-network-off",
		);
		if (nonLocalEntry !== undefined) {
			reject(
				"benchmark_provenance_missing",
				`benchmark-fixed-budget corpus contains a non-local execution class for ${nonLocalEntry.challengeId}: ${nonLocalEntry.executionClass}`,
			);
		}
	}
	const eligible = manifest.corpus.filter(entry => !manifest.holdoutChallengeIds.includes(entry.challengeId));
	const unsupported = eligible.find(entry => entry.executionClass !== "verified-local/rootless-podman-network-off");
	if (unsupported !== undefined) {
		reject(
			"benchmark_provenance_missing",
			`benchmark scoring requires real eligible execution provenance for ${unsupported.challengeId}; ${unsupported.executionClass} is non-scored`,
		);
	}
	return eligible.map(entry => entry.challengeId);
}

/** Return real, scored challenge IDs in manifest corpus order; fixture/static and deferred entries are non-scored. */
export function benchmarkEligibleChallengeIds(manifest: BenchmarkManifestV1): readonly string[] {
	return eligibleChallengeIds(manifest);
}

/** Return the lock-defined eligible denominator; an empty denominator is not scoreable. */
export function benchmarkEligibleDenominator(manifest: BenchmarkManifestV1): number {
	const count = eligibleChallengeIds(manifest).length;
	if (!Number.isSafeInteger(count) || count <= 0) reject("benchmark_provenance_missing", "benchmark has no eligible challenges");
	return count;
}

/** Validate an explicitly supplied denominator against the locked corpus. */
export function validateBenchmarkEligibleDenominator(manifest: BenchmarkManifestV1, value: unknown): number {
	const expected = benchmarkEligibleDenominator(manifest);
	const denominator = typeof value === "number" ? value : Number.NaN;
	if (!Number.isSafeInteger(denominator) || denominator <= 0 || denominator !== expected) {
		reject("benchmark_provenance_missing", "eligible challenge denominator is missing or does not match the locked corpus");
	}
	return denominator;
}
function benchmarkTargetFloor(
	calibration: BenchmarkCalibrationPolicy,
	denominator: number,
	suppliedTarget?: unknown,
	suppliedFloor?: unknown,
): { targetPassCount: number; floorPassCount: number } {
	const target = calibration.thresholds.targetPassCount;
	const floor = calibration.thresholds.floorPassCount;
	if (
		!Number.isSafeInteger(target) ||
		!Number.isSafeInteger(floor) ||
		target < 0 ||
		floor < 0 ||
		target > denominator ||
		floor > denominator ||
		floor > target
	) {
		reject("uncalibrated_limits", "benchmark calibration must bind valid targetPassCount and floorPassCount");
	}
	if (
		(suppliedTarget !== undefined && suppliedTarget !== target) ||
		(suppliedFloor !== undefined && suppliedFloor !== floor)
	) {
		reject("uncalibrated_limits", "benchmark target/floor values are not bound to calibration");
	}
	return { targetPassCount: target, floorPassCount: floor };
}

export function verifyBenchmarkOracleTransitionProof(
	proof: OracleTransitionProof,
	contextValue: unknown,
	evidenceRefs: readonly Digest[],
	manifest: BenchmarkManifestV1,
	oracle: TrustedOracleRegistry,
): void {
	try {
		oracle = validateTrustedOracleRegistry(oracle);
	} catch {
		reject("oracle_integrity_error", "signed benchmark evidence trusted registry is invalid");
	}
	if (!contextValue || typeof contextValue !== "object" || Array.isArray(contextValue)) {
		reject("oracle_integrity_error", "signed benchmark evidence transition context is missing");
	}
	const context = contextValue as Record<string, unknown>;
	if (
		(context.eventType !== "node" && context.eventType !== "edge") ||
		typeof context.challengeId !== "string" ||
		context.challengeId.length === 0 ||
		!("after" in context)
	) {
		reject("oracle_integrity_error", "signed benchmark evidence transition context is invalid");
	}
	const corpusEntry = manifest.corpus.find(
		entry => entry.challengeId === context.challengeId && !manifest.holdoutChallengeIds.includes(entry.challengeId),
	);
	if (corpusEntry === undefined) {
		reject("oracle_integrity_error", "signed benchmark evidence transition context is not an eligible challenge");
	}
	const trustedEntry = oracle.registry.entries.find(entry => entry.oracleId === corpusEntry.oracleId);
	if (trustedEntry === undefined) {
		reject("oracle_integrity_error", "signed benchmark evidence oracle entry is not registered");
	}
	const trustedEntryDigest = oracleEntryDigest(trustedEntry);
	if (
		!digestsEqual(corpusEntry.oracleDigest, trustedEntryDigest) ||
		!digestsEqual(proof.oracleEntryDigest, trustedEntryDigest) ||
		!digestsEqual(proof.registryDigest, oracle.registry.registryDigest)
	) {
		reject("oracle_integrity_error", "signed benchmark evidence oracle entry is detached from the trusted registry");
	}
	const expectedSignerKeyId = proof.authority === "preflight" ? trustedEntry.signerKeyId : trustedEntry.publicKeyId;
	if (proof.signerKeyId !== expectedSignerKeyId) {
		reject("oracle_integrity_error", "signed benchmark evidence signer is not authorized for its authority");
	}
	const key = oracle.keys.find(candidate => candidate.keyId === expectedSignerKeyId);
	if (key === undefined || !key.active || key.algorithm !== "ed25519") {
		reject("oracle_integrity_error", "signed benchmark evidence signer key is not active Ed25519");
	}
	try {
		verifyOracleTransitionProofSignature({
			eventType: context.eventType === "node" ? "node_transition" : "edge_transition",
			before: context.before,
			after: context.after,
			challengeId: context.challengeId,
			evidenceRefs,
			proof,
			resolver: {
				resolveKey(input) {
					if (
						input.signerKeyId !== expectedSignerKeyId ||
						input.challengeId !== context.challengeId ||
						!digestsEqual(input.registryDigest, oracle.registry.registryDigest) ||
						!digestsEqual(input.oracleEntryDigest, trustedEntryDigest)
					) {
						return undefined;
					}
					return key;
				},
			},
		});
	} catch {
		reject("oracle_integrity_error", "signed benchmark evidence signature is invalid");
	}
}

function validateSignedBenchmarkEvidence(
	request: BenchmarkPreflightRequest,
	manifest: BenchmarkManifestV1,
	lock: BenchmarkLockV1,
	oracle: TrustedOracleRegistry,
): void {
	if (!isDigest(request.preflightReportDigest) || !isDigest(request.runtimeEvidenceDigest)) {
		reject("benchmark_provenance_missing", "scored benchmark preflight requires signed preflight and runtime evidence digests");
	}
	const refs = request.evidenceRefs;
	if (
		!Array.isArray(refs) ||
		refs.length < 2 ||
		!refs.every(isDigest) ||
		!refs.includes(request.preflightReportDigest) ||
		!refs.includes(request.runtimeEvidenceDigest)
	) {
		reject("benchmark_provenance_missing", "signed benchmark evidence references are incomplete");
	}
	let preflight: OracleTransitionProof;
	let runtime: OracleTransitionProof;
	try {
		preflight = validateOracleTransitionProof(
			request.preflightProof ??
			(request.oracleProof && typeof request.oracleProof === "object" && !Array.isArray(request.oracleProof) &&
			(request.oracleProof as { authority?: unknown }).authority === "preflight"
				? request.oracleProof
				: undefined),
		);
		runtime = validateOracleTransitionProof(
			request.runtimeProof ??
			(request.oracleProof && typeof request.oracleProof === "object" && !Array.isArray(request.oracleProof) &&
			(request.oracleProof as { authority?: unknown }).authority === "oracle"
				? request.oracleProof
				: undefined),
		);
	} catch {
		reject("oracle_integrity_error", "signed benchmark preflight/runtime evidence is invalid");
	}
	if (
		preflight.authority !== "preflight" ||
		preflight.preflightReportDigest !== request.preflightReportDigest ||
		runtime.authority !== "oracle" ||
		runtime.oracleResultDigest !== request.runtimeEvidenceDigest ||
		preflight.registryDigest !== manifest.oracleRegistryDigest ||
		runtime.registryDigest !== manifest.oracleRegistryDigest
	) {
		reject("oracle_integrity_error", "signed benchmark evidence is detached from the benchmark lock");
	}
	const evidenceDigest = canonicalDigest(refs);
	if (preflight.evidenceDigest !== evidenceDigest || runtime.evidenceDigest !== evidenceDigest) {
		reject("oracle_integrity_error", "signed benchmark evidence references are not canonical");
	}
	const keyIds = new Set(oracle.keys.map(key => key.keyId));
	if (!keyIds.has(preflight.signerKeyId) || !keyIds.has(runtime.signerKeyId)) {
		reject("oracle_integrity_error", "signed benchmark evidence uses an untrusted signer");
	}
	if (request.oracleProofContext === undefined) {
		reject("oracle_integrity_error", "scored benchmark evidence requires an explicit transition context");
	}
	try {
		verifyBenchmarkOracleTransitionProof(preflight, request.oracleProofContext, refs, manifest, oracle);
		verifyBenchmarkOracleTransitionProof(runtime, request.oracleProofContext, refs, manifest, oracle);
	} catch (error) {
		if (error instanceof CtfError) throw error;
		reject("oracle_integrity_error", "signed benchmark evidence signature is invalid");
	}
	if (lock.oracleRegistryDigest !== manifest.oracleRegistryDigest) {
		reject("benchmark_lock_mismatch", "signed benchmark evidence registry is detached from the lock");
	}
}

/** Build the content-addressed lock from a validated manifest. */
export function createBenchmarkLock(value: unknown): BenchmarkLockV1 {
	const manifest = validateBenchmarkManifest(value);
	const unsigned: Omit<BenchmarkLockV1, "lockDigest"> = {
		schemaVersion: "ctf-benchmark-lock-1",
		benchmarkId: manifest.benchmarkId,
		benchmarkManifestDigest: manifest.manifestDigest,
		corpusDigest: benchmarkCorpusDigest(manifest),
		eligibilityDigest: benchmarkEligibilityDigest(manifest),
		holdoutDigest: benchmarkHoldoutDigest(manifest),
		objective: manifest.objective,
		budgetDigest: benchmarkBudgetDigest(manifest),
		sourceCommit: manifest.sourceCommit,
		modelPolicyId: manifest.modelPolicyId,
		modelConfigDigest: manifest.modelConfigDigest,
		skill: manifest.skill,
		backendPolicyDigest: manifest.backendPolicyDigest,
		oracleRegistryDigest: manifest.oracleRegistryDigest,
		safetyPolicyDigest: manifest.safetyPolicyDigest,
		calibrationId: manifest.calibrationId,
		operationalLimitsDigest: manifest.operationalLimitsDigest,
		repeatCount: manifest.repeatCount,
		...(manifest.seedSchedule === undefined ? {} : { seedSchedule: manifest.seedSchedule }),
		...(manifest.seeds === undefined ? {} : { seeds: [...manifest.seeds] as [string, string, string, string, string] }),
	};
	return freeze({ ...unsigned, lockDigest: benchmarkLockDigest(unsigned) });
}

/** Canonical equality includes every locked field, never object identity. */
export function benchmarkManifestEquals(left: unknown, right: unknown): boolean {
	try {
		const a = validateBenchmarkManifest(left);
		const b = validateBenchmarkManifest(right);
		return digestsEqual(benchmarkManifestDigest(a), benchmarkManifestDigest(b));
	} catch {
		return false;
	}
}

export function benchmarkLockEquals(left: unknown, right: unknown): boolean {
	try {
		const a = validateBenchmarkLock(left);
		const b = validateBenchmarkLock(right);
		return digestsEqual(benchmarkLockDigest(a), benchmarkLockDigest(b));
	} catch {
		return false;
	}
}

/** A lock cannot be amended in place or replaced by a lock with a new digest. */
export function assertBenchmarkLockImmutable(before: unknown, after: unknown): void {
	const previous = validateBenchmarkLock(before);
	const next = validateBenchmarkLock(after);
	if (!benchmarkLockEquals(previous, next) || !digestsEqual(previous.lockDigest, next.lockDigest)) {
		reject("benchmark_lock_mismatch", "benchmark lock is immutable and content-addressed");
	}
}

/**
 * Validate the oracle authority against the immutable benchmark identity.
 *
 * A signed trusted registry is required for every scored objective; digest-only
 * authority cannot establish a validated benchmark solve. No registry or entry
 * is inferred from the manifest.
 */
function validateBenchmarkOracle(
	manifest: BenchmarkManifestV1,
	lock: BenchmarkLockV1,
	oracle: BenchmarkOracleRef | undefined,
): void {
	const fixedBudget = manifest.objective === "benchmark-fixed-budget";
	if (!oracle || typeof oracle !== "object") reject("oracle_integrity_error", "trusted oracle registry provenance is missing");
	const registryInput =
		oracle.trustedRegistry !== undefined
			? oracle.trustedRegistry
			: oracle.oracleRegistry !== undefined
				? oracle.oracleRegistry
				: oracle.registry;
	const hasSelection = oracle.oracleId !== undefined || oracle.oracleDigest !== undefined;

	if (registryInput === undefined) {
		reject("oracle_integrity_error", "a scored benchmark requires a trusted oracle registry");
	}

	const trusted = validateTrustedOracleRegistry(registryInput);
	const validatedRegistryDigest = oracleRegistryDigest(trusted.registry);
	if (oracle.registryDigest !== undefined && (!isDigest(oracle.registryDigest) || !digestsEqual(oracle.registryDigest, validatedRegistryDigest))) {
		reject("oracle_integrity_error", "trusted oracle registry digest does not match the supplied authority");
	}
	if (!digestsEqual(validatedRegistryDigest, manifest.oracleRegistryDigest) || !digestsEqual(validatedRegistryDigest, lock.oracleRegistryDigest)) {
		reject("oracle_integrity_error", "validated trusted oracle registry does not match the manifest and lock");
	}
	const holdoutIds = new Set(manifest.holdoutChallengeIds);
	eligibleChallengeIds(manifest);
	for (const corpusEntry of manifest.corpus) {
		if (holdoutIds.has(corpusEntry.challengeId)) continue;
		const trustedEntry = trusted.registry.entries.find(candidate => candidate.oracleId === corpusEntry.oracleId);
		if (trustedEntry === undefined) {
			reject("oracle_integrity_error", `eligible challenge oracle is not registered: ${corpusEntry.oracleId}`);
		}
		if (!digestsEqual(corpusEntry.oracleDigest, oracleEntryDigest(trustedEntry))) {
			reject("oracle_integrity_error", `eligible challenge oracle digest does not match the trusted registry: ${corpusEntry.challengeId}`);
		}
		if (!trustedEntry.allowedChallengeIds.includes(corpusEntry.challengeId)) {
			reject("oracle_integrity_error", `trusted oracle is not authorized for eligible challenge: ${corpusEntry.challengeId}`);
		}
	}
	if (!hasSelection) {
		if (fixedBudget) reject("oracle_integrity_error", "benchmark-fixed-budget requires a selected oracle entry");
		return;
	}
	if (typeof oracle.oracleId !== "string" || oracle.oracleId.length === 0 || !isDigest(oracle.oracleDigest)) {
		reject("oracle_integrity_error", "selected oracle ID and digest are required");
	}
	const entry = trusted.registry.entries.find(candidate => candidate.oracleId === oracle.oracleId);
	if (entry === undefined) reject("oracle_integrity_error", `selected oracle is not registered: ${oracle.oracleId}`);
	const validatedEntryDigest = oracleEntryDigest(entry);
	if (!digestsEqual(validatedEntryDigest, oracle.oracleDigest)) {
		reject("oracle_integrity_error", "selected oracle digest does not match the trusted registry entry");
	}
	const manifestEntries = manifest.corpus.filter(candidate => candidate.oracleId === oracle.oracleId && (!fixedBudget || !manifest.holdoutChallengeIds.includes(candidate.challengeId)));
	if (manifestEntries.length === 0 || manifestEntries.some(candidate => !digestsEqual(candidate.oracleDigest, validatedEntryDigest))) {
		reject("oracle_integrity_error", "selected oracle digest does not match the benchmark manifest");
	}
	if (manifestEntries.some(candidate => !entry.allowedChallengeIds.includes(candidate.challengeId))) {
		reject("oracle_integrity_error", "selected oracle is not authorized for a benchmark challenge");
	}
	// The lock's corpus digest is checked against the manifest above; retaining
	// this explicit check documents that selection is bound to the locked corpus.
	if (!digestsEqual(lock.corpusDigest, benchmarkCorpusDigest(manifest))) {
		reject("benchmark_lock_mismatch", "selected oracle is not bound to the benchmark lock");
	}
}
function validateBenchmarkConcreteLineage(
	request: BenchmarkPreflightRequest,
	manifest: BenchmarkManifestV1,
): { skillDigest: Digest; limits: OperationalLimitsV1; safety: SafetyMaximaV1 } {
	const rawSkill = request.effectiveSkill ?? request.skill;
	if (rawSkill === undefined) reject("benchmark_provenance_missing", "benchmark preflight requires a concrete effective skill identity");
	const parsedLockSkill = SkillLockIdentitySchema.safeParse(rawSkill);
	let skillDigest: Digest;
	if (parsedLockSkill.success) {
		skillDigest = canonicalDigest(parsedLockSkill.data);
	} else {
		try {
			const effective = validateEffectiveSkill(rawSkill);
			skillDigest = canonicalDigest({
				effectiveId: effective.id,
				effectiveVersion: effective.version,
				contentDigest: effective.contentDigest,
				loaderDigest: effective.loaderDigest,
				buildDigest: effective.buildDigest,
				workspaceOverrideDigest: effective.workspaceOverrideDigest,
			});
		} catch {
			reject("benchmark_provenance_missing", "benchmark effective skill identity is invalid");
		}
	}
	if (!digestsEqual(skillDigest, canonicalDigest(manifest.skill))) {
		reject("benchmark_lock_mismatch", "benchmark effective skill identity does not match the manifest");
	}
	const rawSafety = request.safetyMaxima ?? request.safety;
	const rawLimits = request.operationalLimits ?? request.limits;
	if (rawSafety === undefined || rawLimits === undefined) {
		reject("uncalibrated_limits", "benchmark preflight requires concrete safety maxima and operational limits");
	}
	const safety = validateSafetyMaxima(rawSafety);
	const limits = validateOperationalLimits(rawLimits, safety);
	if (limits.selectedFor !== "benchmark" || limits.calibrationId !== manifest.calibrationId) {
		reject("uncalibrated_limits", "benchmark operational limits are not benchmark-calibrated");
	}
	if (!digestsEqual(limits.limitsDigest, manifest.operationalLimitsDigest) || !digestsEqual(safety.policyDigest, manifest.safetyPolicyDigest)) {
		reject("uncalibrated_limits", "benchmark concrete limits or safety maxima do not match the manifest");
	}
	return { skillDigest, limits, safety };
}

/**
 * Preflight all external attestations needed to score a benchmark.  Missing
 * calibration, oracle, or safety provenance is a typed rejection; no local
 * default is substituted.
 */
export function preflightBenchmark(
	request: BenchmarkPreflightRequest,
	evaluatorCapability?: BenchmarkEvaluatorCapability,
): BenchmarkPreflight {
	if (!request || typeof request !== "object") reject("benchmark_provenance_missing", "benchmark preflight request is missing");
	const manifest = validateBenchmarkManifest(request.manifest);
	const lock = validateBenchmarkLock(request.lock);
	assertBenchmarkLockMatchesManifest(lock, manifest);
	if (manifest.seedSchedule === undefined || lock.seedSchedule === undefined) {
		reject("benchmark_lock_mismatch", "scored benchmark preflight requires a canonical challenge seed schedule");
	}
	const calibrationInput = {
		schemaVersion: request.calibration?.schemaVersion,
		calibrationId: request.calibration?.calibrationId,
		operationalLimitsDigest: request.calibration?.operationalLimitsDigest,
		selectedFor: request.calibration?.selectedFor,
		eligibleDenominator: request.calibration?.eligibleDenominator ?? request.eligibleDenominator,
		thresholds: request.calibration?.thresholds ?? request.thresholds,
		calibrationDigest: request.calibration?.calibrationDigest,
	};
	const calibration = validateBenchmarkCalibration(calibrationInput, { requireBenchmark: true });
	if (calibration.calibrationId !== manifest.calibrationId || !digestsEqual(calibration.operationalLimitsDigest, manifest.operationalLimitsDigest)) {
		reject("uncalibrated_limits", "benchmark calibration does not match the manifest");
	}
	validateBenchmarkConcreteLineage(request, manifest);
	validateReviewedImplementationIdentity(request.implementationIdentity, evaluatorCapability);
	const denominator = validateBenchmarkEligibleDenominator(manifest, calibration.eligibleDenominator);
	const targetFloor = benchmarkTargetFloor(
		calibration,
		denominator,
		request.targetPassCount ?? calibrationInput.thresholds?.targetPassCount,
		request.floorPassCount ?? calibrationInput.thresholds?.floorPassCount,
	);
	if (!calibrationInput.calibrationDigest || !calibrationInput.thresholds) {
		reject("uncalibrated_limits", "benchmark calibration must carry explicit digest-bound denominator and thresholds");
	}
	validateBenchmarkOracle(manifest, lock, request.oracle);
	let trustedOracle: TrustedOracleRegistry;
	try {
		const trustAnchors = evaluatorCapability?.oracleTrustAnchors;
		trustedOracle = validateAnchoredOracleRegistry(
			request.oracle.trustedRegistry ?? request.oracle.oracleRegistry ?? request.oracle.registry,
			trustAnchors,
		);
	} catch {
		reject("oracle_integrity_error", "scored benchmark preflight requires externally anchored oracle authority");
	}
	validateSignedBenchmarkEvidence(request, manifest, lock, trustedOracle);
	if (!isDigest(request.safetyPolicyDigest) || !digestsEqual(request.safetyPolicyDigest, manifest.safetyPolicyDigest)) {
		reject("benchmark_provenance_missing", "benchmark safety policy provenance does not match the manifest");
	}
	return freeze({
		manifest,
		lock,
		manifestDigest: manifest.manifestDigest as Digest,
		lockDigest: lock.lockDigest as Digest,
		calibration,
		eligibleDenominator: denominator,
		thresholds: calibration.thresholds,
		calibrationDigest: calibration.calibrationDigest,
		...targetFloor,
	});
}

export function benchmarkLockFingerprint(lock: BenchmarkLockV1): Digest {
	const validated = validateBenchmarkLock(lock);
	return canonicalDigest({ lockDigest: validated.lockDigest, benchmarkId: validated.benchmarkId });
}

export const validateBenchmarkPreflight = preflightBenchmark;
export const assertLockImmutable = assertBenchmarkLockImmutable;
export const preflightBenchmarkManifest = preflightBenchmark;
export const validateBenchmarkLockPreflight = preflightBenchmark;
