import {
	assertBenchmarkLockMatchesManifest,
	benchmarkCorpusDigest,
	validateBenchmarkLock,
	validateBenchmarkManifest,
} from "../../packages/coding-agent/src/ctf/contracts/benchmark";
import { canonicalDigest, digestsEqual, isDigest, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import { type OracleTrustAnchorsV1, validateOracleTrustAnchors } from "../../packages/coding-agent/src/ctf/contracts/oracle";
import { createCtfStateStore, type CtfStateStore, type CtfStateStoreLike } from "../../packages/coding-agent/src/ctf/state/storage";
import { validateAnchoredOracleRegistry } from "../../packages/coding-agent/src/ctf/runtime/oracle";
import { validateBenchmarkCalibration } from "../../packages/coding-agent/src/ctf/runtime/policy";
import { evaluateBenchmarkReport } from "./metrics";

export const LACTF_BENCHMARK_TIERS = Object.freeze([
	Object.freeze([
		"lactf-2026-misc-endians",
		"lactf-2026-rev-ooo",
		"lactf-2026-rev-flag-finder",
	] as const),
	Object.freeze([
		"lactf-2026-crypto-not-so-lazy-trigrams",
		"lactf-2026-pwn-tic-tac-no",
		"lactf-2026-web-single-trust",
	] as const),
] as const);

export type LactfTierChallengeId = (typeof LACTF_BENCHMARK_TIERS)[number][number];
export type LactfTierNumber = 1 | 2;

export const LACTF_TIER_CONTROLLER_PATH = "benchmarks/gjc-ctf/tier-controller.json" as const;
export const LACTF_TIER_CONTROLLER_IDENTITY: Digest = canonicalDigest(LACTF_BENCHMARK_TIERS);
export type LactfTierAuthority = Readonly<{
	manifest: unknown;
	lock: unknown;
	calibration: unknown;
	oracle: unknown;
	oracleTrustAnchors: unknown;
}>;
export type LactfTierAuthoritySet = Readonly<{
	tier1: LactfTierAuthority;
	tier2: LactfTierAuthority;
}>;
type LactfTierAuthorityIdentity = Readonly<{
	manifestDigest: Digest;
	lockDigest: Digest;
	corpusDigest: Digest;
	calibrationDigest: Digest;
	oracleRegistryDigest: Digest;
	oracleAuthorityDigest: Digest;
	oracleRegistrySignerFingerprint: Digest;
	oracleResultSignerFingerprint: Digest;
}>;
type LactfTierAuthoritySetIdentity = Readonly<Partial<Record<LactfTierNumber, LactfTierAuthorityIdentity>>>;

export type VerifiedSolveStatus = Readonly<Record<LactfTierChallengeId, boolean>>;
export type SignedReportSummary = Readonly<{
	reportDigest: Digest;
	reportFingerprint: Digest;
	authorityDigest: Digest;
	authoritySetDigest: Digest;
	tier: LactfTierNumber;
	eligibleChallengeIds: readonly LactfTierChallengeId[];
	verifiedSolveIds: readonly LactfTierChallengeId[];
}>;
export type TierExpansion = Readonly<{
	fromTier: 1;
	toTier: 2;
	reportDigest: Digest;
	iteration: number;
}>;
export type LactfTierState = Readonly<{
	schemaVersion: "gjc-lactf-tier-state-3";
	identity: Digest;
	authoritySet: LactfTierAuthoritySetIdentity;
	authoritySetDigest: Digest;
	activeTier: LactfTierNumber;
	iteration: number;
	terminal: boolean;
	verifiedSolves: VerifiedSolveStatus;
	signedReportHistory: readonly SignedReportSummary[];
	expansionHistory: readonly TierExpansion[];
	stateDigest: Digest;
}>;

const ALL_IDS = Object.freeze(LACTF_BENCHMARK_TIERS.flat()) as readonly LactfTierChallengeId[];

function freeze<T>(value: T): T {
	if (value && typeof value === "object" && !Object.isFrozen(value)) {
		for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
		Object.freeze(value);
	}
	return value;
}

function initialStatuses(): VerifiedSolveStatus {
	return {
		"lactf-2026-misc-endians": false,
		"lactf-2026-rev-ooo": false,
		"lactf-2026-rev-flag-finder": false,
		"lactf-2026-crypto-not-so-lazy-trigrams": false,
		"lactf-2026-pwn-tic-tac-no": false,
		"lactf-2026-web-single-trust": false,
	};
}

function stateDigest(state: Omit<LactfTierState, "stateDigest">): Digest {
	return canonicalDigest(state);
}

function authoritySetDigest(authoritySet: LactfTierAuthoritySetIdentity): Digest {
	return canonicalDigest(authoritySet);
}

function initialState(authoritySet: LactfTierAuthoritySetIdentity = {}): LactfTierState {
	const base: Omit<LactfTierState, "stateDigest"> = {
		schemaVersion: "gjc-lactf-tier-state-3",
		identity: LACTF_TIER_CONTROLLER_IDENTITY,
		authoritySet: authoritySet,
		authoritySetDigest: authoritySetDigest(authoritySet),
		activeTier: 1,
		iteration: 0,
		terminal: false,
		verifiedSolves: initialStatuses(),
		signedReportHistory: [],
		expansionHistory: [],
	};
	return freeze({ ...base, stateDigest: stateDigest(base) });
}

export function createInitialLactfTierState(): LactfTierState {
	return initialState();
}

function fail(code: "digest_mismatch" | "integrity_error" | "revision_conflict", message: string): never {
	throw new CtfError(code, message);
}

function tierIds(tier: LactfTierNumber): readonly LactfTierChallengeId[] {
	return LACTF_BENCHMARK_TIERS[tier - 1];
}

function sameIds(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((id, index) => id === right[index]);
}

function isChallengeId(value: unknown): value is LactfTierChallengeId {
	return typeof value === "string" && (ALL_IDS as readonly string[]).includes(value);
}
function trustedOracleAuthority(value: unknown, trustAnchors: OracleTrustAnchorsV1) {
	const input = value && typeof value === "object" && !Array.isArray(value)
		? ((value as Record<string, unknown>).trustedRegistry ??
			(value as Record<string, unknown>).oracleRegistry ??
			(value as Record<string, unknown>).registry ??
			value)
		: value;
	return validateAnchoredOracleRegistry(input, trustAnchors);
}

function pinAuthority(value: LactfTierAuthority): LactfTierAuthorityIdentity {
	try {
		const manifest = validateBenchmarkManifest(value.manifest);
		const lock = validateBenchmarkLock(value.lock);
		assertBenchmarkLockMatchesManifest(lock, manifest);
		const calibration = validateBenchmarkCalibration(value.calibration, { requireBenchmark: true });
		const trustAnchors = validateOracleTrustAnchors(value.oracleTrustAnchors);
		const oracle = trustedOracleAuthority(value.oracle, trustAnchors);
		if (
			calibration.calibrationId !== manifest.calibrationId ||
			!digestsEqual(calibration.operationalLimitsDigest, manifest.operationalLimitsDigest) ||
			!digestsEqual(oracle.registry.registryDigest, manifest.oracleRegistryDigest)
		) {
			fail("integrity_error", "tier controller authority does not match its benchmark manifest");
		}
		return freeze({
			manifestDigest: manifest.manifestDigest,
			lockDigest: lock.lockDigest,
			corpusDigest: benchmarkCorpusDigest(manifest),
			calibrationDigest: calibration.calibrationDigest,
			oracleRegistryDigest: oracle.registry.registryDigest,
			oracleAuthorityDigest: canonicalDigest({ oracle, trustAnchors }),
			oracleRegistrySignerFingerprint: trustAnchors.registrySignerFingerprint,
			oracleResultSignerFingerprint: trustAnchors.resultSignerFingerprint,
		});
	} catch (error) {
		if (error instanceof CtfError) throw error;
		fail("integrity_error", "tier controller authority is invalid");
	}
}
function pinAuthoritySet(value: LactfTierAuthoritySet): LactfTierAuthoritySetIdentity {
	return freeze({ 1: pinAuthority(value.tier1), 2: pinAuthority(value.tier2) });
}

function requestMatchesAuthority(request: unknown, authority: LactfTierAuthorityIdentity): boolean {
	if (!request || typeof request !== "object" || Array.isArray(request)) return false;
	try {
		const value = request as Record<string, unknown>;
		const manifest = validateBenchmarkManifest(value.manifest);
		const lock = validateBenchmarkLock(value.lock);
		assertBenchmarkLockMatchesManifest(lock, manifest);
		const calibration = validateBenchmarkCalibration(value.calibration, { requireBenchmark: true });
		const trustAnchors = validateOracleTrustAnchors({
			registrySignerFingerprint: authority.oracleRegistrySignerFingerprint,
			resultSignerFingerprint: authority.oracleResultSignerFingerprint,
		});
		const oracle = trustedOracleAuthority(value.oracle, trustAnchors);
		return (
			digestsEqual(manifest.manifestDigest, authority.manifestDigest) &&
			digestsEqual(lock.lockDigest, authority.lockDigest) &&
			digestsEqual(benchmarkCorpusDigest(manifest), authority.corpusDigest) &&
			digestsEqual(calibration.calibrationDigest, authority.calibrationDigest) &&
			digestsEqual(oracle.registry.registryDigest, authority.oracleRegistryDigest) &&
			digestsEqual(canonicalDigest({ oracle, trustAnchors }), authority.oracleAuthorityDigest)
		);
	} catch {
		return false;
	}
}

/** Reject malformed, cross-corpus, and internally inconsistent durable state. */
export function validateLactfTierState(value: unknown): LactfTierState {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail("integrity_error", "tier state is not an object");
	const state = value as Record<string, unknown>;
	const expectedKeys = new Set([
		"schemaVersion", "identity", "authoritySet", "authoritySetDigest", "activeTier", "iteration", "terminal", "verifiedSolves", "signedReportHistory", "expansionHistory", "stateDigest",
	]);
	if (Object.keys(state).some(key => !expectedKeys.has(key)) || Object.keys(state).length !== expectedKeys.size) {
		fail("integrity_error", "tier state has an invalid shape");
	}
	if (state.schemaVersion !== "gjc-lactf-tier-state-3" || !digestsEqual(String(state.identity), LACTF_TIER_CONTROLLER_IDENTITY)) {
		fail("integrity_error", "tier state identity does not match the immutable LA CTF corpus");
	}
	if (!state.authoritySet || typeof state.authoritySet !== "object" || Array.isArray(state.authoritySet) || !isDigest(state.authoritySetDigest)) {
		fail("integrity_error", "tier state authority set is invalid");
	}
	const authoritySet = state.authoritySet as Record<string, unknown>;
	const authorityKeys = Object.keys(authoritySet).sort();
	if (!sameIds(authorityKeys, []) && !sameIds(authorityKeys, ["1", "2"])) fail("integrity_error", "tier state authority set is incomplete");
	for (const key of authorityKeys) {
		const authority = authoritySet[key] as Record<string, unknown>;
		if (!authority || typeof authority !== "object" || Array.isArray(authority) || Object.keys(authority).length !== 8 ||
			!isDigest(authority.manifestDigest) || !isDigest(authority.lockDigest) || !isDigest(authority.corpusDigest) ||
			!isDigest(authority.calibrationDigest) || !isDigest(authority.oracleRegistryDigest) || !isDigest(authority.oracleAuthorityDigest) ||
			!isDigest(authority.oracleRegistrySignerFingerprint) || !isDigest(authority.oracleResultSignerFingerprint) ||
			digestsEqual(String(authority.oracleRegistrySignerFingerprint), String(authority.oracleResultSignerFingerprint))) {
			fail("integrity_error", "tier state authority identity is invalid");
		}
	}
	if (!digestsEqual(authoritySetDigest(authoritySet as LactfTierAuthoritySetIdentity), state.authoritySetDigest as Digest)) {
		fail("digest_mismatch", "tier state authority set digest mismatch");
	}
	if (state.activeTier !== 1 && state.activeTier !== 2) fail("integrity_error", "tier state active tier is invalid");
	if (!Number.isSafeInteger(state.iteration) || (state.iteration as number) < 0) fail("integrity_error", "tier state iteration is invalid");
	if (typeof state.terminal !== "boolean") fail("integrity_error", "tier state terminal flag is invalid");
	if (!state.verifiedSolves || typeof state.verifiedSolves !== "object" || Array.isArray(state.verifiedSolves)) fail("integrity_error", "tier state solve statuses are invalid");
	const statuses = state.verifiedSolves as Record<string, unknown>;
	if (!sameIds(Object.keys(statuses).sort(), [...ALL_IDS].sort()) || ALL_IDS.some(id => typeof statuses[id] !== "boolean")) {
		fail("integrity_error", "tier state solve statuses do not bind the pinned corpus");
	}
	if (!Array.isArray(state.signedReportHistory) || !Array.isArray(state.expansionHistory)) fail("integrity_error", "tier state histories are invalid");
	const history = state.signedReportHistory as SignedReportSummary[];
	const reportDigests = new Set<string>();
	const verifiedByHistory = new Set<LactfTierChallengeId>();
	for (const entry of history) {
		if (
			!entry ||
			typeof entry !== "object" ||
			Object.keys(entry as object).length !== 7 ||
			!isDigest(entry.reportDigest) ||
			!isDigest(entry.reportFingerprint) ||
			!isDigest(entry.authorityDigest) ||
			!isDigest(entry.authoritySetDigest) ||
			(entry.tier !== 1 && entry.tier !== 2) ||
			!Array.isArray(entry.eligibleChallengeIds) ||
			!Array.isArray(entry.verifiedSolveIds) ||
			!sameIds(entry.eligibleChallengeIds, tierIds(entry.tier)) ||
			new Set(entry.verifiedSolveIds).size !== entry.verifiedSolveIds.length ||
			entry.verifiedSolveIds.some(id => !isChallengeId(id) || !tierIds(entry.tier).includes(id)) ||
			!digestsEqual(entry.authoritySetDigest, state.authoritySetDigest as Digest) ||
			!authoritySet[String(entry.tier)] ||
			!digestsEqual(entry.authorityDigest, canonicalDigest(authoritySet[String(entry.tier)]))
		) {
			fail("integrity_error", "tier state report history is invalid");
		}
		if (reportDigests.has(entry.reportDigest)) fail("integrity_error", "tier state report history contains a duplicate digest");
		reportDigests.add(entry.reportDigest);
		for (const id of entry.verifiedSolveIds) verifiedByHistory.add(id);
	}
	if (history.length !== state.iteration || ALL_IDS.some(id => statuses[id] !== verifiedByHistory.has(id))) {
		fail("integrity_error", "tier state solve statuses are not derived from report history");
	}
	const expansions = state.expansionHistory as TierExpansion[];
	if (
		expansions.length > 1 ||
		expansions.some(
			entry =>
				!entry ||
				typeof entry !== "object" ||
				Object.keys(entry as object).length !== 4 ||
				entry.fromTier !== 1 ||
				entry.toTier !== 2 ||
				!isDigest(entry.reportDigest) ||
				!Number.isSafeInteger(entry.iteration) ||
				entry.iteration <= 0 ||
				!reportDigests.has(entry.reportDigest),
		)
	) {
		fail("integrity_error", "tier state expansion history is invalid");
	}
	if ((state.activeTier === 1 && (state.terminal || expansions.length !== 0)) || (state.activeTier === 2 && expansions.length !== 1)) {
		fail("integrity_error", "tier state active tier conflicts with its expansion history");
	}
	if (state.terminal && (!ALL_IDS.every(id => statuses[id] === true) || state.activeTier !== 2)) {
		fail("integrity_error", "terminal tier state is incomplete");
	}
	if (!isDigest(state.stateDigest)) fail("digest_mismatch", "tier state digest is invalid");
	const { stateDigest: persistedDigest, ...base } = state as LactfTierState;
	if (!digestsEqual(stateDigest(base), persistedDigest)) fail("digest_mismatch", "tier state digest mismatch");
	return freeze(state as LactfTierState);
}

function isMissing(error: unknown): boolean {
	return typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === "ENOENT";
}

export class LactfTierController {
	readonly store: CtfStateStore;
	readonly path: string;
	readonly authority?: LactfTierAuthoritySetIdentity;

	constructor(store: CtfStateStoreLike, path = LACTF_TIER_CONTROLLER_PATH, authority?: LactfTierAuthoritySet) {
		this.store = createCtfStateStore(store, { durability: "ctf" });
		this.path = path;
		this.authority = authority === undefined ? undefined : pinAuthoritySet(authority);
	}

	private assertAuthority(state: LactfTierState): LactfTierState {
		if (Object.keys(state.authoritySet).length === 0) {
			fail("integrity_error", "durable tier state is missing its pinned authority set");
		}
		if (this.authority === undefined || !digestsEqual(state.authoritySetDigest, authoritySetDigest(this.authority))) {
			fail("integrity_error", "tier state authority does not match the pinned controller authority set");
		}
		return state;
	}

	private async readPersisted(): Promise<LactfTierState | undefined> {
		try {
			return this.assertAuthority(validateLactfTierState(JSON.parse(await Bun.file(this.store.resolve(this.path)).text())));
		} catch (error) {
			if (isMissing(error)) return undefined;
			if (error instanceof SyntaxError) fail("integrity_error", "tier state is not valid JSON");
			throw error;
		}
	}

	async load(): Promise<LactfTierState> {
		return (await this.readPersisted()) ?? initialState(this.authority);
	}


	/**
	 * Admit one raw report request only when it is rooted in the authority
	 * pinned at controller construction. Reports without a pinned authority
	 * remain unavailable, including internally consistent caller-created roots.
	 */
	async submitReport(request: unknown): Promise<LactfTierState> {
		return this.store.withLock(this.path, async () => {
			const current = (await this.readPersisted()) ?? initialState(this.authority);
			if (this.authority === undefined || !requestMatchesAuthority(request, this.authority[current.activeTier]!)) return current;
			const evaluated = evaluateBenchmarkReport(request, {
				oracleTrustAnchors: this.authority[current.activeTier]!.oracleTrustAnchors,
			});
			if (evaluated.status !== "ready") return current;
			const activeIds = tierIds(current.activeTier);
			if (!sameIds(evaluated.report.eligibleChallengeIds ?? [], activeIds)) return current;
			const reportDigest = canonicalDigest(evaluated.report);
			if (current.signedReportHistory.some(entry => digestsEqual(entry.reportDigest, reportDigest))) return current;
			const solved = activeIds.filter(id => evaluated.report.runs.some(run => run.challengeId === id && run.outcome === "pass" && run.validatedSolve));
			const verifiedSolves: VerifiedSolveStatus = { ...current.verifiedSolves };
			for (const id of solved) verifiedSolves[id] = true;
			const summary: SignedReportSummary = {
				reportDigest,
				reportFingerprint: evaluated.report.fingerprint,
				authorityDigest: canonicalDigest(this.authority[current.activeTier]!),
				authoritySetDigest: authoritySetDigest(this.authority),
				tier: current.activeTier,
				eligibleChallengeIds: [...activeIds],
				verifiedSolveIds: solved,
			};
			const complete = activeIds.every(id => verifiedSolves[id]);
			const expands = complete && current.activeTier === 1;
			const nextTier: LactfTierNumber = expands ? 2 : current.activeTier;
			const nextIteration = current.iteration + 1;
			const base: Omit<LactfTierState, "stateDigest"> = {
				schemaVersion: "gjc-lactf-tier-state-3",
				identity: LACTF_TIER_CONTROLLER_IDENTITY,
				authoritySet: this.authority,
				authoritySetDigest: authoritySetDigest(this.authority),
				activeTier: nextTier,
				iteration: nextIteration,
				terminal: complete && current.activeTier === 2,
				verifiedSolves,
				signedReportHistory: [...current.signedReportHistory, summary],
				expansionHistory: expands ? [...current.expansionHistory, { fromTier: 1, toTier: 2, reportDigest, iteration: nextIteration }] : current.expansionHistory,
			};
			const next = validateLactfTierState({ ...base, stateDigest: stateDigest(base) });
			await this.store.writeJsonAtomic(this.path, next, { durability: "ctf" });
			return next;
		}, { durability: "ctf" });
	}

	async evaluate(request: unknown): Promise<LactfTierState> {
		return this.submitReport(request);
	}
}

export const createLactfTierController = (store: CtfStateStoreLike, path?: string, authority?: LactfTierAuthoritySet): LactfTierController =>
	new LactfTierController(store, path, authority);
