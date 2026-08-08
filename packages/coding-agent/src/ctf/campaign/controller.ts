import { randomUUID } from "node:crypto";
import * as path from "node:path";
import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type CorpusEntry,
	corpusContentDigest,
	type MaterializedCorpus,
	validateCorpusEntry,
	validateMaterializedCorpus,
} from "../corpus";
import {
	type CtfArtifactEvidence,
	type CtfBatchScheduleResult,
	type CtfScheduledRun,
	type CtfSolverBackend,
	type CtfTerminationRequest,
	scheduleCtfRuns,
} from "../runtime/scheduler";
import { type CtfStateStoreLike, createCtfStateStore } from "../state/storage";

export const CTF_CAMPAIGN_HARD_STOP = "2026-08-09T00:00:00Z" as const;
const CAMPAIGN_SCHEMA = "ctf-campaign-1" as const;
const MAX_REASON_LENGTH = 256;
const CAMPAIGN_FINALIZATION_SCHEMA = "ctf-campaign-finalization-1" as const;

export type CampaignAttempt = Readonly<{
	attempt: number;
	startedAt: string;
	finishedAt?: string;
	status: "candidate" | "unknown" | "failure";
	reason?: string;
	artifacts: readonly string[];
	artifactEvidence?: readonly CtfArtifactEvidence[];
	producerDigest?: Digest;
	routeDigest?: Digest;
}>;

export type CampaignMaterialized = Readonly<{
	root: string;
	provenanceDigest: Digest;
	visibleFileDigests: Readonly<Record<string, Digest>>;
}>;

export type CampaignChallenge = Readonly<{
	challengeId: string;
	inputDigest: Digest;
	status: "pending" | "candidate" | "unknown" | "failure";
	attempts: readonly CampaignAttempt[];
	materialized?: CampaignMaterialized;
}>;
export type CampaignFinalization = Readonly<{
	schemaVersion: typeof CAMPAIGN_FINALIZATION_SCHEMA;
	campaignId: string;
	competitionId: string;
	stopAt: typeof CTF_CAMPAIGN_HARD_STOP;
	preFinalStateDigest: Digest;
	challengeStateDigest: Digest;
	finalizationDigest: Digest;
}>;

export type CtfCampaignState = Readonly<{
	schemaVersion: typeof CAMPAIGN_SCHEMA;
	campaignId: string;
	competitionId: string;
	createdAt: string;
	updatedAt: string;
	stopAt: typeof CTF_CAMPAIGN_HARD_STOP;
	challenges: readonly CampaignChallenge[];
	stateDigest: Digest;
	finalization?: CampaignFinalization;
}>;

export type CtfCampaignMaterializer = ((
	input: Readonly<{
		challengeId: string;
		attempt: number;
		ownerId: string;
		signal: AbortSignal;
	}>,
) => Promise<MaterializedCorpus>) & {
	/** Resolves only after this materializer can prove the attempt cannot write again. */
	terminate?(request: CtfTerminationRequest): Promise<void>;
};

export type CampaignCandidateLineage = Readonly<{
	producerDigest: Digest;
	routeDigest: Digest;
}>;

export type CtfCampaignOptions = Readonly<{
	campaignId: string;
	competitionId: string;
	challenges: readonly CorpusEntry[];
	store: CtfStateStoreLike;
	backend: CtfSolverBackend;
	/** Required to resume a candidate: binds its immutable producing route and backend lineage. */
	candidateLineageFor?: (input: Readonly<{ challengeId: string }>) => Promise<CampaignCandidateLineage>;
	authorityFor: Parameters<typeof scheduleCtfRuns>[0]["authorityFor"];
	terminateAuthority: NonNullable<Parameters<typeof scheduleCtfRuns>[0]["terminateAuthority"]>;
	prepareRun?: Parameters<typeof scheduleCtfRuns>[0]["prepareRun"];
	terminatePreparation?: Parameters<typeof scheduleCtfRuns>[0]["terminatePreparation"];
	concurrency: number;
	budgetMs?: number;
	maxAttempts: number;
	backoffMs?: number;
	materialize?: CtfCampaignMaterializer;
	signal?: AbortSignal;
}>;

export type CtfCampaignResult = Readonly<{
	state: CtfCampaignState;
	runs: readonly CtfBatchScheduleResult[];
	stopped: boolean;
}>;

function reason(value: string | undefined): string | undefined {
	if (value === undefined || value.trim().length === 0) return undefined;
	return value.length > MAX_REASON_LENGTH ? `${value.slice(0, MAX_REASON_LENGTH)}…` : value;
}

function campaignPath(id: string): string {
	if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(id))
		throw new CtfError("invalid_api_request", "campaign id is invalid");
	return path.posix.join("campaigns", `${id}.json`);
}
function campaignFinalizationPath(id: string): string {
	return path.posix.join("campaigns", `${id}.finalization.json`);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
function sealState(state: Omit<CtfCampaignState, "stateDigest">): CtfCampaignState {
	return { ...state, stateDigest: canonicalDigest(state) };
}
function sealFinalization(
	state: Omit<CtfCampaignState, "stateDigest" | "finalization">,
	preFinalStateDigest: Digest,
): CampaignFinalization {
	const basis = {
		schemaVersion: CAMPAIGN_FINALIZATION_SCHEMA,
		campaignId: state.campaignId,
		competitionId: state.competitionId,
		stopAt: state.stopAt,
		preFinalStateDigest,
		challengeStateDigest: canonicalDigest(state.challenges),
	};
	return { ...basis, finalizationDigest: canonicalDigest(basis) };
}

function finalizeState(state: CtfCampaignState): CtfCampaignState {
	const { stateDigest: preFinalStateDigest, finalization: _finalization, ...basis } = state;
	const finalization = sealFinalization(basis, preFinalStateDigest);
	return sealState({ ...basis, finalization });
}

function validFinalization(value: unknown): value is CampaignFinalization {
	if (
		!isRecord(value) ||
		!hasExactKeys(value, [
			"schemaVersion",
			"campaignId",
			"competitionId",
			"stopAt",
			"preFinalStateDigest",
			"challengeStateDigest",
			"finalizationDigest",
		])
	)
		return false;
	const { finalizationDigest, ...basis } = value;
	return (
		value.schemaVersion === CAMPAIGN_FINALIZATION_SCHEMA &&
		typeof value.campaignId === "string" &&
		typeof value.competitionId === "string" &&
		value.stopAt === CTF_CAMPAIGN_HARD_STOP &&
		isDigest(value.preFinalStateDigest) &&
		isDigest(value.challengeStateDigest) &&
		isDigest(finalizationDigest) &&
		canonicalDigest(basis) === finalizationDigest
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function validArtifactEvidence(value: unknown): value is CtfArtifactEvidence {
	if (!isRecord(value) || !hasExactKeys(value, ["path", "digest", "size"])) return false;
	const size = value.size;
	return (
		typeof value.path === "string" &&
		value.path.length > 0 &&
		!path.isAbsolute(value.path) &&
		!value.path.includes("\\") &&
		path.posix.normalize(value.path) === value.path &&
		value.path !== "." &&
		!value.path.startsWith("../") &&
		!value.path.includes("/../") &&
		typeof value.digest === "string" &&
		/^[a-f0-9]{64}$/u.test(value.digest) &&
		typeof size === "number" &&
		Number.isSafeInteger(size) &&
		size >= 0
	);
}
function validRelativePath(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		!path.isAbsolute(value) &&
		!value.includes("\\") &&
		path.posix.normalize(value) === value &&
		value !== "." &&
		!value.startsWith("../") &&
		!value.includes("/../")
	);
}

function validMaterialized(value: unknown): value is CampaignMaterialized {
	if (!isRecord(value) || Object.keys(value).length !== 3) return false;
	if (
		typeof value.root !== "string" ||
		value.root.length === 0 ||
		!path.isAbsolute(value.root) ||
		path.resolve(value.root) !== value.root ||
		!isDigest(value.provenanceDigest) ||
		!isRecord(value.visibleFileDigests)
	)
		return false;
	const visibleFileDigests = value.visibleFileDigests;
	const paths = Object.keys(visibleFileDigests);
	return (
		paths.length > 0 &&
		paths.every(relativePath => validRelativePath(relativePath) && isDigest(visibleFileDigests[relativePath]))
	);
}

function campaignInputDigest(entry: CorpusEntry, backendId: string): Digest {
	return canonicalDigest({
		backendId,
		source: entry.source,
		provenance: entry.provenance,
		permissionEvidence: entry.permissionEvidence ?? null,
		installCommands: entry.installCommands ?? [],
	});
}
function materializedMatchesEntry(materialized: CampaignMaterialized, entry: CorpusEntry): boolean {
	const expectedFiles = Object.fromEntries(entry.provenance.files.map(file => [file.relativePath, file.sha256]));
	const actualPaths = Object.keys(materialized.visibleFileDigests);
	return (
		digestsEqual(materialized.provenanceDigest, corpusContentDigest(entry.provenance)) &&
		actualPaths.length === Object.keys(expectedFiles).length &&
		actualPaths.every(
			relativePath =>
				expectedFiles[relativePath] !== undefined &&
				digestsEqual(materialized.visibleFileDigests[relativePath] ?? "", expectedFiles[relativePath]),
		)
	);
}
function validLineage(value: unknown): value is CampaignCandidateLineage {
	return (
		isRecord(value) &&
		Object.keys(value).length === 2 &&
		isDigest(value.producerDigest) &&
		isDigest(value.routeDigest)
	);
}

function attemptLineageMatches(attempt: CampaignAttempt, lineage: CampaignCandidateLineage): boolean {
	return (
		attempt.producerDigest !== undefined &&
		attempt.routeDigest !== undefined &&
		digestsEqual(attempt.producerDigest, lineage.producerDigest) &&
		digestsEqual(attempt.routeDigest, lineage.routeDigest)
	);
}

export function validateCampaignState(value: unknown): CtfCampaignState {
	if (
		!isRecord(value) ||
		!hasExactKeys(
			value,
			value.finalization === undefined
				? [
						"schemaVersion",
						"campaignId",
						"competitionId",
						"createdAt",
						"updatedAt",
						"stopAt",
						"challenges",
						"stateDigest",
					]
				: [
						"schemaVersion",
						"campaignId",
						"competitionId",
						"createdAt",
						"updatedAt",
						"stopAt",
						"challenges",
						"stateDigest",
						"finalization",
					],
		) ||
		value.schemaVersion !== CAMPAIGN_SCHEMA ||
		typeof value.campaignId !== "string" ||
		typeof value.competitionId !== "string" ||
		typeof value.createdAt !== "string" ||
		typeof value.updatedAt !== "string" ||
		value.stopAt !== CTF_CAMPAIGN_HARD_STOP ||
		typeof value.stateDigest !== "string" ||
		!Array.isArray(value.challenges)
	)
		throw new CtfError("integrity_error", "campaign state schema is invalid");
	const { stateDigest, ...basis } = value;
	if (value.finalization !== undefined) {
		if (Date.now() < Date.parse(CTF_CAMPAIGN_HARD_STOP) || !validFinalization(value.finalization))
			throw new CtfError("integrity_error", "campaign finalization is invalid");
		const { finalization, stateDigest: _stateDigest, ...preFinalBasis } = value;
		if (
			finalization.campaignId !== value.campaignId ||
			finalization.competitionId !== value.competitionId ||
			finalization.stopAt !== value.stopAt ||
			!digestsEqual(finalization.preFinalStateDigest, canonicalDigest(preFinalBasis)) ||
			!digestsEqual(finalization.challengeStateDigest, canonicalDigest(value.challenges))
		)
			throw new CtfError("integrity_error", "campaign finalization does not match state");
	}
	for (const challenge of value.challenges) {
		if (
			!isRecord(challenge) ||
			!hasExactKeys(
				challenge,
				challenge.materialized === undefined
					? ["challengeId", "inputDigest", "status", "attempts"]
					: ["challengeId", "inputDigest", "status", "attempts", "materialized"],
			) ||
			typeof challenge.challengeId !== "string" ||
			!isDigest(challenge.inputDigest) ||
			!["pending", "candidate", "unknown", "failure"].includes(String(challenge.status)) ||
			!Array.isArray(challenge.attempts) ||
			(challenge.materialized !== undefined && !validMaterialized(challenge.materialized))
		)
			throw new CtfError("integrity_error", "campaign challenge state is invalid");
		for (const [index, attempt] of challenge.attempts.entries()) {
			if (
				!isRecord(attempt) ||
				!hasExactKeys(attempt, [
					"attempt",
					"startedAt",
					"status",
					"artifacts",
					...(attempt.finishedAt === undefined ? [] : ["finishedAt"]),
					...(attempt.reason === undefined ? [] : ["reason"]),
					...(attempt.artifactEvidence === undefined ? [] : ["artifactEvidence"]),
					...(attempt.producerDigest === undefined ? [] : ["producerDigest", "routeDigest"]),
				]) ||
				attempt.attempt !== index + 1 ||
				typeof attempt.startedAt !== "string" ||
				!["candidate", "unknown", "failure"].includes(String(attempt.status)) ||
				(attempt.finishedAt !== undefined && typeof attempt.finishedAt !== "string") ||
				(attempt.reason !== undefined && typeof attempt.reason !== "string") ||
				!Array.isArray(attempt.artifacts) ||
				(attempt.producerDigest === undefined) !== (attempt.routeDigest === undefined) ||
				(attempt.producerDigest !== undefined &&
					(!isDigest(attempt.producerDigest) || !isDigest(attempt.routeDigest))) ||
				(attempt.status === "candidate" &&
					(attempt.producerDigest === undefined || attempt.routeDigest === undefined))
			)
				throw new CtfError("integrity_error", "campaign attempt state is invalid");
			const artifacts = attempt.artifacts;
			if (
				artifacts.some(
					artifact =>
						typeof artifact !== "string" ||
						artifact.length === 0 ||
						path.isAbsolute(artifact) ||
						artifact.includes("\\") ||
						path.posix.normalize(artifact) !== artifact ||
						artifact === "." ||
						artifact.startsWith("../") ||
						artifact.includes("/../"),
				) ||
				new Set(artifacts).size !== artifacts.length
			)
				throw new CtfError("integrity_error", "campaign attempt state is invalid");
			if (attempt.artifactEvidence === undefined) continue;
			if (!Array.isArray(attempt.artifactEvidence) || !attempt.artifactEvidence.every(validArtifactEvidence))
				throw new CtfError("integrity_error", "campaign attempt state is invalid");
			const artifactEvidence = attempt.artifactEvidence;
			if (
				new Set(artifactEvidence.map(artifact => artifact.path)).size !== artifactEvidence.length ||
				artifactEvidence.length !== artifacts.length ||
				artifactEvidence.some((artifact, artifactIndex) => artifact.path !== artifacts[artifactIndex])
			)
				throw new CtfError("integrity_error", "campaign attempt state is invalid");
		}
	}
	if (canonicalDigest(basis) !== stateDigest)
		throw new CtfError("integrity_error", "campaign state digest is invalid");
	return value as CtfCampaignState;
}

async function loadState(
	store: ReturnType<typeof createCtfStateStore>,
	target: string,
	fallback: CtfCampaignState,
): Promise<CtfCampaignState> {
	const file = Bun.file(store.resolve(target));
	if (!(await file.exists())) return fallback;
	let value: unknown;
	try {
		value = JSON.parse(await file.text()) as unknown;
	} catch {
		throw new CtfError("integrity_error", "campaign state is corrupt");
	}
	return validateCampaignState(value);
}
async function loadFinalizationAnchor(
	store: ReturnType<typeof createCtfStateStore>,
	target: string,
): Promise<CampaignFinalization | undefined> {
	const file = Bun.file(store.resolve(target));
	if (!(await file.exists())) return undefined;
	let value: unknown;
	try {
		value = JSON.parse(await file.text()) as unknown;
	} catch {
		throw new CtfError("integrity_error", "campaign finalization anchor is corrupt");
	}
	if (!validFinalization(value)) throw new CtfError("integrity_error", "campaign finalization anchor is invalid");
	return value;
}

function finalizationsEqual(left: CampaignFinalization, right: CampaignFinalization): boolean {
	return canonicalDigest(left) === canonicalDigest(right);
}

function initialState(options: CtfCampaignOptions, now: Date): CtfCampaignState {
	const ids = options.challenges.map(entry => entry.source.challengeId);
	for (const entry of options.challenges) validateCorpusEntry(entry);
	if (ids.length === 0 || new Set(ids).size !== ids.length)
		throw new CtfError("invalid_api_request", "campaign challenges must be unique");
	return sealState({
		schemaVersion: CAMPAIGN_SCHEMA,
		campaignId: options.campaignId,
		competitionId: options.competitionId,
		createdAt: now.toISOString(),
		updatedAt: now.toISOString(),
		stopAt: CTF_CAMPAIGN_HARD_STOP,
		challenges: options.challenges
			.map(entry => ({
				challengeId: entry.source.challengeId,
				inputDigest: campaignInputDigest(entry, options.backend.id),
				status: "pending" as const,
				attempts: [],
			}))
			.sort((left, right) => left.challengeId.localeCompare(right.challengeId)),
	});
}

function outcomeStatus(outcome: Pick<CtfScheduledRun, "status">): "candidate" | "unknown" | "failure" {
	if (outcome.status === "candidate") return "candidate";
	if (outcome.status === "failed") return "failure";
	return "unknown";
}

function defaultMaterializer(_options: CtfCampaignOptions): CtfCampaignMaterializer {
	return async ({ challengeId }) => {
		throw new CtfError("missing_provenance", `a materializer is required for ${challengeId}`);
	};
}

function createDeadlineSignal(signal: AbortSignal | undefined): Readonly<{
	signal: AbortSignal;
	reached(): boolean;
	dispose(): void;
}> {
	const stop = Date.parse(CTF_CAMPAIGN_HARD_STOP);
	const controller = new AbortController();
	let deadlineReached = false;
	const abortForDeadline = () => {
		deadlineReached = true;
		controller.abort("campaign deadline reached");
	};
	const remainingMs = stop - Date.now();
	let timer: ReturnType<typeof setTimeout> | undefined;
	if (remainingMs <= 0) abortForDeadline();
	else timer = setTimeout(abortForDeadline, remainingMs);
	const abortForCaller = () => controller.abort(signal?.reason);
	if (signal?.aborted) abortForCaller();
	else signal?.addEventListener("abort", abortForCaller, { once: true });
	return {
		signal: controller.signal,
		reached: () => deadlineReached || Date.now() >= stop,
		dispose: () => {
			if (timer !== undefined) clearTimeout(timer);
			signal?.removeEventListener("abort", abortForCaller);
		},
	};
}

async function materializeWithAbort(
	materialize: CtfCampaignMaterializer,
	input: Readonly<{ challengeId: string; attempt: number; ownerId: string; signal: AbortSignal }>,
): Promise<MaterializedCorpus | undefined> {
	if (input.signal.aborted) return undefined;
	const cancelled = Promise.withResolvers<undefined>();
	let termination: Promise<void> | undefined;
	const terminateMaterialization = () => {
		if (termination === undefined) {
			if (materialize.terminate === undefined)
				termination = Promise.reject(
					new CtfError("invalid_api_request", "production materialization requires termination acknowledgment"),
				);
			else
				termination = materialize.terminate({
					runId: input.ownerId,
					challengeId: input.challengeId,
					ownerId: input.ownerId,
					reason: input.signal.reason === "campaign deadline reached" ? "budget_exhausted" : "cancelled",
				});
			void termination.then(
				() => cancelled.resolve(undefined),
				error => cancelled.reject(error),
			);
		}
		return termination;
	};
	const abort = () => {
		void terminateMaterialization();
	};
	input.signal.addEventListener("abort", abort, { once: true });
	const materialization = Promise.resolve().then(() => materialize(input));
	try {
		const result = await Promise.race([materialization, cancelled.promise]);
		if (input.signal.aborted) {
			await terminateMaterialization();
			return undefined;
		}
		return result;
	} finally {
		input.signal.removeEventListener("abort", abort);
	}
}
function reserveMaterializationOwnerId(owners: Set<string>): string {
	let ownerId = randomUUID();
	while (owners.has(ownerId)) ownerId = randomUUID();
	owners.add(ownerId);
	return ownerId;
}
async function backoffWithAbort(milliseconds: number, signal: AbortSignal): Promise<void> {
	if (signal.aborted) return;
	const cancelled = Promise.withResolvers<void>();
	const abort = () => cancelled.resolve();
	signal.addEventListener("abort", abort, { once: true });
	try {
		await Promise.race([Bun.sleep(milliseconds), cancelled.promise]);
	} finally {
		signal.removeEventListener("abort", abort);
	}
}

async function runCtfCampaignLocked(
	options: CtfCampaignOptions,
	store: ReturnType<typeof createCtfStateStore>,
	target: string,
): Promise<CtfCampaignResult> {
	const deadline = createDeadlineSignal(options.signal);
	try {
		return await runCtfCampaignWithDeadline(options, store, target, deadline);
	} finally {
		deadline.dispose();
	}
}

async function runCtfCampaignWithDeadline(
	options: CtfCampaignOptions,
	store: ReturnType<typeof createCtfStateStore>,
	target: string,
	deadline: Readonly<{ signal: AbortSignal; reached(): boolean }>,
): Promise<CtfCampaignResult> {
	const now = () => new Date();
	const stop = Date.parse(CTF_CAMPAIGN_HARD_STOP);
	const initial = initialState(options, now());
	let state = await loadState(store, target, initial);
	const finalizationTarget = campaignFinalizationPath(options.campaignId);
	const anchor = await loadFinalizationAnchor(store, finalizationTarget);
	if (state.finalization === undefined && anchor !== undefined) {
		if (
			Date.now() < stop ||
			anchor.campaignId !== state.campaignId ||
			anchor.competitionId !== state.competitionId ||
			anchor.stopAt !== state.stopAt ||
			!digestsEqual(anchor.preFinalStateDigest, state.stateDigest) ||
			!digestsEqual(anchor.challengeStateDigest, canonicalDigest(state.challenges))
		)
			throw new CtfError("integrity_error", "campaign finalization anchor does not match state");
		const { stateDigest: _stateDigest, ...basis } = state;
		state = validateCampaignState(sealState({ ...basis, finalization: anchor }));
		await store.writeJsonAtomic(target, state, { durability: "ctf" });
	}
	if (state.finalization !== undefined && anchor === undefined)
		throw new CtfError("integrity_error", "campaign finalization state and anchor do not match");
	if (state.finalization !== undefined && !finalizationsEqual(state.finalization, anchor!))
		throw new CtfError("integrity_error", "campaign finalization anchor does not match state");
	if (
		state.campaignId !== options.campaignId ||
		state.competitionId !== options.competitionId ||
		state.stopAt !== CTF_CAMPAIGN_HARD_STOP
	) {
		throw new CtfError("integrity_error", "campaign state identity or hard stop does not match");
	}
	const corpusByChallengeId = new Map<string, (typeof options.challenges)[number]>(
		options.challenges.map(entry => [entry.source.challengeId, entry]),
	);
	if (corpusByChallengeId.size !== state.challenges.length)
		throw new CtfError("integrity_error", "campaign challenge set does not match");
	for (const challenge of state.challenges) {
		const entry = corpusByChallengeId.get(challenge.challengeId);
		if (
			entry === undefined ||
			!digestsEqual(challenge.inputDigest, campaignInputDigest(entry, options.backend.id)) ||
			(challenge.materialized !== undefined && !materializedMatchesEntry(challenge.materialized, entry))
		)
			throw new CtfError("integrity_error", "campaign challenge input identity does not match");
		if (challenge.status === "candidate" && state.finalization === undefined) {
			const attempt = challenge.attempts.at(-1);
			const lineage =
				options.candidateLineageFor === undefined
					? undefined
					: await options.candidateLineageFor({ challengeId: challenge.challengeId });
			if (
				attempt?.status !== "candidate" ||
				lineage === undefined ||
				!validLineage(lineage) ||
				!attemptLineageMatches(attempt, lineage)
			)
				throw new CtfError("integrity_error", "campaign candidate lineage does not match");
		}
	}
	if (state.finalization !== undefined) return { state, runs: [], stopped: true };
	const materialize = options.materialize ?? defaultMaterializer(options);
	const materializationOwners = new Set<string>();
	const runs: CtfBatchScheduleResult[] = [];
	for (let iteration = 0; iteration < options.maxAttempts; iteration += 1) {
		if (deadline.signal.aborted || deadline.reached()) break;
		const pending = state.challenges
			.filter(challenge => challenge.status !== "candidate" && challenge.attempts.length < options.maxAttempts)
			.map(challenge => challenge.challengeId);
		if (pending.length === 0) break;
		const startedAt = now().toISOString();
		const materialized = new Map<string, CampaignMaterialized>();
		for (const challengeId of pending) {
			const challenge = state.challenges.find(item => item.challengeId === challengeId);
			if (challenge === undefined) throw new CtfError("integrity_error", "campaign challenge state is missing");
			const corpus = await materializeWithAbort(materialize, {
				challengeId,
				attempt: challenge.attempts.length + 1,
				ownerId: reserveMaterializationOwnerId(materializationOwners),
				signal: deadline.signal,
			});
			if (corpus === undefined) break;
			const entry = corpusByChallengeId.get(challengeId);
			if (entry === undefined) throw new CtfError("integrity_error", "campaign corpus entry is missing");
			const authority = await validateMaterializedCorpus(entry, corpus);
			materialized.set(challengeId, {
				root: corpus.root,
				...authority,
			});
		}
		if (deadline.signal.aborted || deadline.reached()) break;
		const remainingMs = stop - now().getTime();
		if (remainingMs <= 0) break;
		if (deadline.signal.aborted || deadline.reached()) break;
		const batch = await scheduleCtfRuns({
			competitionId: options.competitionId,
			challengeIds: pending,
			mode: "competition",
			concurrency: options.concurrency,
			budgetMs: Math.min(options.budgetMs ?? remainingMs, remainingMs),
			backend: options.backend,
			authorityFor: options.authorityFor,
			terminateAuthority: options.terminateAuthority,
			materializedFor: async ({ challengeId }) => {
				const context = materialized.get(challengeId);
				if (context === undefined)
					throw new CtfError("missing_provenance", `materialized corpus is unavailable for ${challengeId}`);
				return context;
			},
			terminateMaterialization: async () => {},
			prepareRun: options.prepareRun,
			terminatePreparation: options.terminatePreparation,
			signal: deadline.signal,
			createUnavailable: async challengeId => ({
				schemaVersion: "ctf-run-result-1",
				status: "unavailable",
				runId: `unavailable-${challengeId}`,
				competitionId: options.competitionId,
				challengeId,
				mode: "competition",
				reason: "solver backend unavailable",
			}),
		});
		runs.push(batch);
		const finishedAt = now().toISOString();
		const { stateDigest: _stateDigest, ...stateBasis } = state;
		state = sealState({
			...stateBasis,
			updatedAt: finishedAt,
			challenges: state.challenges.map(challenge => {
				const result = batch.results.find(
					candidate => "challengeId" in candidate && candidate.challengeId === challenge.challengeId,
				);
				if (result === undefined) return challenge;
				const status = outcomeStatus(result);
				const context = materialized.get(challenge.challengeId);
				if (context === undefined)
					throw new CtfError("integrity_error", "campaign materialized context is missing");
				const outcomeReason = reason(result.reason);
				const resultLineage =
					"producerDigest" in result || "routeDigest" in result
						? { producerDigest: result.producerDigest, routeDigest: result.routeDigest }
						: undefined;
				if (resultLineage !== undefined && !validLineage(resultLineage))
					throw new CtfError("integrity_error", "campaign result lineage is invalid");
				// A missing pair is admitted only as the scheduler's no-producer result; candidates always require it.
				if (status === "candidate" && resultLineage === undefined)
					throw new CtfError("integrity_error", "candidate result lineage is required");
				return {
					...challenge,
					status,
					materialized: context,
					attempts: [
						...challenge.attempts,
						{
							attempt: challenge.attempts.length + 1,
							startedAt,
							finishedAt,
							status,
							...(outcomeReason === undefined ? {} : { reason: outcomeReason }),
							artifacts: [...("artifacts" in result ? (result.artifacts ?? []) : [])],
							...(resultLineage === undefined ? {} : resultLineage),
							...("artifactEvidence" in result && result.artifactEvidence !== undefined
								? { artifactEvidence: result.artifactEvidence.map(artifact => ({ ...artifact })) }
								: {}),
						},
					],
				};
			}),
		});
		await store.writeJsonAtomic(target, state, { durability: "ctf" });
		if (options.backoffMs !== undefined && options.backoffMs > 0 && now().getTime() < stop)
			await backoffWithAbort(Math.min(options.backoffMs, Math.max(0, stop - now().getTime())), deadline.signal);
	}
	if (Date.now() >= stop) {
		if (anchor === undefined) {
			if (!(await Bun.file(store.resolve(target)).exists())) {
				state = validateCampaignState(state);
				await store.writeJsonAtomic(target, state, { durability: "ctf" });
			}
			state = finalizeState(state);
			await store.writeJsonAtomic(finalizationTarget, state.finalization!, { durability: "ctf" });
		} else {
			state = finalizeState(state);
			if (!finalizationsEqual(anchor, state.finalization!))
				throw new CtfError("integrity_error", "campaign finalization anchor cannot be altered");
		}
		await store.writeJsonAtomic(target, state, { durability: "ctf" });
	}
	return { state, runs, stopped: deadline.reached() };
}
/** Run resumable, non-scoring attempts over only pinned, materialized corpus files. */
function validateCampaignOptions(options: CtfCampaignOptions): void {
	if (!Number.isSafeInteger(options.maxAttempts) || options.maxAttempts < 1)
		throw new CtfError("invalid_api_request", "maxAttempts must be positive");
	if (!Number.isSafeInteger(options.concurrency) || options.concurrency < 1)
		throw new CtfError("invalid_api_request", "concurrency must be positive");
	if (typeof options.backend.id !== "string" || options.backend.id.trim().length === 0)
		throw new CtfError("invalid_api_request", "backend id is required");
}

/** Run resumable, non-scoring attempts over only pinned, materialized corpus files. */
export async function runCtfCampaign(options: CtfCampaignOptions): Promise<CtfCampaignResult> {
	if (Object.hasOwn(options, "now"))
		throw new CtfError("invalid_api_request", "campaign clock control is internal only");
	validateCampaignOptions(options);
	const store = createCtfStateStore(options.store);
	const target = campaignPath(options.campaignId);
	return await store.withLock(`${target}.campaign`, () => runCtfCampaignLocked(options, store, target), {
		durability: "ctf",
	});
}
