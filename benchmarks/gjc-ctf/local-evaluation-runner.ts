import * as fs from "node:fs/promises";
import * as path from "node:path";
import { canonicalDigest, sha256Hex, type Digest } from "../../packages/coding-agent/src/ctf/contracts/digest";
import { type ChallengeDescriptor, validateChallengeDescriptor } from "../../packages/coding-agent/src/ctf/contracts/manifest";
import {
	type EvaluationLineageV1,
	type EvaluationPreflightV1,
	type EvaluationResultV1,
	type EvaluationSpecV1,
	validateEvaluationLineage,
	validateEvaluationPreflight,
	validateEvaluationSpec,
} from "../../packages/coding-agent/src/ctf/contracts/evaluation";
import {
	corpusContentDigest,
	materializeCorpusEntry,
	type CorpusEntry,
	type MaterializedCorpus,
	validateCorpusEntry,
} from "../../packages/coding-agent/src/ctf/corpus";
import {
	evaluateLocalCandidate,
	type CandidateCollector,
	type EvaluationLineageInput,
	type EvaluationRuntimeAdapter,
	type TrustedOracleCallback,
} from "../../packages/coding-agent/src/ctf/runtime/evaluation";
import type { TrustedOracleRegistry } from "../../packages/coding-agent/src/ctf/runtime/oracle";

export type LocalEvaluationBinding = Readonly<{
	challengeId: string;
	repositoryUrl: string;
	sourceCommit: string;
	challengePath: string;
	corpusDigest: Digest;
	sourceDigest: Digest;
	visiblePolicyDigest: Digest;
	permissionDigest: Digest;
	descriptorDigest: Digest;
	specDigest: Digest;
	preflightDigest: Digest;
	lineageDigest: Digest;
	bindingDigest: Digest;
}>;

export type LocalEvaluationRunnerRequest = Readonly<{
	corpus: CorpusEntry;
	checkoutRoot: string;
	destinationRoot: string;
	descriptor: unknown;
	spec: unknown;
	preflight: unknown;
	lineage: EvaluationLineageInput;
	adapters: readonly EvaluationRuntimeAdapter[];
	createCandidateCollector: (corpus: MaterializedCorpus) => CandidateCollector | Promise<CandidateCollector>;
	trustedOracle?: TrustedOracleRegistry;
	requestOracle?: TrustedOracleCallback;
	signal?: AbortSignal;
}>;

export type LocalEvaluationRunnerResult =
	| Readonly<{ status: "evaluated"; scored: false; binding: LocalEvaluationBinding; result: EvaluationResultV1 }>
	| Readonly<{
			status: "unavailable";
			code: "not_available" | "not_feasible" | "preflight_failed";
			sanitizedReason: string;
	  }>;

const EMPTY_DIGEST = sha256Hex(new Uint8Array());

function unavailable(
	code: "not_available" | "not_feasible" | "preflight_failed",
	reason: string,
): LocalEvaluationRunnerResult {
	return { status: "unavailable", code, sanitizedReason: reason };
}

function safeFailure(error: unknown): string {
	const message = error instanceof Error ? error.message : "local evaluation is unavailable";
	if (
		message.length === 0 ||
		/[\0\r\n]|(?:secret|password|token|private[ _-]?key|stderr)|(?:^|\s)(?:\/|[A-Za-z]:[\\/])/i.test(message)
	)
		return "local evaluation is unavailable";
	return message.slice(0, 512);
}

async function trustedCheckoutRoot(root: string): Promise<string> {
	const lexical = path.resolve(root);
	const real = await fs.realpath(lexical);
	const stat = await fs.lstat(real);
	if (lexical !== real || !stat.isDirectory() || stat.isSymbolicLink()) throw new Error("trusted checkout root is unavailable");
	return real;
}

function exactVisiblePolicy(descriptor: ChallengeDescriptor, corpus: CorpusEntry): Digest {
	const expected = [...corpus.source.visibleFiles];
	if (
		descriptor.visibleArtifactAllowlist.length !== expected.length ||
		descriptor.visibleArtifactAllowlist.some((file, index) => file !== expected[index])
	)
		throw new Error("visible file policy does not match the approved corpus");
	return canonicalDigest(expected);
}

function validateStaticLineage(lineage: EvaluationLineageInput): void {
	const unsigned = {
		...lineage,
		candidateDigest: EMPTY_DIGEST,
		instanceCommitmentDigest: EMPTY_DIGEST,
	};
	validateEvaluationLineage({ ...unsigned, lineageDigest: canonicalDigest(unsigned) } as EvaluationLineageV1);
}

function bindRequest(
	corpus: CorpusEntry,
	descriptor: ChallengeDescriptor,
	spec: EvaluationSpecV1,
	preflight: EvaluationPreflightV1,
	lineage: EvaluationLineageInput,
): LocalEvaluationBinding {
	validateCorpusEntry(corpus);
	if (corpus.permissionEvidence === undefined) throw new Error("approved corpus permission evidence is required");
	const corpusDigest = corpusContentDigest(corpus.provenance);
	const sourceDigest = canonicalDigest(corpus.source);
	const visiblePolicyDigest = exactVisiblePolicy(descriptor, corpus);
	const permissionDigest = canonicalDigest(corpus.permissionEvidence);
	if (
		descriptor.id !== corpus.source.challengeId ||
		descriptor.trustLevel !== "verified-local" ||
		descriptor.networkMode !== "off" ||
		descriptor.sourcePath !== corpus.source.challengePath ||
		descriptor.sourceRevision !== corpus.source.sourceCommit
	)
		throw new Error("descriptor does not bind the approved local corpus");
	if (
		spec.challengeId !== corpus.source.challengeId ||
		spec.descriptorDigest !== descriptor.descriptorDigest ||
		preflight.components.length !== spec.adapters.length ||
		preflight.components.some(component => !spec.adapters.some(adapter => adapter.adapterId === component.adapterId))
	)
		throw new Error("evaluation specification or preflight identity is unavailable");
	validateStaticLineage(lineage);
	if (
		lineage.challengeId !== corpus.source.challengeId ||
		lineage.descriptorDigest !== descriptor.descriptorDigest ||
		lineage.specDigest !== spec.specDigest ||
		lineage.preflightDigest !== preflight.preflightDigest ||
		lineage.corpusDigest !== corpusDigest ||
		lineage.sourceDigest !== sourceDigest ||
		lineage.visiblePolicyDigest !== visiblePolicyDigest
	)
		throw new Error("evaluation lineage does not bind the local corpus");
	const unsigned = {
		challengeId: corpus.source.challengeId,
		repositoryUrl: corpus.source.repositoryUrl,
		sourceCommit: corpus.source.sourceCommit,
		challengePath: corpus.source.challengePath,
		corpusDigest,
		sourceDigest,
		visiblePolicyDigest,
		permissionDigest,
		descriptorDigest: descriptor.descriptorDigest,
		specDigest: spec.specDigest,
		preflightDigest: preflight.preflightDigest,
		lineageDigest: canonicalDigest(lineage),
	};
	return Object.freeze({ ...unsigned, bindingDigest: canonicalDigest(unsigned) });
}

/**
 * Materializes the pinned public corpus into a fresh clean room and delegates candidate
 * execution and any trusted-oracle verification to the existing runtime lifecycle.
 */
export async function runLocalEvaluation(request: LocalEvaluationRunnerRequest): Promise<LocalEvaluationRunnerResult> {
	try {
		const descriptor = validateChallengeDescriptor(request.descriptor);
		const spec = validateEvaluationSpec(request.spec);
		const preflight = validateEvaluationPreflight(request.preflight);
		const binding = bindRequest(request.corpus, descriptor, spec, preflight, request.lineage);
		if (!preflight.passed) return unavailable("preflight_failed", "evaluation preflight failed");
		const checkoutRoot = await trustedCheckoutRoot(request.checkoutRoot);
		const materialized = await materializeCorpusEntry(request.corpus, checkoutRoot, request.destinationRoot);
		const collectCandidate = await request.createCandidateCollector(materialized);
		if (typeof collectCandidate !== "function") return unavailable("not_feasible", "candidate collector is unavailable");
		const result = await evaluateLocalCandidate({
			spec,
			preflight,
			lineage: request.lineage,
			adapters: request.adapters,
			collectCandidate,
			...(request.trustedOracle === undefined ? {} : { trustedOracle: request.trustedOracle }),
			...(request.requestOracle === undefined ? {} : { requestOracle: request.requestOracle }),
			...(request.signal === undefined ? {} : { signal: request.signal }),
		});
		return { status: "evaluated", scored: false, binding, result };
	} catch (error) {
		return unavailable("not_available", safeFailure(error));
	}
}

export const evaluateLocalCorpus = runLocalEvaluation;
