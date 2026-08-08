import {
	canonicalDigest,
	isDigest,
	type Digest,
} from "../../packages/coding-agent/src/ctf/contracts/digest";
import {
	validateChallengeDescriptor,
	type ChallengeDescriptor,
} from "../../packages/coding-agent/src/ctf/contracts/manifest";
import { CtfError } from "../../packages/coding-agent/src/ctf/contracts/errors";
import {
	createFixtureGraphEventWriterCapability,
	eventDigest,
	validateEvent,
} from "../../packages/coding-agent/src/ctf/contracts/event";
import {
	oracleResultDigest,
	type OracleResultV1,
} from "../../packages/coding-agent/src/ctf/contracts/oracle";
import {
	CanonicalEventLog,
	EMPTY_EVENT_DIGEST,
	type EventLogReadResult,
} from "../../packages/coding-agent/src/ctf/state/event-log";
import {
	CtfGraphProjection,
	type CtfGraphProjectionSnapshot,
} from "../../packages/coding-agent/src/ctf/graph/projection";
import {
	createCtfWorkspaceDashboardProjectionReader,
	readCtfDashboardRoute,
	readCtfDashboardSnapshot,
} from "../../packages/coding-agent/src/ctf/dashboard/projection-reader";
import type {
	CtfDashboardProjectionReadResult,
	CtfDashboardSnapshot,
} from "../../packages/coding-agent/src/ctf/dashboard/types";
import { preflightLocalExecution, validateBenchmarkCalibration, type BenchmarkCalibrationPolicy, type LocalExecutionPreflight } from "../../packages/coding-agent/src/ctf/runtime/policy";
import { validateSandboxPreflight } from "../../packages/coding-agent/src/ctf/contracts/sandbox";
import {
	trustedOracleRegistryDigest,
	verifyTrustedOracleResult,
	type TrustedOracleRegistry,
	type VerifiedOracleResult,
} from "../../packages/coding-agent/src/ctf/runtime/oracle";
import {
	metricFixtureDigest,
	summarizeMetricFixture,
	validateMetricFixture,
	type FixtureMetricSummary,
	type MetricFixture,
} from "./metrics";
import type { CtfWorkspace } from "../../packages/coding-agent/src/ctf/workspace";
import type { MetricOutcome } from "../../packages/coding-agent/src/ctf/contracts/metrics";
import type { GraphSnapshot } from "../../packages/coding-agent/src/ctf/contracts/graph";

const RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export type FixturePolicyAuthority = Readonly<{
	safetyMaxima: unknown;
	runtime: unknown;
}>;

export type FixtureOracleAuthority = Readonly<{
	registry: TrustedOracleRegistry;
	registryDigest: Digest;
	result: unknown;
}>;

/** Every authority is caller supplied; no fixture value is inferred by this harness. */
export type FixtureRunnerRequest = Readonly<{
	workspace: Pick<CtfWorkspace, "root" | "stateRoot" | "manifest">;
	runId: string;
	challengeId: string;
	occurredAt: string;
	candidateDigest: Digest;
	inputDigest: Digest;
	benchmarkLockDigest: Digest;
	calibration: unknown;
	policy: FixturePolicyAuthority;
	oracle: FixtureOracleAuthority;
	fixture: unknown;
}>;

export type FixtureDigestLineage = Readonly<{
	runId: string;
	competitionId: string;
	challengeId: string;
	candidateDigest: Digest;
	inputDigest: Digest;
	oracleRegistryDigest: Digest;
	oracleResultDigest: Digest;
	oracleOutputDigest: Digest;
	calibrationDigest: Digest;
	fixtureDigest: Digest;
	policyDigest: Digest;
	preflightDigest: Digest;
	canonicalDigest: Digest;
	projectionDigest: Digest;
	graphDigest: Digest;
}>;

export type FixtureEvidence = Readonly<{
	eventIds: readonly string[];
	evidenceRefs: readonly Digest[];
	lineage: FixtureDigestLineage;
}>;

export type FixtureReport = Readonly<{
	schemaVersion: "gjc-ctf-fixture-report-1";
	status: "ready";
	runId: string;
	challengeId: string;
	competitionId: string;
	verdict: OracleResultV1["verdict"];
	outcome: MetricOutcome;
	metricSummary: FixtureMetricSummary;
	preflight: LocalExecutionPreflight;
	dashboard: Readonly<{
		projectionStatus: "current";
		canonicalRevision: number;
		canonicalDigest: Digest;
		projectionRevision: number;
		projectionDigest: Digest;
		graphRevision: number;
		graphDigest: Digest;
	}>;
	evidence: FixtureEvidence;
}>;
export type FixturePipelineReport = FixtureReport;

export type FixtureRunnerResult =
	| Readonly<{ status: "ready"; runId: string; report: FixtureReport }>
	| Readonly<{ status: "unavailable"; runId?: string; reason: string }>;
export type FixtureResult = FixtureRunnerResult;
export type FixtureReportResult = FixtureRunnerResult;

export type FixtureReportBuilderInput = Readonly<{
	request: FixtureRunnerRequest;
	challenge: ChallengeDescriptor;
	calibration: BenchmarkCalibrationPolicy;
	fixture: MetricFixture;
	metricSummary: FixtureMetricSummary;
	preflight: LocalExecutionPreflight;
	verifiedOracle: VerifiedOracleResult;
	events: EventLogReadResult;
	projection: CtfGraphProjectionSnapshot;
	dashboard: CtfDashboardSnapshot;
	graphRoute: CtfDashboardProjectionReadResult;
}>;

function unavailable(reason: string, runId?: string): FixtureRunnerResult {
	return runId === undefined ? { status: "unavailable", reason } : { status: "unavailable", runId, reason };
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function requireDigest(value: unknown, label: string): Digest {
	if (!isDigest(value)) throw new CtfError("benchmark_provenance_missing", `${label} is missing or invalid`);
	return value;
}

function requireId(value: unknown, label: string): string {
	if (typeof value !== "string" || value.length > 256 || !RUN_ID_PATTERN.test(value)) throw new CtfError("benchmark_provenance_missing", `${label} is missing or invalid`);
	return value;
}

function requireTimestamp(value: unknown): string {
	if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
		throw new CtfError("benchmark_provenance_missing", "fixture event timestamp is missing or invalid");
	}
	return value;
}

function expectedOutcome(verdict: OracleResultV1["verdict"]): MetricOutcome {
	switch (verdict) {
		case "pass": return "pass";
		case "fail": return "fail";
		case "invalid": return "invalid";
		case "error": return "unknown";
	}
}

function terminalState(verdict: OracleResultV1["verdict"]): "solved" | "failed" | "blocked" {
	if (verdict === "pass") return "solved";
	if (verdict === "error") return "blocked";
	return "failed";
}

function graphFromRoute(value: CtfDashboardProjectionReadResult): { graph: GraphSnapshot; graphRevision: number; graphDigest: Digest; canonicalRevision: number; canonicalDigest: Digest } | undefined {
	const object = objectValue(value);
	if (object === undefined) return undefined;
	const graph = object.graph;
	const checkpoint = object.checkpoint;
	const checkpointObject = objectValue(checkpoint);
	if (graph === undefined || checkpointObject === undefined) return undefined;
	const graphObject = objectValue(graph);
	if (graphObject === undefined || typeof graphObject.revision !== "number" || !isDigest(graphObject.digest)) return undefined;
	if (typeof checkpointObject.graphRevision !== "number" || !isDigest(checkpointObject.graphDigest) || typeof checkpointObject.canonicalRevision !== "number" || !isDigest(checkpointObject.canonicalDigest)) return undefined;
	return {
		graph: graph as GraphSnapshot,
		graphRevision: graphObject.revision,
		graphDigest: graphObject.digest,
		canonicalRevision: checkpointObject.canonicalRevision,
		canonicalDigest: checkpointObject.canonicalDigest,
	};
}

function validateBuilderEvidence(input: FixtureReportBuilderInput): FixtureDigestLineage {
	const request = input.request;
	const runId = requireId(request.runId, "fixture run ID");
	const challengeId = requireId(request.challengeId, "fixture challenge ID");
	if (runId.length > 240) throw new CtfError("benchmark_provenance_missing", "fixture run ID is too long for deterministic event identities");
	const competitionId = requireId(input.challenge.id === challengeId ? request.workspace.manifest.competitionId : "", "fixture competition ID");
	const challenge = validateChallengeDescriptor(input.challenge);
	if (challenge.id !== challengeId || challenge.oracleId.length === 0 || challenge.trustLevel !== "fixture" || challenge.executionClass !== "static" || challenge.networkMode !== "off") throw new CtfError("unsafe_sandbox", "fixture challenge evidence is not static and offline");
	const registeredChallenge = request.workspace.manifest.challenges.find(candidate => candidate.id === challengeId);
	if (registeredChallenge === undefined || canonicalDigest(validateChallengeDescriptor(registeredChallenge)) !== canonicalDigest(challenge)) throw new CtfError("integrity_error", "fixture challenge evidence is not the registered authority");
	const calibration = validateBenchmarkCalibration(input.calibration);
	if (calibration.calibrationDigest !== input.calibration.calibrationDigest || calibration.calibrationId !== challenge.calibrationId || calibration.operationalLimitsDigest !== challenge.limits.limitsDigest) {
		throw new CtfError("uncalibrated_limits", "fixture calibration evidence is invalid");
	}
	validateSandboxPreflight(input.preflight.preflight);
	const expectedPreflight = preflightLocalExecution({
		executionClass: "fixture/static",
		safetyMaxima: request.policy.safetyMaxima,
		runtime: request.policy.runtime,
		executeRequested: false,
	});
	if (canonicalDigest(expectedPreflight) !== canonicalDigest(input.preflight)) throw new CtfError("unsafe_sandbox", "fixture preflight evidence is not derived from the supplied policy");
	const policyDigest = requireDigest(input.preflight.safety.policyDigest, "fixture safety policy digest");
	if (policyDigest !== challenge.safetyPolicyDigest) throw new CtfError("unsafe_sandbox", "fixture safety policy evidence is detached from the challenge");
	const preflightDigest = canonicalDigest(input.preflight.preflight);
	const recomputedSummary = summarizeMetricFixture(input.fixture);
	if (canonicalDigest(recomputedSummary) !== canonicalDigest(input.metricSummary)) throw new CtfError("missing_evidence", "fixture metric summary is not derived from the fixture");
	const candidateDigest = requireDigest(request.candidateDigest, "candidate digest");
	const inputDigest = requireDigest(request.inputDigest, "oracle input digest");
	const benchmarkLockDigest = requireDigest(request.benchmarkLockDigest, "benchmark lock digest");
	if (input.fixture.benchmarkLockDigest !== benchmarkLockDigest) throw new CtfError("benchmark_lock_mismatch", "fixture benchmark lock lineage does not match the request");
	if (input.fixture.runs.length !== 1 || input.fixture.runs[0]?.runId !== runId || input.fixture.runs[0]?.challengeId !== challengeId) {
		throw new CtfError("benchmark_provenance_missing", "fixture must contain exactly one run with the requested identity");
	}
	if (input.metricSummary.fixture.fixtureDigest !== metricFixtureDigest(input.fixture)) throw new CtfError("digest_mismatch", "fixture digest is invalid");
	if (calibration.selectedFor !== "fixture") throw new CtfError("uncalibrated_limits", "fixture calibration must be explicitly selected for fixtures");
	if (input.preflight.preflight.passed !== true || input.preflight.preflight.executionClass !== "fixture/static") throw new CtfError("unsafe_sandbox", "fixture policy preflight did not pass as static");
	if (input.verifiedOracle.verified !== true) throw new CtfError("oracle_integrity_error", "oracle evidence is not verified");
	const oracle = input.verifiedOracle.result;
	const nonce = requireId(objectValue(request.oracle.result)?.nonce, "oracle nonce");
	const reverifiedOracle = verifyTrustedOracleResult(request.oracle.registry, request.oracle.result, {
		runId,
		challengeId,
		nonce,
		candidateDigest,
		inputDigest,
	});
	if (reverifiedOracle.registryDigest !== input.verifiedOracle.registryDigest || oracleResultDigest(reverifiedOracle.result) !== oracleResultDigest(oracle)) {
		throw new CtfError("oracle_integrity_error", "signed oracle evidence changed between verification stages");
	}
	if (oracle.runId !== runId || oracle.challengeId !== challengeId || oracle.oracleId !== challenge.oracleId || oracle.candidateDigest !== candidateDigest || oracle.inputDigest !== inputDigest) {
		throw new CtfError("oracle_integrity_error", "oracle evidence identity does not match the fixture run");
	}
	const oracleDigest = oracleResultDigest(oracle);
	const registryDigest = requireDigest(input.verifiedOracle.registryDigest, "oracle registry digest");
	if (registryDigest !== request.oracle.registryDigest) throw new CtfError("oracle_integrity_error", "oracle registry digest lineage is invalid");
	const outputDigest = requireDigest(oracle.outputDigest, "oracle output digest");
	const events = input.events.events;
	if (input.events.complete !== true || !Number.isSafeInteger(input.events.revision) || input.events.revision !== events.length) throw new CtfError("integrity_error", "canonical event log completeness metadata is invalid");
	let previousEventDigest = EMPTY_EVENT_DIGEST;
	for (const [index, value] of events.entries()) {
		const event = validateEvent(value);
		if (event.revision !== index + 1 || event.previousRevision !== index || event.previousEventDigest !== previousEventDigest) {
			throw new CtfError("integrity_error", "canonical event hash chain is invalid");
		}
		previousEventDigest = eventDigest(event);
	}
	if (previousEventDigest !== input.events.digest) throw new CtfError("integrity_error", "canonical event digest does not match the verified head");
	if (events.length === 0 || events.some(event => event.runId !== runId || event.competitionId !== competitionId || event.challengeId !== challengeId)) {
		throw new CtfError("integrity_error", "canonical event log does not preserve one run identity");
	}
	if (events.length !== 3 || events.map(event => event.eventId).join("|") !== `${runId}:created|${runId}:oracle|${runId}:terminal` || events.map(event => event.eventType).join("|") !== "run_created|node_transition|run_terminal") {
		throw new CtfError("integrity_error", "canonical event log does not preserve the fixture event sequence");
	}
	const last = events.at(-1);
	if (last === undefined || !isDigest(input.events.digest) || canonicalDigest(last) !== input.events.digest) {
		throw new CtfError("integrity_error", "canonical event log digest is unavailable");
	}
	const eventDigests = events.flatMap(event => event.evidenceRefs);
	for (const digest of eventDigests) requireDigest(digest, "event evidence reference");
	const requiredRefs = [inputDigest, outputDigest, oracleDigest, calibration.calibrationDigest, input.fixture.fixtureDigest, policyDigest, preflightDigest] as const;
	for (const digest of requiredRefs) if (!eventDigests.includes(digest)) throw new CtfError("missing_provenance", "canonical event evidence references are incomplete");
	const routeGraph = graphFromRoute(input.graphRoute);
	if (routeGraph === undefined) throw new CtfError("integrity_error", "dashboard graph evidence is unavailable");
	if (routeGraph.canonicalRevision !== input.events.revision || routeGraph.canonicalDigest !== input.events.digest) throw new CtfError("integrity_error", "graph checkpoint is detached from canonical event lineage");
	if (routeGraph.graphRevision !== input.projection.projectionRevision || routeGraph.graphDigest !== input.projection.graph?.digest) throw new CtfError("integrity_error", "graph projection lineage is invalid");
	if (!routeGraph.graph.nodes.some(node => node.nodeId === `${runId}:oracle` && node.provenance.challengeId === challengeId && node.evidenceRefs.includes(outputDigest))) {
		throw new CtfError("missing_evidence", "graph projection does not contain the verified oracle evidence");
	}
	const dashboardCanonical = input.dashboard.canonical;
	const dashboardProjection = input.dashboard.projection;
	if (input.dashboard.projectionStatus !== "current" || dashboardCanonical.status !== "available" || dashboardProjection.status !== "available") throw new CtfError("integrity_error", "dashboard evidence is not current");
	const projectionMetadata = dashboardProjection.metadata;
	if (projectionMetadata === undefined || typeof projectionMetadata.projectionRevision !== "number" || !isDigest(projectionMetadata.projectionDigest)) {
		throw new CtfError("integrity_error", "dashboard projection metadata is unavailable");
	}
	if (dashboardCanonical.metadata.canonicalDigest !== input.events.digest || dashboardCanonical.metadata.canonicalRevision !== input.events.revision) throw new CtfError("integrity_error", "dashboard canonical metadata is detached");
	if (projectionMetadata.projectionDigest !== input.events.digest || projectionMetadata.projectionRevision !== input.events.revision) throw new CtfError("integrity_error", "dashboard projection metadata is detached");
	return {
		runId,
		competitionId,
		challengeId,
		candidateDigest,
		inputDigest,
		oracleRegistryDigest: registryDigest,
		oracleResultDigest: oracleDigest,
		oracleOutputDigest: outputDigest,
		calibrationDigest: calibration.calibrationDigest,
		fixtureDigest: input.fixture.fixtureDigest,
		policyDigest,
		preflightDigest,
		canonicalDigest: input.events.digest,
		projectionDigest: projectionMetadata.projectionDigest,
		graphDigest: routeGraph.graphDigest,
	};
}

/** Build a report only from verified stage evidence; invalid or incomplete input is unavailable. */
export function buildFixtureReport(input: FixtureReportBuilderInput): FixtureRunnerResult {
	try {
		const lineage = validateBuilderEvidence(input);
		const run = input.fixture.runs[0];
		if (run === undefined) throw new CtfError("benchmark_provenance_missing", "fixture run is missing");
		const verdict = input.verifiedOracle.result.verdict;
		const outcome = expectedOutcome(verdict);
		if (run.outcome !== outcome || run.validatedSolve !== (outcome === "pass")) {
			throw new CtfError("oracle_integrity_error", "metric outcome does not preserve the verified oracle verdict");
		}
		const graph = graphFromRoute(input.graphRoute);
		if (graph === undefined) throw new CtfError("integrity_error", "graph evidence is unavailable");
		const projection = input.dashboard.projection;
		if (projection.status !== "available") throw new CtfError("integrity_error", "dashboard projection metadata is unavailable");
		const projectionMetadata = projection.metadata;
		const report: FixtureReport = Object.freeze({
			schemaVersion: "gjc-ctf-fixture-report-1",
			status: "ready",
			runId: lineage.runId,
			challengeId: lineage.challengeId,
			competitionId: lineage.competitionId,
			verdict,
			outcome,
			metricSummary: input.metricSummary,
			preflight: input.preflight,
			dashboard: {
				projectionStatus: "current" as const,
				canonicalRevision: input.events.revision,
				canonicalDigest: lineage.canonicalDigest,
				projectionRevision: projectionMetadata.projectionRevision,
				projectionDigest: lineage.projectionDigest,
				graphRevision: graph.graphRevision,
				graphDigest: lineage.graphDigest,
			},
			evidence: {
				eventIds: input.events.events.map(event => event.eventId),
				evidenceRefs: [...new Set(input.events.events.flatMap(event => event.evidenceRefs))].map(ref =>
					requireDigest(ref, "event evidence digest"),
				),
				lineage,
			},
		});
		return { status: "ready", runId: lineage.runId, report };
	} catch (error) {
		const request = objectValue(objectValue(input)?.request);
		const runId = typeof request?.runId === "string" ? request.runId : undefined;
		return unavailable(error instanceof Error ? error.message : "fixture report evidence is unavailable", runId);
	}
}
export const buildFixture = buildFixtureReport;

function validateRequest(request: FixtureRunnerRequest): {
	challenge: ChallengeDescriptor;
	calibration: BenchmarkCalibrationPolicy;
	fixture: MetricFixture;
	preflight: LocalExecutionPreflight;
	verifiedOracle: VerifiedOracleResult;
} {
	if (!request || typeof request !== "object") throw new CtfError("benchmark_provenance_missing", "fixture runner request is missing");
	const runId = requireId(request.runId, "fixture run ID");
	if (runId.length > 240) throw new CtfError("benchmark_provenance_missing", "fixture run ID is too long for deterministic event identities");
	const challengeId = requireId(request.challengeId, "fixture challenge ID");
	requireTimestamp(request.occurredAt);
	const candidateDigest = requireDigest(request.candidateDigest, "candidate digest");
	const inputDigest = requireDigest(request.inputDigest, "oracle input digest");
	const benchmarkLockDigest = requireDigest(request.benchmarkLockDigest, "benchmark lock digest");
	const workspace = request.workspace;
	if (!workspace || typeof workspace.root !== "string" || typeof workspace.stateRoot !== "string" || !workspace.manifest) throw new CtfError("benchmark_provenance_missing", "fixture workspace authority is missing");
	const competitionId = requireId(workspace.manifest.competitionId, "fixture competition ID");
	if (request.challengeId !== challengeId || !Array.isArray(workspace.manifest.challenges)) throw new CtfError("benchmark_provenance_missing", "fixture challenge authority is missing");
	const rawChallenge = workspace.manifest.challenges.find(candidate => candidate.id === challengeId);
	if (rawChallenge === undefined) throw new CtfError("benchmark_provenance_missing", "fixture challenge is not registered");
	const challenge = validateChallengeDescriptor(rawChallenge);
	if (challenge.trustLevel !== "fixture" || challenge.executionClass !== "static" || challenge.networkMode !== "off") throw new CtfError("unsafe_sandbox", "fixture challenge is not a static offline fixture");
	const calibration = validateBenchmarkCalibration(request.calibration);
	if (calibration.selectedFor !== "fixture" || calibration.calibrationId !== challenge.calibrationId || calibration.operationalLimitsDigest !== challenge.limits.limitsDigest) throw new CtfError("uncalibrated_limits", "fixture calibration does not match the registered challenge");
	const fixture = validateMetricFixture(request.fixture);
	if (fixture.benchmarkLockDigest !== benchmarkLockDigest || fixture.runs.length !== 1 || fixture.runs[0]?.runId !== runId || fixture.runs[0]?.challengeId !== challengeId) throw new CtfError("benchmark_provenance_missing", "fixture metric evidence does not match the run identity");
	const policy = request.policy;
	if (!policy || typeof policy !== "object" || policy.safetyMaxima === undefined || policy.runtime === undefined) throw new CtfError("unsafe_sandbox", "fixture runtime policy authority is missing");
	const preflight = preflightLocalExecution({
		executionClass: "fixture/static",
		safetyMaxima: policy.safetyMaxima,
		runtime: policy.runtime,
		executeRequested: false,
	});
	if (preflight.safety.policyDigest !== challenge.safetyPolicyDigest) throw new CtfError("unsafe_sandbox", "fixture safety policy does not match the challenge authority");
	const oracle = request.oracle;
	if (!oracle || typeof oracle !== "object" || !oracle.registry || !isDigest(oracle.registryDigest) || oracle.result === undefined) throw new CtfError("oracle_integrity_error", "signed fixture oracle authority is missing");
	const registryDigest = trustedOracleRegistryDigest(oracle.registry);
	if (registryDigest !== oracle.registryDigest) throw new CtfError("oracle_integrity_error", "trusted oracle registry digest does not match the supplied authority");
	const verifiedOracle = verifyTrustedOracleResult(oracle.registry, oracle.result, {
		runId,
		challengeId,
		nonce: requireId((objectValue(oracle.result)?.nonce), "oracle nonce"),
		candidateDigest,
		inputDigest,
	});
	if (verifiedOracle.result.oracleId !== challenge.oracleId) throw new CtfError("oracle_integrity_error", "oracle result does not match the registered challenge oracle");
	return { challenge, calibration, fixture, preflight, verifiedOracle };
}

/** Run the local, non-executing fixture pipeline and return a structured report or an explicit unavailable result. */
export async function runFixture(request: FixtureRunnerRequest): Promise<FixtureRunnerResult> {
	const runId = typeof request?.runId === "string" ? request.runId : undefined;
	try {
		const checked = validateRequest(request);
		const workspace = request.workspace;
		const eventLog = new CanonicalEventLog(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: request.challengeId,
		});
		const existing = await eventLog.read();
		if (existing.events.some(event => event.runId !== request.runId || event.competitionId !== workspace.manifest.competitionId || event.challengeId !== request.challengeId)) {
			throw new CtfError("cross_challenge_reference", "fixture event log contains another run or challenge");
		}
		const oracle = checked.verifiedOracle.result;
		const oracleDigest = oracleResultDigest(oracle);
		const policyDigest = checked.preflight.safety.policyDigest;
		const preflightDigest = canonicalDigest(checked.preflight.preflight);
		const evidenceRefs = [request.inputDigest, oracle.outputDigest, oracleDigest, checked.calibration.calibrationDigest, checked.fixture.fixtureDigest, policyDigest, preflightDigest] as Digest[];
		const node = {
			nodeId: `${request.runId}:oracle`,
			type: "Evidence" as const,
			state: "observed" as const,
			confidence: 1,
			evidenceRefs: [oracle.outputDigest, request.inputDigest, oracleDigest, policyDigest, preflightDigest],
			provenance: {
				challengeId: request.challengeId,
				source: "fixture-oracle",
				actor: checked.verifiedOracle.entry.oracleId,
				digest: oracle.outputDigest,
			},
			createdRevision: 2,
			updatedRevision: 2,
		};
		await eventLog.appendDraft({
			eventId: `${request.runId}:created`,
			eventType: "run_created",
			competitionId: workspace.manifest.competitionId,
			challengeId: request.challengeId,
			runId: request.runId,
			idempotencyKey: `${request.runId}:created`,
			actor: "fixture-runner",
			occurredAt: request.occurredAt,
			payload: {
				fixtureId: checked.fixture.fixtureId,
				candidateDigest: request.candidateDigest,
				inputDigest: request.inputDigest,
				oracleRegistryDigest: checked.verifiedOracle.registryDigest,
				calibrationDigest: checked.calibration.calibrationDigest,
				fixtureDigest: checked.fixture.fixtureDigest,
				safetyPolicyDigest: policyDigest,
				preflightDigest,
			},
			evidenceRefs,
		});
		await eventLog.appendDraft(
			{
				eventId: `${request.runId}:oracle`,
				eventType: "node_transition",
				competitionId: workspace.manifest.competitionId,
				challengeId: request.challengeId,
				runId: request.runId,
				idempotencyKey: `${request.runId}:oracle`,
				actor: checked.verifiedOracle.entry.oracleId,
				occurredAt: request.occurredAt,
				payload: { fencingToken: 0, after: node },
				evidenceRefs,
			},
			undefined,
			undefined,
			createFixtureGraphEventWriterCapability({
				competitionId: workspace.manifest.competitionId,
				challengeId: request.challengeId,
				runId: request.runId,
				actor: checked.verifiedOracle.entry.oracleId,
			}),
		);
		await eventLog.appendDraft({
			eventId: `${request.runId}:terminal`,
			eventType: "run_terminal",
			competitionId: workspace.manifest.competitionId,
			challengeId: request.challengeId,
			runId: request.runId,
			idempotencyKey: `${request.runId}:terminal`,
			actor: "fixture-runner",
			occurredAt: request.occurredAt,
			payload: {
				state: terminalState(oracle.verdict),
				verdict: oracle.verdict,
				outcome: checked.fixture.runs[0]?.outcome,
				oracleResultDigest: oracleResultDigest(oracle),
				outputDigest: oracle.outputDigest,
				safetyPolicyDigest: policyDigest,
				preflightDigest,
			},
			evidenceRefs,
		});
		const events = await eventLog.read();
		const projection = new CtfGraphProjection(eventLog);
		const projectionSnapshot = await projection.rebuild();
		if (projectionSnapshot.projectionStatus !== "current" || projectionSnapshot.graph === undefined) throw new CtfError("integrity_error", "fixture graph projection is not current");
		const reader = createCtfWorkspaceDashboardProjectionReader(workspace, projection);
		const dashboard = await readCtfDashboardSnapshot(reader, { competitionId: workspace.manifest.competitionId, challengeId: request.challengeId });
		const graphRoute = await readCtfDashboardRoute(reader, { kind: "challenge-graph", challengeId: request.challengeId, revision: projectionSnapshot.graph.revision });
		const metricSummary = summarizeMetricFixture(checked.fixture);
		return buildFixtureReport({
			request,
			challenge: checked.challenge,
			calibration: checked.calibration,
			fixture: checked.fixture,
			metricSummary,
			preflight: checked.preflight,
			verifiedOracle: checked.verifiedOracle,
			events,
			projection: projectionSnapshot,
			dashboard,
			graphRoute,
		});
	} catch (error) {
		return unavailable(error instanceof Error ? error.message : "fixture pipeline is unavailable", runId);
	}
}

export const buildFixtureResult = runFixture;

export function fixtureReportDigest(report: FixtureReport): Digest {
	return canonicalDigest(report);
}

export const runLocalFixture = runFixture;
