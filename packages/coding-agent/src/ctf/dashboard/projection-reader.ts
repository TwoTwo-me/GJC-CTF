import * as path from "node:path";
import { type Digest, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import { CtfGraphProjection } from "../graph/projection";
import { type CtfWorkspace, readCtfManifest } from "../workspace";
import {
	CTF_DASHBOARD_UNKNOWN_DIGEST,
	type CtfCanonicalMetadata,
	type CtfCanonicalMetadataReadResult,
	type CtfDashboardMetadataScope,
	type CtfDashboardProjectionFailure,
	type CtfDashboardProjectionReader,
	type CtfDashboardProjectionReadResult,
	type CtfDashboardProjectionStatus,
	type CtfDashboardRoute,
	type CtfDashboardSnapshot,
	type CtfDashboardStateIdentity,
	type CtfProjectionMetadata,
	type CtfProjectionMetadataReadResult,
	sanitizeCtfDashboardErrorDetails,
	sanitizeCtfDashboardErrorMessage,
} from "./types";

function failure<S extends "unavailable" | "integrity_error" | "rebuilding">(
	status: S,
	code: string,
	message: string,
	details?: Record<string, unknown>,
): { status: S; code: string; message: string; details?: Record<string, unknown> } {
	const safeDetails = sanitizeCtfDashboardErrorDetails(details);
	return {
		status,
		code,
		message: sanitizeCtfDashboardErrorMessage(message, "CTF dashboard projection request failed"),
		...(safeDetails === undefined ? {} : { details: safeDetails }),
	};
}

function asSafeRevision(value: unknown): number | undefined {
	return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function validDigest(value: unknown): value is Digest {
	return isDigest(value);
}

function validateCanonicalMetadata(value: CtfCanonicalMetadata): CtfCanonicalMetadataReadResult {
	if (
		typeof value.canonicalRevision !== "number" ||
		!Number.isSafeInteger(value.canonicalRevision) ||
		value.canonicalRevision < 0 ||
		!validDigest(value.canonicalDigest)
	) {
		return failure(
			"integrity_error",
			"canonical_metadata_invalid",
			"canonical metadata has an invalid revision or digest",
		);
	}
	if (value.benchmarkLockDigest !== undefined && !validDigest(value.benchmarkLockDigest)) {
		return failure("integrity_error", "canonical_metadata_invalid", "canonical benchmark lock digest is invalid");
	}
	if (value.effectiveSkillDigest !== undefined && !validDigest(value.effectiveSkillDigest)) {
		return failure("integrity_error", "canonical_metadata_invalid", "canonical effective skill digest is invalid");
	}
	if (value.checkpointDigest !== undefined && !validDigest(value.checkpointDigest)) {
		return failure("integrity_error", "canonical_metadata_invalid", "canonical checkpoint digest is invalid");
	}
	if (value.journalByteOffset !== undefined && asSafeRevision(value.journalByteOffset) === undefined) {
		return failure("integrity_error", "canonical_metadata_invalid", "canonical journal offset is invalid");
	}
	return { status: "available", metadata: value };
}

function validateProjectionMetadata(value: CtfProjectionMetadata): CtfProjectionMetadataReadResult {
	if (asSafeRevision(value.projectionRevision) === undefined || !validDigest(value.projectionDigest)) {
		return failure(
			"integrity_error",
			"projection_metadata_invalid",
			"projection metadata has an invalid revision or digest",
		);
	}
	return { status: "available", metadata: value };
}

function normalizeCanonicalResult(value: CtfCanonicalMetadataReadResult): CtfCanonicalMetadataReadResult {
	if (value.status !== "available") return value;
	return validateCanonicalMetadata(value.metadata);
}

function normalizeProjectionResult(value: CtfProjectionMetadataReadResult): CtfProjectionMetadataReadResult {
	if (value.status !== "available") return value;
	return validateProjectionMetadata(value.metadata);
}

function thrownMetadataFailure(
	kind: "canonical" | "projection",
	_error: unknown,
): CtfCanonicalMetadataReadResult | CtfProjectionMetadataReadResult {
	return failure("integrity_error", `${kind}_metadata_read_failed`, `${kind} metadata could not be verified`);
}

function scopeMatches(scope: CtfDashboardMetadataScope | undefined, metadata: CtfCanonicalMetadata): boolean {
	if (!scope) return true;
	if (scope.competitionId !== undefined && metadata.competitionId !== scope.competitionId) return false;
	if (scope.challengeId !== undefined && metadata.challengeId !== scope.challengeId) return false;
	if (scope.runId !== undefined && metadata.runId !== scope.runId) return false;
	return true;
}

/** Compute health without treating projection metadata as canonical authority. */
export function deriveCtfDashboardProjectionStatus(
	canonical: CtfCanonicalMetadataReadResult,
	projection: CtfProjectionMetadataReadResult,
): CtfDashboardProjectionStatus {
	if (canonical.status !== "available") return "integrity_error";
	if (projection.status === "integrity_error" || projection.status === "unavailable") return "integrity_error";
	if (projection.status === "rebuilding") return "rebuilding";
	if (projection.status !== "available") return "integrity_error";
	if (canonical.metadata.canonicalRevision === 0 || projection.metadata.projectionRevision === 0)
		return "integrity_error";
	if (
		canonical.metadata.canonicalDigest === CTF_DASHBOARD_UNKNOWN_DIGEST ||
		projection.metadata.projectionDigest === CTF_DASHBOARD_UNKNOWN_DIGEST
	)
		return "integrity_error";
	const canonicalRevision = canonical.metadata.canonicalRevision;
	const projectionRevision = projection.metadata.projectionRevision;
	if (projectionRevision < canonicalRevision) return "lagging";
	if (
		projectionRevision !== canonicalRevision ||
		projection.metadata.projectionDigest !== canonical.metadata.canonicalDigest
	) {
		return "integrity_error";
	}
	return "current";
}
/**
 * Read the two metadata sources independently. The derived graph state is not
 * consulted for canonical revision/digest, and exceptions become typed integrity failures.
 */
export async function readCtfDashboardSnapshot(
	reader: CtfDashboardProjectionReader,
	scope?: CtfDashboardMetadataScope,
): Promise<CtfDashboardSnapshot> {
	let canonical: CtfCanonicalMetadataReadResult;
	try {
		canonical = normalizeCanonicalResult(await reader.readCanonicalMetadata(scope));
	} catch (error) {
		canonical = thrownMetadataFailure("canonical", error) as CtfCanonicalMetadataReadResult;
	}

	let projection: CtfProjectionMetadataReadResult;
	try {
		projection = normalizeProjectionResult(await reader.readProjectionMetadata(scope));
	} catch (error) {
		projection = thrownMetadataFailure("projection", error) as CtfProjectionMetadataReadResult;
	}

	if (canonical.status === "available" && !scopeMatches(scope, canonical.metadata)) {
		canonical = failure(
			"integrity_error",
			"canonical_identity_mismatch",
			"canonical metadata identity does not match the requested resource",
		);
	}
	return {
		canonical,
		projection,
		projectionStatus: deriveCtfDashboardProjectionStatus(canonical, projection),
	};
}

/**
 * A workspace-backed reader derives canonical metadata from the event-log head
 * and graph data from the corresponding projection. A caller can provide an
 * owned projection; otherwise one is rooted at the workspace state root.
 */
export interface CtfWorkspaceDashboardProjectionReaderOptions {
	projection?: CtfGraphProjection;
	benchmarkLockDigest?: Digest;
}

type WorkspaceProjectionInput = CtfGraphProjection | CtfWorkspaceDashboardProjectionReaderOptions;

function isGraphProjection(value: unknown): value is CtfGraphProjection {
	return (
		typeof value === "object" &&
		value !== null &&
		"eventLog" in value &&
		typeof (value as { refresh?: unknown }).refresh === "function"
	);
}

function projectionBindingMismatch(
	workspace: Pick<CtfWorkspace, "stateRoot" | "manifest">,
	projection: CtfGraphProjection,
): boolean {
	const identity = projection.eventLog?.identity;
	if (identity?.competitionId !== undefined && identity.competitionId !== workspace.manifest.competitionId) {
		return true;
	}
	const root = projection.eventLog?.store?.root;
	if (typeof root === "string" && path.resolve(root) !== path.resolve(workspace.stateRoot)) return true;
	return false;
}

export function createCtfWorkspaceDashboardProjectionReader(
	workspace: Pick<CtfWorkspace, "root" | "stateRoot" | "manifest">,
	projection?: CtfGraphProjection,
): CtfDashboardProjectionReader;
export function createCtfWorkspaceDashboardProjectionReader(
	workspace: Pick<CtfWorkspace, "root" | "stateRoot" | "manifest">,
	options?: CtfWorkspaceDashboardProjectionReaderOptions,
): CtfDashboardProjectionReader;
export function createCtfWorkspaceDashboardProjectionReader(
	workspace: Pick<CtfWorkspace, "root" | "stateRoot" | "manifest">,
	projectionOrOptions?: WorkspaceProjectionInput,
): CtfDashboardProjectionReader {
	const options = isGraphProjection(projectionOrOptions) ? undefined : projectionOrOptions;
	const injectedProjection = isGraphProjection(projectionOrOptions) ? projectionOrOptions : options?.projection;
	const projection =
		injectedProjection ??
		new CtfGraphProjection(workspace.stateRoot, {
			identity: { competitionId: workspace.manifest.competitionId },
		});
	const challengeProjections = injectedProjection === undefined ? new Map<string, CtfGraphProjection>() : undefined;
	const projectionForChallenge = (challengeId: string): CtfGraphProjection => {
		if (challengeProjections === undefined) return projection;
		const cached = challengeProjections.get(challengeId);
		if (cached !== undefined) return cached;
		const challengeProjection = new CtfGraphProjection(workspace.stateRoot, {
			identity: { competitionId: workspace.manifest.competitionId, challengeId },
		});
		challengeProjections.set(challengeId, challengeProjection);
		return challengeProjection;
	};
	const projectionForScope = (scope?: CtfDashboardMetadataScope): CtfGraphProjection =>
		scope?.challengeId === undefined ? projection : projectionForChallenge(scope.challengeId);
	const projectionBindingFailure = (source: CtfGraphProjection, challengeId?: string): boolean => {
		if (injectedProjection !== undefined && projectionBindingMismatch(workspace, injectedProjection)) return true;
		const identityChallengeId = source.eventLog?.identity?.challengeId;
		return identityChallengeId !== undefined && identityChallengeId !== challengeId;
	};
	const injectedChallengeId = injectedProjection?.eventLog.identity.challengeId;
	const stateIdentity: CtfDashboardStateIdentity = {
		competitionId: workspace.manifest.competitionId,
		stateRoot: workspace.stateRoot,
		...(injectedChallengeId === undefined ? {} : { challengeId: injectedChallengeId }),
	};

	const manifestMetadata = (manifest: CtfWorkspace["manifest"], challengeId?: string): CtfCanonicalMetadata => ({
		competitionId: manifest.competitionId,
		...(challengeId === undefined ? {} : { challengeId }),
		canonicalRevision: manifest.manifestRevision,
		canonicalDigest: manifest.manifestDigest as Digest,
		...(options?.benchmarkLockDigest === undefined ? {} : { benchmarkLockDigest: options.benchmarkLockDigest }),
		...(manifest.skill?.digest === undefined ? {} : { effectiveSkillDigest: manifest.skill.digest as Digest }),
	});
	const safePublicMessage = (error: unknown, fallback: string): string => {
		const message = error instanceof Error ? error.message : String(error);
		return sanitizeCtfDashboardErrorMessage(message, fallback);
	};

	const projectionFailure = (
		snapshot: ReturnType<CtfGraphProjection["snapshot"]>,
		status: "unavailable" | "integrity_error" | "rebuilding",
		code: string,
		message: string,
		details?: Record<string, unknown>,
	): CtfDashboardProjectionFailure => {
		const safeDetails = sanitizeCtfDashboardErrorDetails(details);
		return {
			status,
			code,
			message: sanitizeCtfDashboardErrorMessage(message, "CTF projection state could not be read"),
			...(safeDetails === undefined ? {} : { details: safeDetails }),
			metadata: {
				projectionRevision: snapshot.projectionRevision,
				projectionDigest: snapshot.projectionDigest,
			},
		};
	};

	const canonicalEventLog = (source: CtfGraphProjection) => {
		const eventLog = source.eventLog;
		if (eventLog === undefined || typeof eventLog.read !== "function") {
			throw new CtfError("integrity_error", "CTF canonical event log is not connected");
		}
		return eventLog;
	};

	const readCanonicalHead = async (source: CtfGraphProjection) => {
		const eventLog = canonicalEventLog(source);
		const head = await eventLog.read();
		if (
			eventLog.identity.competitionId !== undefined &&
			eventLog.identity.competitionId !== workspace.manifest.competitionId
		) {
			throw new CtfError(
				"cross_challenge_reference",
				"canonical event log competition does not match the workspace",
			);
		}
		return head;
	};

	const canonicalFailure = (
		status: "unavailable" | "integrity_error",
		code: string,
		message: string,
		details?: Record<string, unknown>,
		metadata?: Partial<CtfCanonicalMetadata>,
	): CtfCanonicalMetadataReadResult => {
		const safeDetails = sanitizeCtfDashboardErrorDetails(details);
		return {
			status,
			code,
			message: sanitizeCtfDashboardErrorMessage(message, "CTF canonical metadata could not be verified"),
			...(safeDetails === undefined ? {} : { details: safeDetails }),
			...(metadata === undefined ? {} : { metadata }),
		};
	};

	const projectionMetadataFailure = (
		status: "unavailable" | "integrity_error",
		code: string,
		message: string,
		details?: Record<string, unknown>,
		metadata?: Partial<CtfProjectionMetadata>,
	): CtfProjectionMetadataReadResult => {
		const safeDetails = sanitizeCtfDashboardErrorDetails(details);
		return {
			status,
			code,
			message: sanitizeCtfDashboardErrorMessage(message, "CTF projection metadata could not be verified"),
			...(safeDetails === undefined ? {} : { details: safeDetails }),
			...(metadata === undefined ? {} : { metadata }),
		};
	};

	return {
		stateIdentity,
		async readCanonicalMetadata(scope) {
			try {
				const source = projectionForScope(scope);
				const manifest = await readCtfManifest(workspace.root);
				const fallback = manifestMetadata(manifest, source.eventLog.identity.challengeId ?? scope?.challengeId);
				if (projectionBindingFailure(source, scope?.challengeId)) {
					return canonicalFailure(
						"integrity_error",
						"projection_identity_mismatch",
						"projection identity does not match the requested workspace",
						undefined,
						fallback,
					);
				}
				if (
					scope?.challengeId !== undefined &&
					!manifest.challenges.some(challenge => challenge.id === scope.challengeId)
				) {
					return canonicalFailure(
						"unavailable",
						"challenge_not_registered",
						"requested challenge is not registered",
						{ challengeId: scope.challengeId },
					);
				}
				if (manifest.competitionId !== stateIdentity.competitionId) {
					return canonicalFailure(
						"integrity_error",
						"canonical_identity_mismatch",
						"canonical manifest competition does not match the workspace",
						{
							workspaceCompetitionId: stateIdentity.competitionId,
							manifestCompetitionId: manifest.competitionId,
						},
						fallback,
					);
				}
				const head = await readCanonicalHead(source);
				if (head.revision === 0) {
					// A manifest can identify the competition before any event exists,
					// but cannot authorize a challenge or run projection at revision zero.
					if (scope?.challengeId !== undefined || scope?.runId !== undefined) {
						return canonicalFailure(
							"unavailable",
							"canonical_event_log_unavailable",
							"CTF canonical event log has no events for the requested resource",
							{ source: "ctf-event-log", canonicalRevision: head.revision },
							{ canonicalRevision: head.revision, canonicalDigest: head.digest },
						);
					}
					return { status: "available", metadata: fallback };
				}
				const metadata: CtfCanonicalMetadata = {
					...fallback,
					canonicalRevision: head.revision,
					canonicalDigest: head.digest,
				};
				if (scope?.competitionId !== undefined && scope.competitionId !== metadata.competitionId) {
					return canonicalFailure(
						"integrity_error",
						"canonical_identity_mismatch",
						"canonical metadata identity does not match the requested competition",
						{ competitionId: metadata.competitionId, requestedCompetitionId: scope.competitionId },
						metadata,
					);
				}
				if (
					stateIdentity.challengeId !== undefined &&
					scope?.challengeId !== undefined &&
					stateIdentity.challengeId !== scope.challengeId
				) {
					return canonicalFailure(
						"integrity_error",
						"canonical_identity_mismatch",
						"canonical metadata identity does not match the requested challenge",
						undefined,
						metadata,
					);
				}
				return { status: "available", metadata };
			} catch {
				return canonicalFailure(
					"integrity_error",
					"canonical_metadata_unavailable",
					"CTF canonical event metadata could not be verified",
					{
						source: "ctf-event-log",
					},
				);
			}
		},
		async readProjectionMetadata(scope) {
			const source = projectionForScope(scope);
			if (projectionBindingFailure(source, scope?.challengeId)) {
				return failure(
					"integrity_error",
					"projection_identity_mismatch",
					"projection identity does not match the requested workspace",
				);
			}
			if (scope?.challengeId !== undefined) {
				try {
					const manifest = await readCtfManifest(workspace.root);
					if (manifest.competitionId !== stateIdentity.competitionId) {
						return failure(
							"integrity_error",
							"canonical_identity_mismatch",
							"canonical manifest competition does not match the workspace",
						);
					}
					if (!manifest.challenges.some(challenge => challenge.id === scope.challengeId)) {
						return failure("unavailable", "challenge_not_registered", "requested challenge is not registered", {
							challengeId: scope.challengeId,
						});
					}
				} catch {
					return projectionMetadataFailure(
						"unavailable",
						"canonical_metadata_unavailable",
						"CTF canonical event metadata could not be verified",
						{ source: "ctf-event-log" },
					);
				}
			}
			if (
				stateIdentity.challengeId !== undefined &&
				scope?.challengeId !== undefined &&
				stateIdentity.challengeId !== scope.challengeId
			) {
				return failure(
					"integrity_error",
					"projection_identity_mismatch",
					"projection identity does not match the requested challenge",
				);
			}
			let head: { revision: number; digest: Digest };
			try {
				head = await readCanonicalHead(source);
			} catch {
				return projectionMetadataFailure(
					"unavailable",
					"canonical_event_log_unavailable",
					"CTF canonical event log could not be read",
					{
						source: "ctf-event-log",
					},
				);
			}
			try {
				const snapshot = await source.refresh();
				if (snapshot.projectionStatus === "integrity_error") {
					return projectionFailure(
						snapshot,
						"integrity_error",
						"projection_integrity_error",
						"CTF projection state is not ready",
						{
							source: "ctf-projection",
						},
					);
				}
				if (snapshot.projectionStatus === "rebuilding") {
					return projectionFailure(
						snapshot,
						"rebuilding",
						"projection_rebuilding",
						"CTF projection is rebuilding",
						{
							source: "ctf-projection",
						},
					);
				}
				if (head.revision === 0 || snapshot.projectionRevision === 0) {
					return projectionMetadataFailure(
						"unavailable",
						"projection_revision_unavailable",
						"CTF projection has no verified event revision",
						{
							source: "ctf-projection",
							canonicalRevision: head.revision,
						},
						{
							projectionRevision: snapshot.projectionRevision,
							projectionDigest: snapshot.projectionDigest,
						},
					);
				}
				if (snapshot.canonicalRevision !== head.revision || snapshot.canonicalDigest !== head.digest) {
					return projectionFailure(
						snapshot,
						"integrity_error",
						"projection_integrity_error",
						"CTF projection canonical metadata changed during read",
						{
							source: "ctf-projection",
							canonicalRevision: head.revision,
							projectionCanonicalRevision: snapshot.canonicalRevision,
						},
					);
				}
				return normalizeProjectionResult({
					status: "available",
					metadata: {
						projectionRevision: snapshot.projectionRevision,
						projectionDigest: snapshot.projectionDigest,
					},
				});
			} catch (error) {
				const snapshot = source.snapshot();
				return projectionFailure(
					snapshot,
					"integrity_error",
					"projection_integrity_error",
					safePublicMessage(error, "CTF projection state could not be read"),
					{
						source: "ctf-projection",
					},
				);
			}
		},
		async readRoute(route) {
			if (route.kind !== "challenge-graph") {
				return failure("unavailable", "projection_unavailable", "CTF projection state is not connected", {
					source: "ctf-projection",
				});
			}
			const source = projectionForChallenge(route.challengeId);
			if (projectionBindingFailure(source, route.challengeId)) {
				return failure(
					"integrity_error",
					"projection_identity_mismatch",
					"projection identity does not match the requested workspace",
				);
			}
			try {
				const manifest = await readCtfManifest(workspace.root);
				if (manifest.competitionId !== stateIdentity.competitionId) {
					return failure(
						"integrity_error",
						"canonical_identity_mismatch",
						"canonical manifest competition does not match the workspace",
					);
				}
				if (!manifest.challenges.some(challenge => challenge.id === route.challengeId)) {
					return failure("unavailable", "challenge_not_registered", "requested challenge is not registered", {
						challengeId: route.challengeId,
					});
				}
			} catch {
				return failure(
					"unavailable",
					"canonical_metadata_unavailable",
					"CTF canonical event metadata could not be verified",
					{ source: "ctf-event-log" },
				);
			}
			if (stateIdentity.challengeId !== undefined && stateIdentity.challengeId !== route.challengeId) {
				return failure(
					"integrity_error",
					"projection_identity_mismatch",
					"projection identity does not match the requested challenge",
				);
			}
			let head: { revision: number; digest: Digest };
			try {
				head = await readCanonicalHead(source);
			} catch {
				return failure(
					"unavailable",
					"canonical_event_log_unavailable",
					"CTF canonical event log could not be read",
					{
						source: "ctf-event-log",
					},
				);
			}
			try {
				const snapshot = await source.refresh();
				if (snapshot.projectionStatus === "integrity_error") {
					return projectionFailure(
						snapshot,
						"integrity_error",
						"projection_integrity_error",
						"CTF projection state is not ready",
						{
							source: "ctf-projection",
						},
					);
				}
				if (snapshot.projectionStatus === "rebuilding") {
					return projectionFailure(
						snapshot,
						"rebuilding",
						"projection_rebuilding",
						"CTF projection is rebuilding",
						{
							source: "ctf-projection",
						},
					);
				}
				if (head.revision === 0 || snapshot.projectionRevision === 0) {
					return projectionFailure(
						snapshot,
						"unavailable",
						"projection_revision_unavailable",
						"CTF graph projection has no verified event revision",
						{
							source: "ctf-projection",
							canonicalRevision: head.revision,
						},
					);
				}
				if (snapshot.canonicalRevision !== head.revision || snapshot.canonicalDigest !== head.digest) {
					return projectionFailure(
						snapshot,
						"integrity_error",
						"projection_integrity_error",
						"CTF projection canonical metadata changed during read",
						{
							source: "ctf-projection",
						},
					);
				}
				if (snapshot.projectionStatus !== "current") {
					return failure("unavailable", "projection_lagging", "CTF projection is behind canonical state", {
						projectionRevision: snapshot.projectionRevision,
						canonicalRevision: head.revision,
					});
				}
				const graph = await source.readGraph(route.challengeId, route.revision);
				if (graph === undefined || snapshot.checkpoint === undefined)
					return failure(
						"unavailable",
						"graph_projection_unavailable",
						"CTF graph projection has no graph for the requested challenge",
					);
				return { graph, checkpoint: snapshot.checkpoint };
			} catch (error) {
				if (error instanceof CtfError && error.code === "revision_conflict") {
					return failure("unavailable", "graph_revision_unavailable", "requested graph revision is not available");
				}
				const snapshot = source.snapshot();
				return projectionFailure(
					snapshot,
					"integrity_error",
					"projection_integrity_error",
					safePublicMessage(error, "CTF graph projection could not be read"),
					{
						source: "ctf-projection",
					},
				);
			}
		},
	};
}

export const createCtfDashboardProjectionReaderFromWorkspace = createCtfWorkspaceDashboardProjectionReader;

export function projectionFailureStatus(
	value: CtfDashboardProjectionReadResult,
): "unavailable" | "integrity_error" | "rebuilding" | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	if (!("status" in value) || typeof value.status !== "string") return undefined;
	return value.status === "unavailable" || value.status === "integrity_error" || value.status === "rebuilding"
		? value.status
		: undefined;
}

export function isProjectionFailure(value: CtfDashboardProjectionReadResult): value is CtfDashboardProjectionFailure {
	return projectionFailureStatus(value) !== undefined;
}

function hasRouteMethod(reader: CtfDashboardProjectionReader, route: CtfDashboardRoute): boolean {
	if (reader.readRoute) return true;
	switch (route.kind) {
		case "competition":
			return reader.readCompetition !== undefined;
		case "challenge-status":
			return reader.readChallengeStatus !== undefined;
		case "challenge-graph":
			return reader.readChallengeGraph !== undefined;
		case "run":
			return reader.readRun !== undefined;
		case "run-events":
			return reader.readRunEvents !== undefined;
		case "run-metrics":
			return reader.readRunMetrics !== undefined;
		case "health":
			return true;
	}
}

/** Read one route only after metadata verification has established its status. */
export async function readCtfDashboardRoute(
	reader: CtfDashboardProjectionReader,
	route: CtfDashboardRoute,
): Promise<CtfDashboardProjectionReadResult> {
	if (!hasRouteMethod(reader, route))
		return failure("unavailable", "projection_reader_unavailable", "CTF projection reader is not connected");
	try {
		if (reader.readRoute) return await reader.readRoute(route);
		switch (route.kind) {
			case "competition":
				return (
					(await reader.readCompetition?.(route.competitionId)) ??
					failure("unavailable", "projection_reader_unavailable", "competition projection reader is not connected")
				);
			case "challenge-status":
				return (
					(await reader.readChallengeStatus?.(route.challengeId)) ??
					failure("unavailable", "projection_reader_unavailable", "challenge projection reader is not connected")
				);
			case "challenge-graph":
				return (
					(await reader.readChallengeGraph?.(route.challengeId, route.revision)) ??
					failure("unavailable", "projection_reader_unavailable", "graph projection reader is not connected")
				);
			case "run":
				return (
					(await reader.readRun?.(route.runId)) ??
					failure("unavailable", "projection_reader_unavailable", "run projection reader is not connected")
				);
			case "run-events":
				return (
					(await reader.readRunEvents?.(route.runId, route.cursor)) ??
					failure("unavailable", "projection_reader_unavailable", "event projection reader is not connected")
				);
			case "run-metrics":
				return (
					(await reader.readRunMetrics?.(route.runId)) ??
					failure("unavailable", "projection_reader_unavailable", "metrics projection reader is not connected")
				);
		}
	} catch {
		return failure("integrity_error", "projection_read_failed", "CTF projection data could not be read");
	}
}

/** Explicit default used until the state writer supplies a real reader. */
export function createUnavailableCtfDashboardProjectionReader(
	reason = "CTF canonical state is not connected",
	stateIdentity?: CtfDashboardStateIdentity,
): CtfDashboardProjectionReader {
	return {
		...(stateIdentity === undefined ? {} : { stateIdentity }),
		async readCanonicalMetadata() {
			return failure("unavailable", "canonical_metadata_unavailable", reason, {
				source: "ctf-state",
				...(stateIdentity === undefined ? {} : { competitionId: stateIdentity.competitionId }),
			});
		},
		async readProjectionMetadata() {
			return {
				status: "unavailable",
				code: "projection_metadata_unavailable",
				message: "CTF projection state is not connected",
				details: {
					source: "ctf-projection",
				},
				metadata: { projectionRevision: 0, projectionDigest: CTF_DASHBOARD_UNKNOWN_DIGEST },
			};
		},
		async readRoute() {
			return failure("unavailable", "projection_unavailable", "CTF projection state is not connected", {
				source: "ctf-projection",
			});
		},
	};
}
