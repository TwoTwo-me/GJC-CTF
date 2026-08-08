import { EvidenceRefsSchema } from "../contracts/common";
import { canonicalDigest, type Digest, digestsEqual, isDigest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type EventV1,
	eventDigest,
	oracleEvidenceDigest,
	oracleTransitionDigest,
	validateEvent,
	validateOracleTransitionProof,
} from "../contracts/event";
import {
	canonicalGraphDigest,
	type GraphEdge,
	GraphEdgeSchema,
	type GraphNode,
	GraphNodeSchema,
	type GraphSnapshot,
} from "../contracts/graph";
import { oracleEntryDigest, type TrustedOracleRegistry } from "../contracts/oracle";
import { CTF_SCHEMA_VERSIONS } from "../contracts/version";
import { validateTrustedOracleRegistry } from "../runtime/oracle";
import { CheckpointStore, type CheckpointV1 } from "../state/checkpoint";
import { CanonicalEventLog, EMPTY_EVENT_DIGEST, type EventLogIdentity } from "../state/event-log";
import { DerivedProjection, type ProjectionSnapshot } from "../state/projection";
import type { CtfStateStoreLike } from "../state/storage";
import {
	allowedEdgeInitialState,
	allowedNodeInitialState,
	type NodeTransitionContext,
	type OracleTransitionProofResolver,
	type OracleTransitionVerificationOptions,
	type TransitionAuthority,
	validateEdgeCompatibility,
	validateEdgeTransition,
	validateNodeTransition,
	verifyOracleTransitionProofSignature,
} from "./ontology";
import { validateGraphOntology } from "./validation";

/** Metadata and graph state produced by replaying one canonical event prefix. */
export interface CtfGraphReplayResult {
	readonly graph?: GraphSnapshot;
	readonly canonicalRevision: number;
	readonly canonicalDigest: Digest;
}

/** A graph checkpoint always identifies the canonical event prefix it represents. */
export interface CtfGraphCheckpoint {
	readonly schemaVersion: typeof CTF_SCHEMA_VERSIONS.state;
	readonly canonicalRevision: number;
	readonly canonicalDigest: Digest;
	readonly graphRevision: number;
	readonly graphDigest: Digest;
	readonly graph: GraphSnapshot;
}

export interface CtfGraphProjectionSnapshot extends ProjectionSnapshot<GraphSnapshot | undefined> {
	readonly graph?: GraphSnapshot;
	readonly checkpoint?: CtfGraphCheckpoint;
}

export interface CtfGraphProofOptions extends OracleTransitionVerificationOptions {
	readonly trustedOracleRegistry?: TrustedOracleRegistry;
	readonly oracleResolver?: OracleTransitionProofResolver;
}

export interface CtfGraphProjectionOptions extends CtfGraphProofOptions {
	readonly identity?: EventLogIdentity;
}
type CtfGraphProjectionSourceOptions = CtfGraphProjectionOptions | EventLogIdentity;
type CtfGraphApplyOptions = CtfGraphProofOptions | TrustedOracleRegistry | OracleTransitionProofResolver;

type GraphState = GraphSnapshot | undefined;
type TransitionObject = Record<string, unknown>;
function isTrustedOracleRegistry(value: CtfGraphApplyOptions): value is TrustedOracleRegistry {
	return typeof value === "object" && value !== null && "registry" in value && "keys" in value;
}
function isOracleProofResolver(value: CtfGraphApplyOptions): value is OracleTransitionProofResolver {
	return (
		typeof value === "function" ||
		(typeof value === "object" && value !== null && "resolveKey" in value && typeof value.resolveKey === "function")
	);
}

function proofOptions(value: CtfGraphApplyOptions | undefined): OracleTransitionVerificationOptions {
	if (value === undefined) return {};
	if (isOracleProofResolver(value)) return { oracleProofResolver: value };
	const directRegistry = isTrustedOracleRegistry(value) ? value : value.trustedOracleRegistry;
	const resolver = isTrustedOracleRegistry(value) ? undefined : (value.oracleProofResolver ?? value.oracleResolver);
	if (resolver !== undefined) return { oracleProofResolver: resolver };
	if (directRegistry === undefined) return {};
	const trusted = validateTrustedOracleRegistry(directRegistry);
	return {
		oracleProofResolver: {
			resolveKey(input) {
				if (trusted.registry.registryDigest !== input.registryDigest) {
					return undefined;
				}
				const entry = trusted.registry.entries.find(
					candidate =>
						oracleEntryDigest(candidate) === input.oracleEntryDigest &&
						candidate.allowedChallengeIds.includes(input.challengeId) &&
						candidate.signerKeyId === input.signerKeyId,
				);
				if (entry === undefined) return undefined;
				return trusted.keys.find(key => key.keyId === entry.signerKeyId);
			},
		},
	};
}

function objectValue(value: unknown, label: string): TransitionObject {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new CtfError("invalid_transition", `${label} must be an object`);
	}
	return value as TransitionObject;
}

function transitionValue(payload: TransitionObject, names: readonly string[], label: string): unknown {
	const present = names.filter(name => name in payload);
	if (present.length !== 1)
		throw new CtfError("invalid_transition", `${label} must contain exactly one of ${names.join(", ")}`);
	return payload[present[0]];
}

function transitionContext(payload: TransitionObject): NodeTransitionContext | undefined {
	const authority = payload.authority;
	const resolverType = payload.resolverType;
	const resolverEdgeType = payload.resolverEdgeType;
	const resolverNodeId = payload.resolverNodeId;
	const resolverEdgeId = payload.resolverEdgeId;
	const oracleProof = payload.oracleProof;
	const evidenceRefs = payload.evidenceRefs;
	if (
		authority === undefined &&
		resolverType === undefined &&
		resolverEdgeType === undefined &&
		resolverNodeId === undefined &&
		resolverEdgeId === undefined &&
		evidenceRefs === undefined &&
		oracleProof === undefined
	)
		return undefined;
	const authorities = [
		"writer",
		"oracle",
		"preflight",
		"worker-observation",
		"scheduler",
		"runtime",
		"terminal-policy",
	] as const;
	if (authority !== undefined && !authorities.includes(authority as (typeof authorities)[number]))
		throw new CtfError("invalid_transition", "transition authority is unknown");
	const nodeTypes = ["Hypothesis", "Evidence", "Capability", "Action", "Blocker", "Goal"] as const;
	const edgeTypes = ["enables", "requires", "blocks", "resolves", "contradicts", "produces"] as const;
	if (resolverType !== undefined && !nodeTypes.includes(resolverType as (typeof nodeTypes)[number]))
		throw new CtfError("invalid_transition", "transition resolver type is unknown");
	if (resolverEdgeType !== undefined && !edgeTypes.includes(resolverEdgeType as (typeof edgeTypes)[number]))
		throw new CtfError("invalid_transition", "transition resolver edge type is unknown");
	if (resolverNodeId !== undefined && (typeof resolverNodeId !== "string" || resolverNodeId.length === 0))
		throw new CtfError("invalid_transition", "transition resolver node is invalid");
	if (resolverEdgeId !== undefined && (typeof resolverEdgeId !== "string" || resolverEdgeId.length === 0))
		throw new CtfError("invalid_transition", "transition resolver edge is invalid");
	if (
		evidenceRefs !== undefined &&
		(!Array.isArray(evidenceRefs) || !EvidenceRefsSchema.safeParse(evidenceRefs).success)
	)
		throw new CtfError("invalid_transition", "transition resolver evidence is invalid");
	return {
		...(authority === undefined ? {} : { authority: authority as TransitionAuthority }),
		...(resolverType === undefined ? {} : { resolverType: resolverType as GraphNode["type"] }),
		...(resolverEdgeType === undefined ? {} : { resolverEdgeType: resolverEdgeType as GraphEdge["type"] }),
		...(resolverNodeId === undefined ? {} : { resolverNodeId }),
		...(resolverEdgeId === undefined ? {} : { resolverEdgeId }),
		...(evidenceRefs === undefined ? {} : { evidenceRefs: evidenceRefs as readonly string[] }),
		...(oracleProof === undefined ? {} : { oracleProof: validateOracleTransitionProof(oracleProof) }),
	} as NodeTransitionContext;
}

function snapshotAtRevision(graph: GraphSnapshot, revision: number): GraphSnapshot {
	const next = { ...graph, revision, digest: "" as Digest };
	const withDigest = { ...next, digest: canonicalGraphDigest(next) };
	return validateGraphOntology(withDigest);
}

function graphNodeAt(graph: GraphSnapshot, nodeId: string): GraphNode | undefined {
	return graph.nodes.find(node => node.nodeId === nodeId);
}

function graphEdgeAt(graph: GraphSnapshot, edgeId: string): GraphEdge | undefined {
	return graph.edges.find(edge => edge.edgeId === edgeId);
}

function evidenceOverlap(left: readonly string[], right: readonly string[]): boolean {
	const rightSet = new Set(right);
	return left.some(ref => rightSet.has(ref));
}

function sameEvidenceRefs(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((ref, index) => ref === right[index]);
}

function validateOracleProofBinding(
	eventType: "node_transition" | "edge_transition",
	before: unknown,
	after: unknown,
	event: EventV1,
	context: NodeTransitionContext | undefined,
): void {
	const authority = typeof context === "object" && context !== null ? context.authority : undefined;
	if (authority !== "oracle" && authority !== "preflight") return;
	if (
		context === undefined ||
		typeof context === "string" ||
		context.oracleProof === undefined ||
		context.evidenceRefs === undefined
	) {
		throw new CtfError("invalid_transition", `${authority} transition requires a typed oracle proof and evidence`);
	}
	const proof = validateOracleTransitionProof(context.oracleProof);
	if (proof.authority !== authority) {
		throw new CtfError("invalid_transition", "oracle proof authority does not match transition authority");
	}
	if (proof.transitionDigest !== oracleTransitionDigest({ eventType, before, after })) {
		throw new CtfError("invalid_transition", "oracle proof is not bound to the complete graph transition");
	}
	if (!sameEvidenceRefs(context.evidenceRefs, event.evidenceRefs)) {
		throw new CtfError("invalid_transition", "oracle proof evidence must equal the canonical event evidence");
	}
	if (proof.evidenceDigest !== oracleEvidenceDigest(event.evidenceRefs)) {
		throw new CtfError(
			"invalid_transition",
			"oracle proof evidence digest does not match the canonical event evidence",
		);
	}
	const boundDigest = proof.oracleResultDigest ?? proof.preflightReportDigest;
	if (
		boundDigest === undefined ||
		!event.evidenceRefs.includes(boundDigest) ||
		!context.evidenceRefs.includes(boundDigest)
	) {
		throw new CtfError(
			"invalid_transition",
			"oracle proof result/preflight digest is not present in canonical evidence",
		);
	}
}
function isPrivilegedNodeTransition(current: GraphNode, next: GraphNode): boolean {
	return (
		(current.type === "Evidence" && current.state === "observed" && next.state === "verified") ||
		(current.type === "Goal" && current.state === "open" && next.state === "satisfied") ||
		(current.type === "Blocker" && current.state === "open" && next.state === "resolved")
	);
}

function validateResolverProof(
	graph: GraphSnapshot,
	current: GraphNode,
	next: GraphNode,
	event: EventV1,
	context: NodeTransitionContext | undefined,
): void {
	if (!isPrivilegedNodeTransition(current, next)) return;
	validateOracleProofBinding("node_transition", current, next, event, context);
	if (
		context === undefined ||
		typeof context === "string" ||
		context.resolverNodeId === undefined ||
		context.evidenceRefs === undefined
	) {
		throw new CtfError(
			"invalid_transition",
			`${current.type} privileged transition requires contextual resolver proof`,
		);
	}
	const resolver = graphNodeAt(graph, context.resolverNodeId);
	if (resolver === undefined || resolver.type !== context.resolverType) {
		throw new CtfError("invalid_transition", "resolver node does not match transition context");
	}
	if (
		!evidenceOverlap(context.evidenceRefs, resolver.evidenceRefs) ||
		!evidenceOverlap(context.evidenceRefs, next.evidenceRefs) ||
		!evidenceOverlap(context.evidenceRefs, event.evidenceRefs)
	) {
		throw new CtfError("invalid_transition", "resolver evidence is not bound to the node transition");
	}
	if (current.type !== "Blocker") return;
	if (context.resolverEdgeId === undefined || context.resolverEdgeType !== "resolves") {
		throw new CtfError("invalid_transition", "blocker resolution requires a resolves edge context");
	}
	const resolverEdge = graphEdgeAt(graph, context.resolverEdgeId);
	if (
		resolverEdge === undefined ||
		resolverEdge.type !== "resolves" ||
		resolverEdge.sourceNodeId !== resolver.nodeId ||
		resolverEdge.targetNodeId !== next.nodeId ||
		resolverEdge.state !== "active"
	) {
		throw new CtfError("invalid_transition", "blocker resolution requires an active resolver edge");
	}
	if (!evidenceOverlap(context.evidenceRefs, resolverEdge.evidenceRefs)) {
		throw new CtfError("invalid_transition", "resolver edge evidence does not support blocker resolution");
	}
	validateEdgeCompatibility(resolverEdge, resolver, next);
}

function validateSignedCreationAuthority(
	eventType: "node_transition" | "edge_transition",
	after: GraphNode | GraphEdge,
	event: EventV1,
	context: NodeTransitionContext | undefined,
	verification: OracleTransitionVerificationOptions,
): void {
	if (
		typeof context !== "object" ||
		context === null ||
		(context.authority !== "oracle" && context.authority !== "preflight") ||
		context.oracleProof === undefined
	) {
		throw new CtfError("invalid_transition", `${after.type} creation requires an explicit signed authority`);
	}
	validateOracleProofBinding(eventType, undefined, after, event, context);
	verifyOracleTransitionProofSignature({
		eventType,
		before: undefined,
		after,
		challengeId: event.challengeId,
		evidenceRefs: event.evidenceRefs,
		proof: context.oracleProof,
		resolver: verification.oracleProofResolver,
	});
}

function validateInitialNodeCreation(
	next: GraphNode,
	event: EventV1,
	context: NodeTransitionContext | undefined,
	verification: OracleTransitionVerificationOptions,
): void {
	if (allowedNodeInitialState(next.type, next.state)) return;
	validateSignedCreationAuthority("node_transition", next, event, context, verification);
}

function validateInitialEdgeCreation(
	next: GraphEdge,
	event: EventV1,
	context: NodeTransitionContext | undefined,
	verification: OracleTransitionVerificationOptions,
): void {
	if (allowedEdgeInitialState(next.state)) return;
	validateSignedCreationAuthority("edge_transition", next, event, context, verification);
}

function applyNodeTransition(
	graph: GraphSnapshot | undefined,
	event: EventV1,
	verification: OracleTransitionVerificationOptions,
): GraphSnapshot {
	const payload = objectValue(event.payload, "node transition payload");
	const beforeValue =
		payload.before === undefined &&
		payload.current === undefined &&
		payload.previous === undefined &&
		payload.from === undefined
			? undefined
			: transitionValue(payload, ["before", "current", "previous", "from"], "node transition");
	const afterValue =
		payload.after === undefined &&
		payload.next === undefined &&
		payload.node === undefined &&
		payload.to === undefined
			? undefined
			: transitionValue(payload, ["after", "next", "node", "to"], "node transition result");
	if (afterValue === undefined) throw new CtfError("invalid_transition", "node transition has no next node");
	const next = objectValue(afterValue, "node transition result") as unknown as GraphNode;
	const parsedNode = GraphNodeSchema.safeParse(next);
	if (!parsedNode.success)
		throw new CtfError("invalid_transition", "node transition result is invalid", {
			details: { issues: parsedNode.error.issues },
		});
	const validatedNext = parsedNode.data;
	if (validatedNext.provenance.challengeId !== event.challengeId)
		throw new CtfError("cross_challenge_reference", "node transition challenge does not match the event");
	if (validatedNext.updatedRevision !== event.revision)
		throw new CtfError("invalid_transition", "node transition revision must equal the event revision");
	const context = transitionContext(payload);
	if (graph === undefined) {
		if (beforeValue !== undefined && beforeValue !== null)
			throw new CtfError("invalid_transition", "first node transition must add a node");
		validateInitialNodeCreation(validatedNext, event, context, verification);
		if (validatedNext.createdRevision !== event.revision)
			throw new CtfError("invalid_transition", "new node creation revision must equal the event revision");
		return snapshotAtRevision(
			{
				graphSchemaVersion: CTF_SCHEMA_VERSIONS.graph,
				rankingPolicyVersion: CTF_SCHEMA_VERSIONS.ranking,
				revision: event.revision,
				nodes: [validatedNext],
				edges: [],
				digest: "" as Digest,
			},
			event.revision,
		);
	}
	const current = graphNodeAt(graph, validatedNext.nodeId);
	if (beforeValue === undefined || beforeValue === null) {
		if (current !== undefined)
			throw new CtfError("invalid_transition", `node already exists: ${validatedNext.nodeId}`);
		validateInitialNodeCreation(validatedNext, event, context, verification);
		if (validatedNext.createdRevision !== event.revision)
			throw new CtfError("invalid_transition", "new node creation revision must equal the event revision");
		return snapshotAtRevision(
			{
				...graph,
				nodes: [...graph.nodes, validatedNext],
				digest: graph.digest,
			},
			event.revision,
		);
	}
	if (current === undefined) throw new CtfError("invalid_transition", `node does not exist: ${validatedNext.nodeId}`);
	const before = objectValue(beforeValue, "node transition predecessor") as unknown as GraphNode;
	if (canonicalDigest(before) !== canonicalDigest(current))
		throw new CtfError("integrity_error", "node transition predecessor does not match the graph");
	validateResolverProof(graph, current, validatedNext, event, context);
	validateNodeTransition(current, validatedNext, context, verification);

	return snapshotAtRevision(
		{
			...graph,
			nodes: graph.nodes.map(node => (node.nodeId === validatedNext.nodeId ? validatedNext : node)),
			digest: graph.digest,
		},
		event.revision,
	);
}

function applyEdgeTransition(
	graph: GraphSnapshot | undefined,
	event: EventV1,
	verification: OracleTransitionVerificationOptions,
): GraphSnapshot {
	if (graph === undefined) throw new CtfError("invalid_transition", "edge transition requires an existing graph");
	const payload = objectValue(event.payload, "edge transition payload");
	const beforeValue =
		payload.before === undefined &&
		payload.current === undefined &&
		payload.previous === undefined &&
		payload.from === undefined
			? undefined
			: transitionValue(payload, ["before", "current", "previous", "from"], "edge transition");
	const afterValue =
		payload.after === undefined &&
		payload.next === undefined &&
		payload.edge === undefined &&
		payload.to === undefined
			? undefined
			: transitionValue(payload, ["after", "next", "edge", "to"], "edge transition result");
	if (afterValue === undefined) throw new CtfError("invalid_transition", "edge transition has no next edge");
	const next = objectValue(afterValue, "edge transition result") as unknown as GraphEdge;
	const source = graphNodeAt(graph, next.sourceNodeId);
	const target = graphNodeAt(graph, next.targetNodeId);
	if (source === undefined || target === undefined)
		throw new CtfError("invalid_edge", `edge endpoint not found: ${next.edgeId}`);
	const parsedEdge = GraphEdgeSchema.safeParse(next);
	if (!parsedEdge.success)
		throw new CtfError("invalid_edge", "edge transition result is invalid", {
			details: { issues: parsedEdge.error.issues },
		});
	const validatedNext = parsedEdge.data;
	if (validatedNext === undefined || validatedNext.edgeId !== next.edgeId)
		throw new CtfError("invalid_edge", `invalid edge: ${next.edgeId}`);
	if (validatedNext.provenance.challengeId !== event.challengeId)
		throw new CtfError("cross_challenge_reference", "edge transition challenge does not match the event");
	if (validatedNext.updatedRevision !== event.revision)
		throw new CtfError("invalid_transition", "edge transition revision must equal the event revision");
	const context = transitionContext(payload);
	validateOracleProofBinding("edge_transition", beforeValue ?? undefined, validatedNext, event, context);
	const current = graphEdgeAt(graph, validatedNext.edgeId);
	if (beforeValue === undefined || beforeValue === null) {
		if (current !== undefined)
			throw new CtfError("invalid_transition", `edge already exists: ${validatedNext.edgeId}`);
		validateInitialEdgeCreation(validatedNext, event, context, verification);
		if (validatedNext.createdRevision !== event.revision)
			throw new CtfError("invalid_transition", "new edge creation revision must equal the event revision");
		validateEdgeCompatibility(validatedNext, source, target);
		validateEdgeTransition(validatedNext, validatedNext, source, target, context, verification);
		return snapshotAtRevision(
			{
				...graph,
				edges: [...graph.edges, validatedNext],
				digest: graph.digest,
			},
			event.revision,
		);
	}
	if (current === undefined) throw new CtfError("invalid_transition", `edge does not exist: ${validatedNext.edgeId}`);
	const before = objectValue(beforeValue, "edge transition predecessor") as unknown as GraphEdge;
	if (canonicalDigest(before) !== canonicalDigest(current))
		throw new CtfError("integrity_error", "edge transition predecessor does not match the graph");
	validateEdgeTransition(current, validatedNext, source, target, context, verification);
	return snapshotAtRevision(
		{
			...graph,
			edges: graph.edges.map(edge => (edge.edgeId === validatedNext.edgeId ? validatedNext : edge)),
			digest: graph.digest,
		},
		event.revision,
	);
}

/** Apply one validated canonical event without mutating the canonical event log. */
export function applyCtfGraphEvent(
	graph: GraphSnapshot | undefined,
	eventValue: unknown,
	options?: CtfGraphApplyOptions,
): GraphSnapshot | undefined {
	const event = validateEvent(eventValue);
	const verification = proofOptions(options);
	if (event.eventType === "node_transition") return applyNodeTransition(graph, event, verification);
	if (event.eventType === "edge_transition") return applyEdgeTransition(graph, event, verification);
	if (graph === undefined) return undefined;
	return snapshotAtRevision(graph, event.revision);
}

/** Replay a complete canonical event prefix, validating its hash chain and graph transitions. */
export function replayCtfGraphEvents(
	eventsValue: readonly unknown[],
	initialGraph?: GraphSnapshot,
	options?: CtfGraphApplyOptions,
): CtfGraphReplayResult {
	const verification = proofOptions(options);
	let graph = initialGraph === undefined ? undefined : validateGraphOntology(initialGraph);
	let previousRevision = graph?.revision ?? 0;
	let previousDigest = EMPTY_EVENT_DIGEST;
	if (graph !== undefined && graph.revision <= 0)
		throw new CtfError("invalid_transition", "graph revision must be positive");
	for (const value of eventsValue) {
		const event = validateEvent(value);
		if (event.revision !== previousRevision + 1 || event.previousRevision !== previousRevision)
			throw new CtfError("revision_conflict", "graph replay event revisions are not contiguous");
		if (!digestsEqual(event.previousEventDigest, previousDigest))
			throw new CtfError("integrity_error", "graph replay event hash chain does not match");
		graph = applyCtfGraphEvent(graph, event, verification);
		previousRevision = event.revision;
		previousDigest = eventDigest(event);
	}
	if (graph !== undefined && graph.revision !== previousRevision) graph = snapshotAtRevision(graph, previousRevision);
	return {
		...(graph === undefined ? {} : { graph }),
		canonicalRevision: previousRevision,
		canonicalDigest: previousDigest,
	};
}

export function createCtfGraphCheckpoint(replay: CtfGraphReplayResult): CtfGraphCheckpoint | undefined {
	if (replay.graph === undefined) return undefined;
	if (!Number.isSafeInteger(replay.canonicalRevision) || replay.canonicalRevision < 0)
		throw new CtfError("revision_conflict", "graph checkpoint canonical revision is invalid");
	if (replay.graph.revision !== replay.canonicalRevision)
		throw new CtfError("revision_conflict", "graph checkpoint revision does not match canonical revision");
	if (!isDigest(replay.canonicalDigest))
		throw new CtfError("integrity_error", "graph checkpoint canonical digest is invalid");
	const graph = validateGraphOntology(replay.graph);
	if (!isDigest(graph.digest)) throw new CtfError("integrity_error", "graph checkpoint graph digest is invalid");
	return {
		schemaVersion: CTF_SCHEMA_VERSIONS.state,
		canonicalRevision: replay.canonicalRevision,
		canonicalDigest: replay.canonicalDigest,
		graphRevision: graph.revision,
		graphDigest: graph.digest as Digest,
		graph,
	};
}

/** Rebuildable graph projection backed exclusively by the canonical event log. */
export class CtfGraphProjection {
	readonly eventLog: CanonicalEventLog;
	readonly projection: DerivedProjection<GraphState>;
	readonly checkpointStore: CheckpointStore;
	private readonly verification: OracleTransitionVerificationOptions;
	private durableCheckpoint: CheckpointV1 | undefined;
	private durabilityStatus: ProjectionSnapshot<GraphState>["projectionStatus"] = "rebuilding";

	constructor(eventLog: CanonicalEventLog | CtfStateStoreLike, options: CtfGraphProjectionSourceOptions = {}) {
		const identity: EventLogIdentity | undefined =
			"identity" in options ? options.identity : (options as EventLogIdentity);
		this.verification = proofOptions(
			"trustedOracleRegistry" in options || "oracleProofResolver" in options || "oracleResolver" in options
				? (options as CtfGraphProjectionOptions)
				: undefined,
		);
		const log = eventLog instanceof CanonicalEventLog ? eventLog : new CanonicalEventLog(eventLog, identity);
		this.eventLog = log;
		this.checkpointStore = new CheckpointStore(log.store, log);
		this.projection = new DerivedProjection<GraphState>(log, undefined, ({ state, event }) =>
			applyCtfGraphEvent(state, event, this.verification),
		);
	}

	private snapshotOf(value: ProjectionSnapshot<GraphState>): CtfGraphProjectionSnapshot {
		const graph = value.state;
		const replay: CtfGraphReplayResult = {
			...(graph === undefined ? {} : { graph }),
			canonicalRevision: value.canonicalRevision,
			canonicalDigest: value.canonicalDigest,
		};
		const status =
			this.durabilityStatus === "current" || this.durabilityStatus === "lagging"
				? value.projectionStatus
				: this.durabilityStatus;
		const durableGraphCheckpoint =
			this.durableCheckpoint !== undefined &&
			this.durableCheckpoint.canonicalRevision === value.canonicalRevision &&
			digestsEqual(this.durableCheckpoint.canonicalDigest, value.canonicalDigest) &&
			(graph === undefined
				? this.durableCheckpoint.graphDigest === undefined
				: this.durableCheckpoint.graphDigest !== undefined &&
					digestsEqual(this.durableCheckpoint.graphDigest, graph.digest))
				? createCtfGraphCheckpoint(replay)
				: undefined;
		const exposeGraph = status !== "integrity_error" && status !== "rebuilding" && status !== "unavailable";
		const { state: _state, ...metadata } = value;
		return {
			...metadata,
			projectionStatus: status,
			...(exposeGraph && graph !== undefined ? { state: graph, graph } : {}),
			...(exposeGraph && durableGraphCheckpoint !== undefined ? { checkpoint: durableGraphCheckpoint } : {}),
		};
	}

	private initialSnapshot(): ProjectionSnapshot<GraphState> {
		return {
			canonicalRevision: 0,
			canonicalDigest: EMPTY_EVENT_DIGEST,
			projectionRevision: 0,
			projectionDigest: EMPTY_EVENT_DIGEST,
			projectionStatus: this.durabilityStatus,
			stateDigest: EMPTY_EVENT_DIGEST,
		};
	}

	private projectionSnapshot(): ProjectionSnapshot<GraphState> {
		try {
			return this.projection.snapshot();
		} catch {
			return this.initialSnapshot();
		}
	}

	private async readAndValidateCheckpoint(): Promise<CheckpointV1 | undefined> {
		this.durableCheckpoint = undefined;
		const checkpoint = await this.checkpointStore.read();
		if (checkpoint === undefined) return undefined;
		const head = await this.eventLog.read();
		const prefix = head.events.slice(0, checkpoint.canonicalRevision);
		const replay = replayCtfGraphEvents(prefix, undefined, this.verification);
		if (!digestsEqual(replay.canonicalDigest, checkpoint.canonicalDigest)) {
			throw new CtfError("digest_mismatch", "graph checkpoint canonical digest does not match replayed events");
		}
		if (
			checkpoint.projectionDigest === undefined ||
			!digestsEqual(checkpoint.projectionDigest, replay.canonicalDigest)
		) {
			throw new CtfError("digest_mismatch", "graph checkpoint projection digest does not match canonical events");
		}
		const graphDigest = replay.graph?.digest;
		if (
			(checkpoint.graphDigest === undefined && graphDigest !== undefined) ||
			(checkpoint.graphDigest !== undefined && graphDigest === undefined) ||
			(checkpoint.graphDigest !== undefined &&
				graphDigest !== undefined &&
				!digestsEqual(checkpoint.graphDigest, graphDigest))
		) {
			throw new CtfError("digest_mismatch", "graph checkpoint graph digest does not match replayed graph");
		}
		this.durableCheckpoint = checkpoint;
		return checkpoint;
	}

	private checkpointMatches(value: ProjectionSnapshot<GraphState>, checkpoint: CheckpointV1): boolean {
		return (
			checkpoint.canonicalRevision === value.canonicalRevision &&
			digestsEqual(checkpoint.canonicalDigest, value.canonicalDigest) &&
			checkpoint.projectionDigest !== undefined &&
			digestsEqual(checkpoint.projectionDigest, value.projectionDigest) &&
			(value.state === undefined
				? checkpoint.graphDigest === undefined
				: checkpoint.graphDigest !== undefined && digestsEqual(checkpoint.graphDigest, value.state.digest))
		);
	}
	private async projectWithoutGraph(): Promise<ProjectionSnapshot<GraphState> | undefined> {
		const canonical = await this.eventLog.read();
		if (
			canonical.events.some(event => event.eventType === "node_transition" || event.eventType === "edge_transition")
		) {
			return undefined;
		}
		const replay = replayCtfGraphEvents(canonical.events, undefined, this.verification);
		if (replay.graph !== undefined) return undefined;
		return {
			canonicalRevision: replay.canonicalRevision,
			canonicalDigest: replay.canonicalDigest,
			projectionRevision: replay.canonicalRevision,
			projectionDigest: replay.canonicalDigest,
			projectionStatus: "current",
			stateDigest: EMPTY_EVENT_DIGEST,
		};
	}

	private async persistCurrent(value: ProjectionSnapshot<GraphState>): Promise<CtfGraphProjectionSnapshot> {
		if (value.projectionStatus !== "current") {
			this.durabilityStatus = value.projectionStatus;
			return this.snapshotOf(value);
		}
		const head = await this.eventLog.read();
		const competitionId = this.eventLog.identity.competitionId ?? head.events[0]?.competitionId;
		if (competitionId === undefined) {
			this.durabilityStatus = "unavailable";
			return this.snapshotOf(value);
		}
		const journalByteOffset = head.journalByteOffsets?.[value.canonicalRevision];
		if (journalByteOffset === undefined) {
			this.durabilityStatus = "integrity_error";
			throw new CtfError("integrity_error", "canonical event log did not provide a journal byte offset");
		}
		if (!this.durableCheckpoint || !this.checkpointMatches(value, this.durableCheckpoint)) {
			this.durableCheckpoint = await this.checkpointStore.write({
				competitionId,
				...(this.eventLog.identity.challengeId === undefined
					? {}
					: { challengeId: this.eventLog.identity.challengeId }),
				canonicalRevision: value.canonicalRevision,
				canonicalDigest: value.canonicalDigest,
				eventCount: value.canonicalRevision,
				journalByteOffset,
				...(value.state === undefined ? {} : { graphDigest: value.state.digest as Digest }),
				projectionDigest: value.projectionDigest,
			});
		}
		this.durabilityStatus = "current";
		return this.snapshotOf(value);
	}

	async rebuild(): Promise<CtfGraphProjectionSnapshot> {
		this.durabilityStatus = "rebuilding";
		try {
			await this.readAndValidateCheckpoint();
			const projection = await this.projectWithoutGraph();
			return await this.persistCurrent(projection ?? (await this.projection.rebuild()));
		} catch (error) {
			this.durabilityStatus = "integrity_error";
			throw error;
		}
	}

	async refresh(): Promise<CtfGraphProjectionSnapshot> {
		this.durabilityStatus = "rebuilding";
		try {
			const checkpoint = await this.readAndValidateCheckpoint();
			const projection = await this.projectWithoutGraph();
			const next =
				projection ??
				(checkpoint === undefined ? await this.projection.rebuild() : await this.projection.refresh());
			return await this.persistCurrent(next);
		} catch (error) {
			this.durabilityStatus = "integrity_error";
			throw error;
		}
	}

	snapshot(): CtfGraphProjectionSnapshot {
		return this.snapshotOf(this.projectionSnapshot());
	}

	metadataOnly() {
		const metadata = this.projectionSnapshot();
		return {
			canonicalRevision: metadata.canonicalRevision,
			canonicalDigest: metadata.canonicalDigest,
			projectionRevision: metadata.projectionRevision,
			projectionDigest: metadata.projectionDigest,
			projectionStatus:
				this.durabilityStatus === "current" || this.durabilityStatus === "lagging"
					? metadata.projectionStatus
					: this.durabilityStatus,
			stateDigest: metadata.stateDigest,
		};
	}

	async readGraph(challengeId: string, revision?: number): Promise<Record<string, unknown> | undefined> {
		if (this.eventLog.identity.challengeId !== undefined && this.eventLog.identity.challengeId !== challengeId) {
			throw new CtfError("cross_challenge_reference", "requested challenge does not match event-log identity");
		}
		const result = await this.refresh();
		if (result.projectionStatus !== "current") return undefined;
		if (result.graph === undefined) return undefined;
		if (
			result.graph.nodes.some(node => node.provenance.challengeId !== challengeId) ||
			result.graph.edges.some(edge => edge.provenance.challengeId !== challengeId)
		) {
			throw new CtfError("cross_challenge_reference", "requested challenge does not match graph provenance");
		}
		if (revision !== undefined && revision !== result.graph.revision)
			throw new CtfError("revision_conflict", "requested graph revision is not available");
		return result.graph as unknown as Record<string, unknown>;
	}
}

export const GraphProjection = CtfGraphProjection;
export const createCtfGraphProjection = (
	eventLog: CanonicalEventLog | CtfStateStoreLike,
	options?: CtfGraphProjectionSourceOptions,
): CtfGraphProjection => new CtfGraphProjection(eventLog, options);
export const graphCheckpoint = createCtfGraphCheckpoint;
export const replayGraphEvents = replayCtfGraphEvents;
