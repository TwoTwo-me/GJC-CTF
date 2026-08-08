import { createPublicKey, type KeyObject, verify as verifySignature } from "node:crypto";
import { EvidenceRefsSchema } from "../contracts/common";
import { canonicalJson, type Digest } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	type OracleTransitionProof,
	oracleEvidenceDigest,
	oracleTransitionDigest,
	validateOracleTransitionProof,
} from "../contracts/event";
import {
	EDGE_COMPATIBILITY,
	type GraphEdge,
	GraphEdgeSchema,
	type GraphEdgeState,
	type GraphEdgeType,
	type GraphNode,
	GraphNodeSchema,
	type GraphNodeState,
	type GraphNodeType,
	isCompatibleEdge,
} from "../contracts/graph";

export { EDGE_COMPATIBILITY, isCompatibleEdge };
export const EDGE_COMPATIBILITY_MATRIX = EDGE_COMPATIBILITY;
export interface OracleTransitionProofResolverInput {
	readonly signerKeyId: string;
	readonly registryDigest: Digest;
	readonly oracleEntryDigest: Digest;
	readonly authority: "oracle" | "preflight";
	readonly challengeId: string;
}

export interface OracleTransitionSigningKey {
	readonly keyId?: string;
	readonly algorithm: "ed25519";
	readonly publicKey: string | KeyObject;
	readonly active?: boolean;
}

export type OracleTransitionProofResolver =
	| ((input: OracleTransitionProofResolverInput) => OracleTransitionSigningKey | undefined)
	| {
			readonly resolveKey: (input: OracleTransitionProofResolverInput) => OracleTransitionSigningKey | undefined;
	  };

export interface OracleTransitionVerificationOptions {
	readonly oracleProofResolver?: OracleTransitionProofResolver;
}

export function oracleTransitionSignaturePayload(input: {
	readonly eventType: "node_transition" | "edge_transition";
	readonly challengeId: string;
	readonly proof: OracleTransitionProof;
}): Record<string, unknown> {
	const { proof } = input;
	return {
		schemaVersion: proof.schemaVersion,
		authority: proof.authority,
		registryDigest: proof.registryDigest,
		oracleEntryDigest: proof.oracleEntryDigest,
		...(proof.oracleResultDigest === undefined ? {} : { oracleResultDigest: proof.oracleResultDigest }),
		...(proof.preflightReportDigest === undefined ? {} : { preflightReportDigest: proof.preflightReportDigest }),
		transitionDigest: proof.transitionDigest,
		evidenceDigest: proof.evidenceDigest,
		signerKeyId: proof.signerKeyId,
		signatureAlgorithm: proof.signatureAlgorithm,
		eventType: input.eventType,
		challengeId: input.challengeId,
	};
}

function decodeOracleSignature(value: string): Buffer {
	const trimmed = value.trim();
	if (!trimmed) throw new CtfError("invalid_transition", "oracle proof signature is empty");
	if (/^[a-f0-9]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
		return Buffer.from(trimmed, "hex");
	}
	const decoded = Buffer.from(trimmed, "base64");
	if (decoded.length === 0 || decoded.toString("base64").replace(/=+$/, "") !== trimmed.replace(/=+$/, "")) {
		throw new CtfError("invalid_transition", "oracle proof signature encoding is invalid");
	}
	return decoded;
}

function resolveOracleSigningKey(
	resolver: OracleTransitionProofResolver,
	input: OracleTransitionProofResolverInput,
): OracleTransitionSigningKey | undefined {
	try {
		return typeof resolver === "function" ? resolver(input) : resolver.resolveKey(input);
	} catch {
		return undefined;
	}
}

export function verifyOracleTransitionProofSignature(input: {
	readonly eventType: "node_transition" | "edge_transition";
	readonly before?: unknown;
	readonly after: unknown;
	readonly challengeId: string;
	readonly evidenceRefs: readonly string[];
	readonly proof: OracleTransitionProof;
	readonly resolver?: OracleTransitionProofResolver;
}): void {
	const resolver = input.resolver;
	if (resolver === undefined) {
		throw new CtfError("invalid_transition", "privileged oracle transition requires a trusted key resolver");
	}
	if (
		input.proof.transitionDigest !==
		oracleTransitionDigest({
			eventType: input.eventType,
			before: input.before,
			after: input.after,
		})
	) {
		throw new CtfError("invalid_transition", "oracle proof is not bound to the complete graph transition");
	}
	if (input.proof.evidenceDigest !== oracleEvidenceDigest(input.evidenceRefs)) {
		throw new CtfError("invalid_transition", "oracle proof evidence is not bound to the complete graph transition");
	}
	const key = resolveOracleSigningKey(resolver, {
		signerKeyId: input.proof.signerKeyId,
		registryDigest: input.proof.registryDigest as Digest,
		oracleEntryDigest: input.proof.oracleEntryDigest as Digest,
		authority: input.proof.authority,
		challengeId: input.challengeId,
	});
	if (key === undefined) {
		throw new CtfError("invalid_transition", "oracle proof signer is not trusted for this registry entry");
	}
	if (
		key.algorithm !== "ed25519" ||
		key.active === false ||
		(key.keyId !== undefined && key.keyId !== input.proof.signerKeyId)
	) {
		throw new CtfError("invalid_transition", "oracle proof signer key is not an active Ed25519 key");
	}
	let publicKey: KeyObject;
	try {
		publicKey =
			typeof key.publicKey === "string"
				? key.publicKey.includes("BEGIN ")
					? createPublicKey(key.publicKey)
					: createPublicKey({
							key: Buffer.from(key.publicKey, "base64"),
							format: "der",
							type: "spki",
						})
				: key.publicKey;
	} catch {
		throw new CtfError("invalid_transition", "oracle proof signer key cannot be parsed");
	}
	if (publicKey.asymmetricKeyType !== "ed25519") {
		throw new CtfError("invalid_transition", "oracle proof signer key is not Ed25519");
	}
	let valid = false;
	try {
		valid = verifySignature(
			null,
			Buffer.from(
				canonicalJson(
					oracleTransitionSignaturePayload({
						eventType: input.eventType,
						challengeId: input.challengeId,
						proof: input.proof,
					}),
				),
				"utf8",
			),
			publicKey,
			decodeOracleSignature(input.proof.signature),
		);
	} catch {
		valid = false;
	}
	if (!valid) {
		throw new CtfError("invalid_transition", "oracle proof signature is invalid");
	}
}

export const NODE_STATE_TRANSITIONS: Readonly<
	Record<GraphNodeType, Readonly<Record<GraphNodeState, readonly GraphNodeState[]>>>
> = {
	Hypothesis: {
		proposed: ["active"],
		active: ["supported", "refuted", "blocked", "retired"],
		supported: ["retired"],
		refuted: ["retired"],
		blocked: ["active", "retired"],
		retired: [],
		observed: [],
		verified: [],
		rejected: [],
		unknown: [],
		available: [],
		unavailable: [],
		expired: [],
		planned: [],
		runnable: [],
		running: [],
		succeeded: [],
		failed: [],
		cancelled: [],
		open: [],
		resolved: [],
		wont_fix: [],
		satisfied: [],
		abandoned: [],
	},
	Evidence: {
		observed: ["verified", "rejected"],
		verified: [],
		rejected: [],
		proposed: [],
		active: [],
		supported: [],
		refuted: [],
		blocked: [],
		retired: [],
		unknown: [],
		available: [],
		unavailable: [],
		expired: [],
		planned: [],
		runnable: [],
		running: [],
		succeeded: [],
		failed: [],
		cancelled: [],
		open: [],
		resolved: [],
		wont_fix: [],
		satisfied: [],
		abandoned: [],
	},
	Capability: {
		unknown: ["available", "unavailable", "expired"],
		available: ["expired", "unavailable"],
		unavailable: ["available", "expired"],
		expired: ["available", "unavailable"],
		proposed: [],
		active: [],
		supported: [],
		refuted: [],
		blocked: [],
		retired: [],
		observed: [],
		verified: [],
		rejected: [],
		planned: [],
		runnable: [],
		running: [],
		succeeded: [],
		failed: [],
		cancelled: [],
		open: [],
		resolved: [],
		wont_fix: [],
		satisfied: [],
		abandoned: [],
	},
	Action: {
		planned: ["runnable"],
		runnable: ["running", "blocked", "cancelled"],
		running: ["succeeded", "failed", "blocked", "cancelled"],
		succeeded: [],
		failed: [],
		blocked: ["runnable", "cancelled"],
		cancelled: [],
		proposed: [],
		active: [],
		supported: [],
		refuted: [],
		retired: [],
		observed: [],
		verified: [],
		rejected: [],
		unknown: [],
		available: [],
		unavailable: [],
		expired: [],
		open: [],
		resolved: [],
		wont_fix: [],
		satisfied: [],
		abandoned: [],
	},
	Blocker: {
		open: ["resolved", "wont_fix"],
		resolved: [],
		wont_fix: [],
		proposed: [],
		active: [],
		supported: [],
		refuted: [],
		retired: [],
		observed: [],
		verified: [],
		rejected: [],
		unknown: [],
		available: [],
		unavailable: [],
		expired: [],
		planned: [],
		runnable: [],
		running: [],
		succeeded: [],
		failed: [],
		blocked: [],
		cancelled: [],
		satisfied: [],
		abandoned: [],
	},
	Goal: {
		open: ["satisfied", "failed", "abandoned"],
		satisfied: [],
		failed: [],
		abandoned: [],
		proposed: [],
		active: [],
		supported: [],
		refuted: [],
		blocked: [],
		retired: [],
		observed: [],
		verified: [],
		rejected: [],
		unknown: [],
		available: [],
		unavailable: [],
		expired: [],
		planned: [],
		runnable: [],
		running: [],
		succeeded: [],
		cancelled: [],
		resolved: [],
		wont_fix: [],
	},
};

export type TransitionAuthority =
	| "writer"
	| "oracle"
	| "preflight"
	| "worker-observation"
	| "scheduler"
	| "runtime"
	| "terminal-policy";
export type NodeTransitionContext =
	| TransitionAuthority
	| {
			authority?: TransitionAuthority;
			resolverType?: GraphNodeType;
			resolverEdgeType?: GraphEdgeType;
			resolverNodeId?: string;
			resolverEdgeId?: string;
			evidenceRefs?: readonly string[];
			oracleProof?: OracleTransitionProof;
	  };

const AUTHORITY_BY_NODE: Readonly<Record<GraphNodeType, readonly TransitionAuthority[]>> = {
	Hypothesis: ["writer"],
	Evidence: ["oracle", "preflight", "worker-observation", "writer"],
	Capability: ["runtime", "preflight", "writer"],
	Action: ["scheduler", "writer"],
	Blocker: ["writer", "terminal-policy"],
	Goal: ["oracle", "terminal-policy", "writer"],
};

/* Edge authority is intentionally broad for ordinary lifecycle updates. Privileged
 * resolver edges still require evidence in the projection, while this map prevents
 * an authority from silently crossing an edge's source/target lifecycle. */
const AUTHORITY_BY_EDGE: Readonly<Record<GraphEdgeType, readonly TransitionAuthority[]>> = {
	enables: ["writer", "oracle", "scheduler"],
	requires: ["writer", "scheduler"],
	blocks: ["writer", "terminal-policy"],
	resolves: ["writer", "oracle", "worker-observation", "terminal-policy"],
	contradicts: ["writer", "oracle", "preflight", "worker-observation"],
	produces: ["writer", "scheduler", "worker-observation", "runtime"],
};

export const NODE_INITIAL_STATES: Readonly<Record<GraphNodeType, readonly GraphNodeState[]>> = {
	Hypothesis: ["proposed"],
	Evidence: ["observed"],
	Capability: ["unknown"],
	Action: ["planned"],
	Blocker: ["open"],
	Goal: ["open"],
};

export const EDGE_INITIAL_STATES: readonly GraphEdgeState[] = ["proposed"];

export function allowedNodeInitialState(type: GraphNodeType, state: GraphNodeState): boolean {
	return NODE_INITIAL_STATES[type]?.includes(state) === true;
}

export function allowedEdgeInitialState(state: GraphEdgeState): boolean {
	return EDGE_INITIAL_STATES.includes(state);
}

export function allowedNodeTransition(type: GraphNodeType, from: GraphNodeState, to: GraphNodeState): boolean {
	return from === to || NODE_STATE_TRANSITIONS[type][from]?.includes(to) === true;
}

function isPrivilegedNodeTransition(current: GraphNode, next: GraphNode): boolean {
	return (
		(current.type === "Evidence" && current.state === "observed" && next.state === "verified") ||
		(current.type === "Goal" && current.state === "open" && next.state === "satisfied") ||
		(current.type === "Blocker" && current.state === "open" && next.state === "resolved")
	);
}

function requireResolverContext(
	current: GraphNode,
	context: NodeTransitionContext | undefined,
): Extract<NodeTransitionContext, object> {
	if (typeof context !== "object" || context === null) {
		throw new CtfError("invalid_transition", `${current.type} privileged transition requires resolver context`);
	}
	const authority = context.authority;
	if (authority === undefined)
		throw new CtfError("invalid_transition", `${current.type} privileged transition requires authority context`);
	if (current.type === "Evidence" && !["oracle", "preflight", "worker-observation"].includes(authority)) {
		throw new CtfError("invalid_transition", "only trusted evidence authorities can verify evidence");
	}
	if (current.type === "Goal" && authority !== "oracle") {
		throw new CtfError("invalid_transition", "goal satisfaction requires oracle authority");
	}
	if (typeof context.resolverType !== "string" || !["Action", "Evidence"].includes(context.resolverType)) {
		throw new CtfError(
			"invalid_transition",
			`${current.type} privileged transition requires trusted resolver context`,
		);
	}
	if (typeof context.resolverNodeId !== "string" || context.resolverNodeId.length === 0) {
		throw new CtfError("invalid_transition", `${current.type} privileged transition requires resolver node context`);
	}
	if (!Array.isArray(context.evidenceRefs) || !EvidenceRefsSchema.safeParse(context.evidenceRefs).success) {
		throw new CtfError(
			"invalid_transition",
			`${current.type} privileged transition requires trusted resolver evidence`,
		);
	}
	if (
		current.type === "Blocker" &&
		(typeof context.resolverEdgeId !== "string" ||
			context.resolverEdgeId.length === 0 ||
			context.resolverEdgeType !== "resolves")
	) {
		throw new CtfError("invalid_transition", "blocker resolution requires an Action/Evidence resolves edge");
	}
	if (authority === "oracle" || authority === "preflight") {
		if (context.oracleProof === undefined) {
			throw new CtfError(
				"invalid_transition",
				`${current.type} ${authority} transition requires a typed oracle proof`,
			);
		}
		if (context.oracleProof.authority !== authority) {
			throw new CtfError("invalid_transition", "oracle proof authority does not match transition authority");
		}
		try {
			validateOracleTransitionProof(context.oracleProof);
		} catch (error) {
			if (error instanceof CtfError) {
				throw new CtfError("invalid_transition", error.message, {
					details: error.details,
				});
			}
			throw error;
		}
	}
	return context;
}

export function validateNodeTransition(
	current: GraphNode,
	next: GraphNode,
	context?: NodeTransitionContext,
	options?: OracleTransitionVerificationOptions,
): void {
	const a = GraphNodeSchema.safeParse(current);
	const b = GraphNodeSchema.safeParse(next);
	if (!a.success || !b.success) throw new CtfError("invalid_transition", "node transition contains an invalid node");
	if (current.nodeId !== next.nodeId || current.type !== next.type)
		throw new CtfError("invalid_transition", "node identity/type cannot change");
	if (current.provenance.challengeId !== next.provenance.challengeId)
		throw new CtfError("cross_challenge_reference", "node challenge provenance cannot change");
	if (!allowedNodeTransition(current.type, current.state, next.state))
		throw new CtfError(
			"invalid_transition",
			`${current.type} cannot transition from ${current.state} to ${next.state}`,
		);
	if (next.updatedRevision < current.updatedRevision)
		throw new CtfError("invalid_transition", "node revision moved backwards");
	const authority = typeof context === "string" ? context : context?.authority;
	if (authority !== undefined && !AUTHORITY_BY_NODE[current.type].includes(authority))
		throw new CtfError("invalid_transition", `${authority} cannot update ${current.type}`);
	if (isPrivilegedNodeTransition(current, next)) requireResolverContext(current, context);
	if (
		(authority === "oracle" || authority === "preflight") &&
		typeof context === "object" &&
		context !== null &&
		context.oracleProof !== undefined
	) {
		if (
			context.oracleProof.transitionDigest !==
			oracleTransitionDigest({
				eventType: "node_transition",
				before: current,
				after: next,
			})
		) {
			throw new CtfError("invalid_transition", "oracle proof is not bound to the node transition");
		}
		if (
			context.evidenceRefs === undefined ||
			context.oracleProof.evidenceDigest !== oracleEvidenceDigest(context.evidenceRefs)
		) {
			throw new CtfError("invalid_transition", "oracle proof evidence is not bound to the node transition");
		}
		const boundDigest = context.oracleProof.oracleResultDigest ?? context.oracleProof.preflightReportDigest;
		if (boundDigest === undefined || !context.evidenceRefs.includes(boundDigest)) {
			throw new CtfError(
				"invalid_transition",
				"oracle proof result/preflight digest is not bound to transition evidence",
			);
		}
		if (context.oracleProof !== undefined && context.evidenceRefs !== undefined) {
			verifyOracleTransitionProofSignature({
				eventType: "node_transition",
				before: current,
				after: next,
				challengeId: current.provenance.challengeId,
				evidenceRefs: context.evidenceRefs,
				proof: context.oracleProof,
				resolver: options?.oracleProofResolver,
			});
		}
	}
}

export function allowedEdgeTransition(from: GraphEdgeState, to: GraphEdgeState): boolean {
	return (
		from === to ||
		(from === "proposed" && to === "active") ||
		(from === "active" && (to === "accepted" || to === "rejected"))
	);
}

export function validateEdgeTransition(
	current: GraphEdge,
	next: GraphEdge,
	source: GraphNode,
	target: GraphNode,
	context?: NodeTransitionContext,
	options?: OracleTransitionVerificationOptions,
): void {
	const a = GraphEdgeSchema.safeParse(current);
	const b = GraphEdgeSchema.safeParse(next);
	if (!a.success || !b.success) throw new CtfError("invalid_transition", "edge transition contains an invalid edge");
	if (
		current.edgeId !== next.edgeId ||
		current.type !== next.type ||
		current.sourceNodeId !== next.sourceNodeId ||
		current.targetNodeId !== next.targetNodeId
	) {
		throw new CtfError("invalid_transition", "edge identity/type/endpoints cannot change");
	}
	if (source.nodeId !== current.sourceNodeId || target.nodeId !== current.targetNodeId)
		throw new CtfError("invalid_edge", "edge endpoints do not resolve to supplied nodes");
	if (!isCompatibleEdge(current.type, source.type, target.type))
		throw new CtfError("invalid_edge", `edge ${current.type} does not allow ${source.type}->${target.type}`);
	if (
		source.provenance.challengeId !== target.provenance.challengeId ||
		current.provenance.challengeId !== source.provenance.challengeId
	)
		throw new CtfError("cross_challenge_reference", "edge crosses challenge provenance");
	if (!allowedEdgeTransition(current.state, next.state))
		throw new CtfError("invalid_transition", `edge cannot transition from ${current.state} to ${next.state}`);
	if (next.updatedRevision < current.updatedRevision)
		throw new CtfError("invalid_transition", "edge revision moved backwards");
	if (context !== undefined) {
		const edgeAuthority = typeof context === "string" ? context : context.authority;
		const signedCreationAuthority =
			current === next &&
			typeof context === "object" &&
			context !== null &&
			(edgeAuthority === "oracle" || edgeAuthority === "preflight") &&
			context.oracleProof !== undefined;
		if (
			edgeAuthority !== undefined &&
			!AUTHORITY_BY_EDGE[current.type].includes(edgeAuthority) &&
			!signedCreationAuthority
		) {
			throw new CtfError("invalid_transition", `${edgeAuthority} cannot update ${current.type} edge`);
		}
		if (current.type === "resolves" && next.state !== "rejected") {
			if (
				typeof context !== "object" ||
				context === null ||
				edgeAuthority === undefined ||
				!Array.isArray(context.evidenceRefs) ||
				!EvidenceRefsSchema.safeParse(context.evidenceRefs).success
			) {
				throw new CtfError("invalid_transition", "resolves edge lifecycle requires trusted authority evidence");
			}
		}
		if (edgeAuthority === "oracle" || edgeAuthority === "preflight") {
			if (typeof context !== "object" || context === null || context.oracleProof === undefined) {
				throw new CtfError("invalid_transition", `${edgeAuthority} edge transition requires a typed oracle proof`);
			}
			if (context.oracleProof.authority !== edgeAuthority) {
				throw new CtfError("invalid_transition", "oracle proof authority does not match edge transition authority");
			}
			try {
				validateOracleTransitionProof(context.oracleProof);
			} catch (error) {
				if (error instanceof CtfError) {
					throw new CtfError("invalid_transition", error.message, {
						details: error.details,
					});
				}
				throw error;
			}
			if (
				context.oracleProof.transitionDigest !==
				oracleTransitionDigest({
					eventType: "edge_transition",
					before: current === next ? undefined : current,
					after: next,
				})
			) {
				throw new CtfError("invalid_transition", "oracle proof is not bound to the edge transition");
			}
			if (
				context.evidenceRefs === undefined ||
				context.oracleProof.evidenceDigest !== oracleEvidenceDigest(context.evidenceRefs)
			) {
				throw new CtfError("invalid_transition", "oracle proof evidence is not bound to the edge transition");
			}
			const boundDigest = context.oracleProof.oracleResultDigest ?? context.oracleProof.preflightReportDigest;
			if (boundDigest === undefined || !context.evidenceRefs.includes(boundDigest)) {
				throw new CtfError(
					"invalid_transition",
					"oracle proof result/preflight digest is not bound to transition evidence",
				);
			}
			if (context.evidenceRefs !== undefined) {
				verifyOracleTransitionProofSignature({
					eventType: "edge_transition",
					before: current === next ? undefined : current,
					after: next,
					challengeId: source.provenance.challengeId,
					evidenceRefs: context.evidenceRefs,
					proof: context.oracleProof,
					resolver: options?.oracleProofResolver,
				});
			}
		}
	}
}

export function validateEdgeCompatibility(edge: GraphEdge, source: GraphNode, target: GraphNode): void {
	if (!isCompatibleEdge(edge.type, source.type, target.type))
		throw new CtfError("invalid_edge", `edge ${edge.type} does not allow ${source.type}->${target.type}`);
	if (edge.sourceNodeId !== source.nodeId || edge.targetNodeId !== target.nodeId)
		throw new CtfError("invalid_edge", "edge endpoint does not exist");
	if (
		source.provenance.challengeId !== target.provenance.challengeId ||
		edge.provenance.challengeId !== source.provenance.challengeId
	)
		throw new CtfError("cross_challenge_reference", "edge crosses challenge provenance");
}
export function isValidNodeTransition(
	current: GraphNode,
	next: GraphNode,
	context?: NodeTransitionContext,
	options?: OracleTransitionVerificationOptions,
): boolean {
	try {
		validateNodeTransition(current, next, context, options);
		return true;
	} catch {
		return false;
	}
}

export function isValidEdgeTransition(
	current: GraphEdge,
	next: GraphEdge,
	source: GraphNode,
	target: GraphNode,
	context?: NodeTransitionContext,
	options?: OracleTransitionVerificationOptions,
): boolean {
	try {
		validateEdgeTransition(current, next, source, target, context, options);
		return true;
	} catch {
		return false;
	}
}
