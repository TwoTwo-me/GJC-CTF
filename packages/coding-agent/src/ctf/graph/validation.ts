import { digestsEqual } from "../contracts/digest";
import { CtfError } from "../contracts/errors";
import {
	canonicalGraphDigest,
	GraphEdgeSchema,
	GraphNodeSchema,
	type GraphNodeType,
	type GraphSnapshot,
	GraphSnapshotSchema,
} from "../contracts/graph";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "../contracts/version";
import { validateEdgeCompatibility } from "./ontology";

const VALID_STATE_BY_TYPE: Readonly<Record<GraphNodeType, readonly string[]>> = {
	Hypothesis: ["proposed", "active", "supported", "refuted", "blocked", "retired"],
	Evidence: ["observed", "verified", "rejected"],
	Capability: ["unknown", "available", "unavailable", "expired"],
	Action: ["planned", "runnable", "running", "succeeded", "failed", "blocked", "cancelled"],
	Blocker: ["open", "resolved", "wont_fix"],
	Goal: ["open", "satisfied", "failed", "abandoned"],
};

export function validateGraphOntology(graph: unknown): GraphSnapshot {
	const parsed = GraphSnapshotSchema.safeParse(graph);
	if (!parsed.success)
		throw new CtfError("invalid_edge", "graph snapshot schema is invalid", {
			details: { issues: parsed.error.issues },
		});
	const snapshot = parsed.data;
	assertKnownMajor(snapshot.graphSchemaVersion, "graph");
	if (snapshot.rankingPolicyVersion !== CTF_SCHEMA_VERSIONS.ranking)
		throw new CtfError("unknown_schema_major", `unknown ranking policy: ${snapshot.rankingPolicyVersion}`);
	if (!digestsEqual(canonicalGraphDigest(snapshot), snapshot.digest))
		throw new CtfError("digest_mismatch", "graph digest mismatch");

	const nodes = new Map<string, (typeof snapshot.nodes)[number]>();
	let challengeId: string | undefined;
	for (const node of snapshot.nodes) {
		if (!GraphNodeSchema.safeParse(node).success)
			throw new CtfError("missing_provenance", `invalid graph node: ${node.nodeId}`);
		if (nodes.has(node.nodeId)) throw new CtfError("invalid_edge", `duplicate graph node: ${node.nodeId}`);
		if (!VALID_STATE_BY_TYPE[node.type].includes(node.state))
			throw new CtfError("invalid_transition", `${node.type} cannot use state ${node.state}`);
		if (challengeId === undefined) challengeId = node.provenance.challengeId;
		if (challengeId !== node.provenance.challengeId)
			throw new CtfError("cross_challenge_reference", "graph contains multiple challenge provenances");
		nodes.set(node.nodeId, node);
	}
	const edges = new Set<string>();
	for (const edge of snapshot.edges) {
		if (!GraphEdgeSchema.safeParse(edge).success)
			throw new CtfError("invalid_edge", `invalid graph edge: ${edge.edgeId}`);
		if (edges.has(edge.edgeId)) throw new CtfError("invalid_edge", `duplicate graph edge: ${edge.edgeId}`);
		edges.add(edge.edgeId);
		const source = nodes.get(edge.sourceNodeId);
		const target = nodes.get(edge.targetNodeId);
		if (source === undefined || target === undefined)
			throw new CtfError("invalid_edge", `edge endpoint not found for ${edge.edgeId}`);
		validateEdgeCompatibility(edge, source, target);
		if (
			edge.type === "contradicts" &&
			target.type === "Hypothesis" &&
			target.state === "refuted" &&
			edge.state !== "active"
		) {
			throw new CtfError("invalid_transition", "contradicts edge must remain active after hypothesis refutation");
		}
	}
	return snapshot;
}

export const validateGraphSnapshot = validateGraphOntology;
export function parseGraphOntology(value: unknown): GraphSnapshot {
	return validateGraphOntology(value);
}
