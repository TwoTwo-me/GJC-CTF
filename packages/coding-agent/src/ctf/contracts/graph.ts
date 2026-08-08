import * as z from "zod/v4";
import {
	CtfIdSchema,
	DigestSchema,
	EvidenceRefsSchema,
	PositiveIntegerSchema,
	ProvenanceSchema,
	RatioSchema,
} from "./common";
import { canonicalDigest, type Digest, digestsEqual } from "./digest";
import { CtfError } from "./errors";
import { assertKnownMajor, CTF_SCHEMA_VERSIONS } from "./version";

export const GraphNodeTypeSchema = z.enum(["Hypothesis", "Evidence", "Capability", "Action", "Blocker", "Goal"]);
export type GraphNodeType = z.infer<typeof GraphNodeTypeSchema>;
export const GraphNodeStateSchema = z.enum([
	"proposed",
	"active",
	"supported",
	"refuted",
	"blocked",
	"retired",
	"observed",
	"verified",
	"rejected",
	"unknown",
	"available",
	"unavailable",
	"expired",
	"planned",
	"runnable",
	"running",
	"succeeded",
	"failed",
	"cancelled",
	"open",
	"resolved",
	"wont_fix",
	"satisfied",
	"abandoned",
]);
export type GraphNodeState = z.infer<typeof GraphNodeStateSchema>;
export const GraphEdgeTypeSchema = z.enum(["enables", "requires", "blocks", "resolves", "contradicts", "produces"]);
export type GraphEdgeType = z.infer<typeof GraphEdgeTypeSchema>;
export const GraphEdgeStateSchema = z.enum(["proposed", "active", "accepted", "rejected"]);
export type GraphEdgeState = z.infer<typeof GraphEdgeStateSchema>;

export const GraphNodeSchema = z
	.object({
		nodeId: CtfIdSchema,
		type: GraphNodeTypeSchema,
		state: GraphNodeStateSchema,
		confidence: RatioSchema,
		evidenceRefs: EvidenceRefsSchema,
		provenance: ProvenanceSchema,
		createdRevision: PositiveIntegerSchema,
		updatedRevision: PositiveIntegerSchema,
	})
	.strict();
export type GraphNode = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z
	.object({
		edgeId: CtfIdSchema,
		type: GraphEdgeTypeSchema,
		sourceNodeId: CtfIdSchema,
		targetNodeId: CtfIdSchema,
		state: GraphEdgeStateSchema,
		evidenceRefs: EvidenceRefsSchema,
		provenance: ProvenanceSchema,
		createdRevision: PositiveIntegerSchema,
		updatedRevision: PositiveIntegerSchema,
	})
	.strict();
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

export const GraphSnapshotSchema = z
	.object({
		graphSchemaVersion: z.literal(CTF_SCHEMA_VERSIONS.graph),
		rankingPolicyVersion: z.literal(CTF_SCHEMA_VERSIONS.ranking),
		revision: PositiveIntegerSchema,
		digest: DigestSchema,
		nodes: z.array(GraphNodeSchema),
		edges: z.array(GraphEdgeSchema),
		rankingPolicyDigest: DigestSchema.optional(),
	})
	.strict();
export type GraphSnapshot = z.infer<typeof GraphSnapshotSchema>;

export const EDGE_COMPATIBILITY: Readonly<Record<GraphEdgeType, readonly `${GraphNodeType}->${GraphNodeType}`[]>> = {
	enables: ["Evidence->Hypothesis", "Capability->Action", "Action->Goal"],
	requires: ["Goal->Hypothesis", "Action->Capability", "Hypothesis->Evidence"],
	blocks: ["Blocker->Action", "Blocker->Goal", "Hypothesis->Action"],
	resolves: ["Action->Blocker", "Evidence->Blocker"],
	contradicts: ["Evidence->Hypothesis", "Hypothesis->Hypothesis", "Evidence->Evidence"],
	produces: ["Action->Evidence", "Action->Capability", "Hypothesis->Evidence"],
};

export function edgePairKey(source: GraphNodeType, target: GraphNodeType): `${GraphNodeType}->${GraphNodeType}` {
	return `${source}->${target}` as `${GraphNodeType}->${GraphNodeType}`;
}
export function isCompatibleEdge(type: GraphEdgeType, source: GraphNodeType, target: GraphNodeType): boolean {
	return EDGE_COMPATIBILITY[type]?.includes(edgePairKey(source, target)) === true;
}
export function canonicalGraphDigest(snapshot: GraphSnapshot | Omit<GraphSnapshot, "digest">): Digest {
	return canonicalDigest(snapshot, ["digest"]);
}

export function validateGraphSnapshot(value: unknown): GraphSnapshot {
	const parsed = GraphSnapshotSchema.safeParse(value);
	if (!parsed.success)
		throw new CtfError("integrity_error", "graph snapshot is invalid", { details: { issues: parsed.error.issues } });
	const graph = parsed.data;
	assertKnownMajor(graph.graphSchemaVersion, "graph");
	if (!digestsEqual(canonicalGraphDigest(graph), graph.digest))
		throw new CtfError("digest_mismatch", "graph snapshot digest mismatch");
	return graph;
}
export const EDGE_COMPATIBILITY_MATRIX = EDGE_COMPATIBILITY;
export const GRAPH_EDGE_COMPATIBILITY = EDGE_COMPATIBILITY;
export const NODE_TYPES = ["Hypothesis", "Evidence", "Capability", "Action", "Blocker", "Goal"] as const;
export const EDGE_TYPES = ["enables", "requires", "blocks", "resolves", "contradicts", "produces"] as const;
export const GraphSchema = GraphSnapshotSchema;
export const parseGraphSnapshot = validateGraphSnapshot;
