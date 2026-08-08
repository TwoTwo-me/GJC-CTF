import { CtfError } from "../contracts/errors";
import type { GraphNode, GraphSnapshot } from "../contracts/graph";
import { validateGraphOntology } from "./validation";

export type RunnableAction = {
	action: GraphNode;
	runnable: boolean;
	blockingNodeIds: string[];
	missingRequirementNodeIds: string[];
};

/** Derive runnable action state from active blocker/requirement edges without mutating canonical state. */
export function evaluateRunnableActions(graph: GraphSnapshot): RunnableAction[] {
	const snapshot = validateGraphOntology(graph);
	const nodes = new Map(snapshot.nodes.map(node => [node.nodeId, node]));
	const activeEdges = snapshot.edges.filter(edge => edge.state === "active" || edge.state === "accepted");
	return snapshot.nodes
		.filter(node => node.type === "Action")
		.map(action => {
			const blockingNodeIds: string[] = [];
			const missingRequirementNodeIds: string[] = [];
			for (const edge of activeEdges) {
				if (edge.targetNodeId === action.nodeId && edge.type === "blocks") {
					const blocker = nodes.get(edge.sourceNodeId);
					if (blocker !== undefined && blocker.state !== "resolved" && blocker.state !== "wont_fix")
						blockingNodeIds.push(edge.sourceNodeId);
				}
				if (edge.sourceNodeId === action.nodeId && edge.type === "requires") {
					const required = nodes.get(edge.targetNodeId);
					if (required === undefined || !isRunnableRequirement(required))
						missingRequirementNodeIds.push(edge.targetNodeId);
				}
			}
			return {
				action,
				runnable:
					(action.state === "planned" || action.state === "blocked" || action.state === "runnable") &&
					blockingNodeIds.length === 0 &&
					missingRequirementNodeIds.length === 0,
				blockingNodeIds,
				missingRequirementNodeIds,
			};
		});
}

function isRunnableRequirement(node: GraphNode): boolean {
	if (node.type === "Capability") return node.state === "available";
	if (node.type === "Evidence") return node.state === "verified";
	if (node.type === "Hypothesis") return node.state === "active" || node.state === "supported";
	if (node.type === "Goal") return node.state === "open";
	return false;
}

/** Return the actions that become runnable after a blocker resolution. */
export function reactivatedActions(graph: GraphSnapshot, resolvedBlockerId: string): GraphNode[] {
	const result = evaluateRunnableActions(graph);
	const resolved = graph.nodes.find(
		node => node.nodeId === resolvedBlockerId && node.type === "Blocker" && node.state === "resolved",
	);
	if (resolved === undefined)
		throw new CtfError("invalid_transition", `blocker is not resolved: ${resolvedBlockerId}`);
	const affected = new Set(
		graph.edges
			.filter(edge => edge.type === "blocks" && edge.sourceNodeId === resolvedBlockerId)
			.map(edge => edge.targetNodeId),
	);
	return result.filter(item => item.runnable && affected.has(item.action.nodeId)).map(item => item.action);
}
