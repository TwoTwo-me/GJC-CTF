import { describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { canonicalJson } from "../../src/ctf/contracts/digest";
import {
	createGraphEventWriterCapability,
	type EventV1,
	eventPayloadDigest,
	oracleEvidenceDigest,
	oracleTransitionDigest,
	validateGraphEventWriterCapability,
} from "../../src/ctf/contracts/event";
import type { GraphEdge, GraphNode } from "../../src/ctf/contracts/graph";
import { canonicalGraphDigest } from "../../src/ctf/contracts/graph";
import { CTF_SCHEMA_VERSIONS } from "../../src/ctf/contracts/version";
import {
	oracleTransitionSignaturePayload,
	validateEdgeTransition,
	validateNodeTransition,
} from "../../src/ctf/graph/ontology";
import { applyCtfGraphEvent } from "../../src/ctf/graph/projection";
import { CanonicalEventLog, EMPTY_EVENT_DIGEST } from "../../src/ctf/state/event-log";
import { RunLeaseStore } from "../../src/ctf/state/lease";
import { DIGEST_A, DIGEST_B } from "./fixtures";

async function temporaryStore(): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-graph-authority-"));
}
function node(type: GraphNode["type"], state: GraphNode["state"], nodeId: string): GraphNode {
	return {
		nodeId,
		type,
		state,
		confidence: 1,
		evidenceRefs: [DIGEST_A],
		provenance: {
			challengeId: "challenge-one",
			source: "test",
			actor: "test",
			digest: DIGEST_B,
		},
		createdRevision: 1,
		updatedRevision: 1,
	};
}

function edge(
	type: GraphEdge["type"],
	state: GraphEdge["state"],
	sourceNodeId: string,
	targetNodeId: string,
): GraphEdge {
	return {
		edgeId: `${sourceNodeId}-${targetNodeId}`,
		type,
		state,
		sourceNodeId,
		targetNodeId,
		evidenceRefs: [DIGEST_A],
		provenance: {
			challengeId: "challenge-one",
			source: "test",
			actor: "test",
			digest: DIGEST_B,
		},
		createdRevision: 1,
		updatedRevision: 1,
	};
}

function graph(nodes: GraphNode[], edges: GraphEdge[] = []) {
	const value = {
		graphSchemaVersion: CTF_SCHEMA_VERSIONS.graph,
		rankingPolicyVersion: CTF_SCHEMA_VERSIONS.ranking,
		revision: 1,
		nodes,
		edges,
		digest: DIGEST_A,
	};
	return { ...value, digest: canonicalGraphDigest(value) };
}
function signedOracleProof(current: GraphNode, next: GraphNode) {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const key = {
		keyId: "fixture-key",
		algorithm: "ed25519" as const,
		publicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
		active: true,
	};
	const proof = {
		schemaVersion: "ctf-oracle-transition-proof-1" as const,
		authority: "oracle" as const,
		registryDigest: DIGEST_B,
		oracleEntryDigest: DIGEST_B,
		oracleResultDigest: DIGEST_A,
		transitionDigest: oracleTransitionDigest({
			eventType: "node_transition",
			before: current,
			after: next,
		}),
		evidenceDigest: oracleEvidenceDigest([DIGEST_A]),
		signerKeyId: key.keyId,
		signatureAlgorithm: "ed25519" as const,
		signature: "fixture-signature",
	};
	const signature = sign(
		null,
		Buffer.from(
			canonicalJson(
				oracleTransitionSignaturePayload({
					eventType: "node_transition",
					challengeId: current.provenance.challengeId,
					proof,
				}),
			),
		),
		privateKey,
	).toString("base64");
	return {
		proof: { ...proof, signature },
		resolver: {
			resolveKey(input: {
				signerKeyId: string;
				registryDigest: string;
				oracleEntryDigest: string;
				authority: "oracle" | "preflight";
				challengeId: string;
			}) {
				if (
					input.signerKeyId !== key.keyId ||
					input.registryDigest !== DIGEST_B ||
					input.oracleEntryDigest !== DIGEST_B ||
					input.authority !== "oracle" ||
					input.challengeId !== current.provenance.challengeId
				) {
					return undefined;
				}
				return key;
			},
		},
	};
}

function transitionEvent(payload: Record<string, unknown>, evidenceRefs = [DIGEST_A]): EventV1 {
	const event = {
		schemaVersion: CTF_SCHEMA_VERSIONS.event,
		eventId: "event-2",
		eventType: "node_transition" as const,
		competitionId: "competition-1",
		challengeId: "challenge-one",
		previousRevision: 1,
		revision: 2,
		idempotencyKey: "transition-2",
		payloadDigest: DIGEST_B,
		previousEventDigest: EMPTY_EVENT_DIGEST,
		actor: "oracle",
		occurredAt: "2026-01-01T00:00:00.000Z",
		payload,
		evidenceRefs,
	};
	return { ...event, payloadDigest: eventPayloadDigest(event) };
}
function edgeTransitionEvent(payload: Record<string, unknown>, evidenceRefs = [DIGEST_A]): EventV1 {
	return { ...transitionEvent(payload, evidenceRefs), eventType: "edge_transition" };
}
describe("graph transition authority context", () => {
	it("keeps ordinary writer transitions compatible with string authority", () => {
		const current = node("Action", "planned", "action-1");
		const next = { ...current, state: "runnable" as const, updatedRevision: 2 };
		expect(() => validateNodeTransition(current, next, "writer")).not.toThrow();
	});

	it("rejects authority-only evidence verification", () => {
		const current = node("Evidence", "observed", "evidence-1");
		const next = { ...current, state: "verified" as const, updatedRevision: 2 };
		expect(() => validateNodeTransition(current, next, "oracle")).toThrow();
		expect(() => validateNodeTransition(current, next, { authority: "oracle" })).toThrow();
	});

	it("rejects authority-only goal satisfaction and blocker resolution", () => {
		const goal = node("Goal", "open", "goal-1");
		expect(() =>
			validateNodeTransition(goal, { ...goal, state: "satisfied", updatedRevision: 2 }, "oracle"),
		).toThrow();
		const blocker = node("Blocker", "open", "blocker-1");
		expect(() =>
			validateNodeTransition(
				blocker,
				{ ...blocker, state: "resolved", updatedRevision: 2 },
				{ authority: "writer" },
			),
		).toThrow();
	});

	it("requires a trusted resolver and resolves edge context for blocker resolution", () => {
		const blocker = node("Blocker", "open", "blocker-1");
		const context = {
			authority: "writer" as const,
			resolverType: "Action" as const,
			resolverNodeId: "action-1",
			resolverEdgeType: "resolves" as const,
			resolverEdgeId: "edge-1",
			evidenceRefs: [DIGEST_A],
		};
		const resolved = {
			...blocker,
			state: "resolved" as const,
			updatedRevision: 2,
		};
		expect(() => validateNodeTransition(blocker, resolved, context)).not.toThrow();
		const wrong = { ...context, resolverEdgeType: "blocks" as const };
		expect(() => validateNodeTransition(blocker, resolved, wrong)).toThrow();
	});

	it("requires authority evidence for privileged resolves edge lifecycle updates", () => {
		const source = node("Action", "succeeded", "action-1");
		const target = node("Blocker", "open", "blocker-1");
		const current = edge("resolves", "proposed", source.nodeId, target.nodeId);
		const next = { ...current, state: "active" as const, updatedRevision: 2 };
		expect(() =>
			validateEdgeTransition(current, next, source, target, {
				authority: "writer",
			}),
		).toThrow();
		expect(() =>
			validateEdgeTransition(current, next, source, target, {
				authority: "writer",
				evidenceRefs: [DIGEST_A],
			}),
		).not.toThrow();
	});
	it("binds privileged evidence verification to resolver graph and event evidence", () => {
		const resolver = node("Evidence", "verified", "resolver-1");
		const current = node("Evidence", "observed", "evidence-1");
		const next = { ...current, state: "verified" as const, updatedRevision: 2 };
		const initial = graph([resolver, current]);
		expect(() =>
			applyCtfGraphEvent(initial, transitionEvent({ before: current, after: next, authority: "oracle" })),
		).toThrow();
		const fixture = signedOracleProof(current, next);
		const event = transitionEvent({
			before: current,
			after: next,
			authority: "oracle",
			resolverType: "Evidence",
			resolverNodeId: resolver.nodeId,
			evidenceRefs: [DIGEST_A],
			oracleProof: fixture.proof,
		});
		expect(() => applyCtfGraphEvent(initial, event)).toThrow();
		expect(
			applyCtfGraphEvent(initial, event, {
				oracleProofResolver: fixture.resolver,
			})?.nodes.find(item => item.nodeId === current.nodeId)?.state,
		).toBe("verified");
		const forged = transitionEvent({
			before: current,
			after: next,
			authority: "oracle",
			resolverType: "Evidence",
			resolverNodeId: resolver.nodeId,
			evidenceRefs: [DIGEST_A],
			oracleProof: { ...fixture.proof, signature: "f".repeat(128) },
		});
		expect(() =>
			applyCtfGraphEvent(initial, forged, {
				oracleProofResolver: fixture.resolver,
			}),
		).toThrow();
	});

	it("binds blocker resolution to an active resolves edge", () => {
		const resolver = node("Action", "succeeded", "action-1");
		const blocker = node("Blocker", "open", "blocker-1");
		const resolves = edge("resolves", "active", resolver.nodeId, blocker.nodeId);
		const initial = graph([resolver, blocker], [resolves]);
		const next = { ...blocker, state: "resolved" as const, updatedRevision: 2 };
		const forged = transitionEvent({
			before: blocker,
			after: next,
			authority: "writer",
			resolverType: "Action",
			resolverNodeId: resolver.nodeId,
			resolverEdgeType: "resolves",
			resolverEdgeId: "missing-edge",
			evidenceRefs: [DIGEST_A],
		});
		expect(() => applyCtfGraphEvent(initial, forged)).toThrow();
		const valid = transitionEvent({
			before: blocker,
			after: next,
			authority: "writer",
			resolverType: "Action",
			resolverNodeId: resolver.nodeId,
			resolverEdgeType: "resolves",
			resolverEdgeId: resolves.edgeId,
			evidenceRefs: [DIGEST_A],
		});
		expect(applyCtfGraphEvent(initial, valid)?.nodes.find(item => item.nodeId === blocker.nodeId)?.state).toBe(
			"resolved",
		);
	});

	it("rejects privileged terminal states at creation without signed authority", () => {
		for (const [type, state] of [
			["Evidence", "verified"],
			["Goal", "satisfied"],
			["Blocker", "resolved"],
		] as const) {
			const created = {
				...node(type, state, `new-${type.toLowerCase()}`),
				createdRevision: 2,
				updatedRevision: 2,
			};
			expect(() => applyCtfGraphEvent(undefined, transitionEvent({ after: created }))).toThrow();
		}

		const source = node("Action", "planned", "action-source");
		const target = node("Goal", "open", "goal-target");
		for (const state of ["accepted", "rejected"] as const) {
			const created = {
				...edge("enables", state, source.nodeId, target.nodeId),
				createdRevision: 2,
				updatedRevision: 2,
			};
			expect(() => applyCtfGraphEvent(graph([source, target]), transitionEvent({ after: created }))).toThrow();
		}
	});

	it("allows ordinary ontology initial states for nodes and edges", () => {
		const createdNode = {
			...node("Evidence", "observed", "new-evidence"),
			createdRevision: 2,
			updatedRevision: 2,
		};
		expect(applyCtfGraphEvent(undefined, transitionEvent({ after: createdNode }))?.nodes).toHaveLength(1);

		const source = node("Action", "planned", "action-source");
		const target = node("Goal", "open", "goal-target");
		const createdEdge = {
			...edge("enables", "proposed", source.nodeId, target.nodeId),
			createdRevision: 2,
			updatedRevision: 2,
		};
		expect(
			applyCtfGraphEvent(graph([source, target]), edgeTransitionEvent({ after: createdEdge }))?.edges,
		).toHaveLength(1);
	});
	it("requires a validated writer capability for graph appends", async () => {
		const root = await temporaryStore();
		try {
			const lease = new RunLeaseStore(root, {
				competitionId: "competition-1",
				challengeId: "challenge-one",
			});
			await lease.acquire({
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-1",
				ownerId: "graph-writer",
				processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
			});
			const log = new CanonicalEventLog(
				root,
				{
					competitionId: "competition-1",
					challengeId: "challenge-one",
				},
				{ leaseStore: lease },
			);
			const draft = {
				eventId: "graph-writer-event-1",
				eventType: "node_transition" as const,
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-1",
				idempotencyKey: "graph-writer-key-1",
				actor: "graph-writer",
				payload: { fencingToken: 1, after: {} },
				evidenceRefs: [],
			};
			await expect(log.appendDraft(draft)).rejects.toMatchObject({ code: "stale_run_fence" });
			const capability = createGraphEventWriterCapability({
				schemaVersion: "ctf-graph-writer-capability-1",
				kind: "run",
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-1",
				actor: "graph-writer",
				fencingToken: 1,
			});
			await expect(log.appendDraft(draft, undefined, undefined, capability)).resolves.toMatchObject({
				appended: true,
			});
			await expect(
				log.appendDraft(
					{ ...draft, eventId: "graph-writer-event-2", idempotencyKey: "graph-writer-key-2" },
					undefined,
					undefined,
					createGraphEventWriterCapability({ ...capability, actor: "other-writer" }),
				),
			).rejects.toMatchObject({ code: "stale_run_fence" });
			const rawFixtureCapability = {
				schemaVersion: "ctf-graph-writer-capability-1",
				kind: "fixture",
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-fixture",
				actor: "fixture-writer",
				fencingToken: 0,
			};
			await expect(
				log.appendDraft(
					{
						...draft,
						eventId: "graph-writer-event-3",
						runId: "run-fixture",
						actor: "fixture-writer",
						idempotencyKey: "graph-writer-key-3",
						payload: { fencingToken: 0, after: {} },
					},
					undefined,
					undefined,
					rawFixtureCapability as never,
				),
			).rejects.toMatchObject({ code: "stale_run_fence" });
			const fixtureCapability = validateGraphEventWriterCapability(rawFixtureCapability);
			await expect(
				log.appendDraft(
					{
						...draft,
						eventId: "graph-writer-event-4",
						runId: "run-fixture",
						actor: "fixture-writer",
						idempotencyKey: "graph-writer-key-4",
						payload: { fencingToken: 0, after: {} },
					},
					undefined,
					undefined,
					fixtureCapability,
				),
			).resolves.toMatchObject({ appended: true });
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("rejects a stale graph writer fence", async () => {
		const root = await temporaryStore();
		try {
			const lease = new RunLeaseStore(root, {
				competitionId: "competition-1",
				challengeId: "challenge-one",
			});
			await lease.acquire({
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-stale",
				ownerId: "graph-writer",
				processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
			});
			const log = new CanonicalEventLog(
				root,
				{ competitionId: "competition-1", challengeId: "challenge-one" },
				{ leaseStore: lease },
			);
			const capability = createGraphEventWriterCapability({
				schemaVersion: "ctf-graph-writer-capability-1",
				kind: "run",
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-stale",
				actor: "graph-writer",
				fencingToken: 2,
			});
			await expect(
				log.appendDraft(
					{
						eventType: "node_transition",
						competitionId: "competition-1",
						challengeId: "challenge-one",
						runId: "run-stale",
						idempotencyKey: "stale-fence",
						actor: "graph-writer",
						payload: { fencingToken: 2, after: {} },
						evidenceRefs: [],
					},
					undefined,
					undefined,
					capability,
				),
			).rejects.toMatchObject({ code: "stale_run_fence" });
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects an expired graph writer lease", async () => {
		const root = await temporaryStore();
		try {
			const lease = new RunLeaseStore(root, {
				competitionId: "competition-1",
				challengeId: "challenge-one",
			});
			await lease.acquire({
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-expired",
				ownerId: "graph-writer",
				processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
				now: new Date(Date.now() - 10_000),
				leaseDurationMs: 1,
			});
			const log = new CanonicalEventLog(
				root,
				{ competitionId: "competition-1", challengeId: "challenge-one" },
				{ leaseStore: lease },
			);
			const capability = createGraphEventWriterCapability({
				schemaVersion: "ctf-graph-writer-capability-1",
				kind: "run",
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-expired",
				actor: "graph-writer",
				fencingToken: 1,
			});
			await expect(
				log.appendDraft(
					{
						eventType: "node_transition",
						competitionId: "competition-1",
						challengeId: "challenge-one",
						runId: "run-expired",
						idempotencyKey: "expired-fence",
						actor: "graph-writer",
						payload: { fencingToken: 1, after: {} },
						evidenceRefs: [],
					},
					undefined,
					undefined,
					capability,
				),
			).rejects.toMatchObject({ code: "stale_run_fence" });
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects a graph writer capability after lease takeover", async () => {
		const root = await temporaryStore();
		try {
			const lease = new RunLeaseStore(root, {
				competitionId: "competition-1",
				challengeId: "challenge-one",
			});
			await lease.acquire({
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-old",
				ownerId: "old-writer",
				processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
				now: new Date(Date.now() - 10_000),
				leaseDurationMs: 1,
			});
			await lease.acquire({
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-new",
				ownerId: "new-writer",
				takeoverOf: "run-old",
				processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
			});
			const log = new CanonicalEventLog(
				root,
				{ competitionId: "competition-1", challengeId: "challenge-one" },
				{ leaseStore: lease },
			);
			const capability = createGraphEventWriterCapability({
				schemaVersion: "ctf-graph-writer-capability-1",
				kind: "run",
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-old",
				actor: "old-writer",
				fencingToken: 1,
			});
			await expect(
				log.appendDraft(
					{
						eventType: "node_transition",
						competitionId: "competition-1",
						challengeId: "challenge-one",
						runId: "run-old",
						idempotencyKey: "takeover-fence",
						actor: "old-writer",
						payload: { fencingToken: 1, after: {} },
						evidenceRefs: [],
					},
					undefined,
					undefined,
					capability,
				),
			).rejects.toMatchObject({ code: "stale_run_fence" });
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
