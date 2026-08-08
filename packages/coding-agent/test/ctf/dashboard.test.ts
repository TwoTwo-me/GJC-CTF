import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createFixtureGraphEventWriterCapability } from "../../src/ctf/contracts/event";
import type { GraphEdge, GraphNode } from "../../src/ctf/contracts/graph";
import { createCtfDashboardApiHandler } from "../../src/ctf/dashboard/api";
import {
	createCtfWorkspaceDashboardProjectionReader,
	createUnavailableCtfDashboardProjectionReader,
	deriveCtfDashboardProjectionStatus,
	readCtfDashboardRoute,
	readCtfDashboardSnapshot,
} from "../../src/ctf/dashboard/projection-reader";
import type { CtfDashboardProjectionReader } from "../../src/ctf/dashboard/types";
import { CtfGraphProjection } from "../../src/ctf/graph/projection";
import { CanonicalEventLog } from "../../src/ctf/state/event-log";
import { initCtfWorkspace, registerChallenge } from "../../src/ctf/workspace";
import { DIGEST_A, DIGEST_B, EVIDENCE_DIGEST, FIXED_TIME, makeDescriptor, SKILL } from "./fixtures";

const NOW = () => new Date("2026-01-01T00:00:00.000Z");

async function json(response: Response): Promise<Record<string, unknown>> {
	return (await response.json()) as Record<string, unknown>;
}

describe("CTF dashboard availability and integrity", () => {
	it("returns an unavailable health response with explicit integrity metadata", async () => {
		const handler = createCtfDashboardApiHandler({
			projectionReader: createUnavailableCtfDashboardProjectionReader("canonical state is offline"),
			now: NOW,
		});
		const response = await handler(new Request("https://ctf.test/api/ctf/v1/health"));
		const body = await json(response);
		const error = body.error as Record<string, unknown>;

		expect(response.status).toBe(503);
		expect(body.projectionStatus).toBe("integrity_error");
		expect(body.canonicalRevision).toBe(0);
		expect(body.canonicalDigest).toBe("0".repeat(64));
		expect(error.code).toBe("canonical_metadata_unavailable");
		expect(error.retryable).toBe(true);
		expect(body.data).toBeUndefined();
	});

	it("does not expose the absolute state root in public error details", async () => {
		const stateRoot = "/absolute/private/ctf-state";
		const reader = createUnavailableCtfDashboardProjectionReader(
			`Unable to read ${stateRoot}/ctf-manifest.json: ENOENT`,
			{
				competitionId: "competition-1",
				stateRoot,
			},
		);
		const readerFailure = await reader.readCanonicalMetadata();
		expect(JSON.stringify(readerFailure)).not.toContain(stateRoot);
		expect(JSON.stringify(readerFailure)).not.toContain("ENOENT");
		const handler = createCtfDashboardApiHandler({ projectionReader: reader, now: NOW });
		const response = await handler(new Request("https://ctf.test/api/ctf/v1/health"));
		const body = await json(response);
		const serialized = JSON.stringify(body);
		expect(serialized).not.toContain(stateRoot);
		expect((body.error as Record<string, unknown>).details).toEqual({
			source: "ctf-state",
			competitionId: "competition-1",
		});
	});
	it("redacts filesystem details from custom projection readers while preserving typed identity", async () => {
		const workspaceRoot = "/absolute/private/workspace";
		const manifestPath = `${workspaceRoot}/ctf-manifest.json`;
		const stateRoot = `${workspaceRoot}/.gjc-ctf`;
		const reader: CtfDashboardProjectionReader = {
			async readCanonicalMetadata() {
				return {
					status: "integrity_error",
					code: "canonical_metadata_unavailable",
					message: `Unable to read CTF manifest at ${manifestPath}: ENOENT`,
					details: {
						source: "ctf-event-log",
						competitionId: "competition-1",
						workspaceRoot,
						manifestPath,
						stateRoot,
						cause: `ENOENT: no such file or directory, open '${manifestPath}'`,
					},
				};
			},
			async readProjectionMetadata() {
				return { status: "available", metadata: { projectionRevision: 1, projectionDigest: DIGEST_A } };
			},
		};
		const handler = createCtfDashboardApiHandler({ projectionReader: reader, now: NOW });
		const response = await handler(new Request("https://ctf.test/api/ctf/v1/competition/competition-1"));
		const body = await json(response);
		const error = body.error as Record<string, unknown>;
		const serialized = JSON.stringify(body);

		expect(response.status).toBe(503);
		expect(body.identity).toEqual({ competitionId: "competition-1" });
		expect(error.code).toBe("canonical_metadata_unavailable");
		expect(error.retryable).toBe(false);
		expect(error.message).toBe("CTF dashboard request could not be completed");
		expect(error.details).toEqual({ source: "ctf-event-log", competitionId: "competition-1" });
		expect(serialized).not.toContain(workspaceRoot);
		expect(serialized).not.toContain(manifestPath);
		expect(serialized).not.toContain(stateRoot);
		expect(serialized).not.toContain("ENOENT");
		expect(serialized).not.toContain("cause");
	});
	it("does not publish an invalid canonical competition identity", async () => {
		const workspaceRoot = "/absolute/private/workspace";
		const reader: CtfDashboardProjectionReader = {
			async readCanonicalMetadata() {
				return {
					status: "available",
					metadata: { competitionId: workspaceRoot, canonicalRevision: 1, canonicalDigest: DIGEST_A },
				};
			},
			async readProjectionMetadata() {
				return { status: "available", metadata: { projectionRevision: 1, projectionDigest: DIGEST_B } };
			},
		};
		const handler = createCtfDashboardApiHandler({ projectionReader: reader, now: NOW });
		const response = await handler(new Request("https://ctf.test/api/ctf/v1/health"));
		const body = await json(response);
		const serialized = JSON.stringify(body);

		expect(response.status).toBe(503);
		expect(body.identity).toEqual({ competitionId: "unknown" });
		expect((body.error as Record<string, unknown>).retryable).toBe(true);
		expect(serialized).not.toContain(workspaceRoot);
	});
	it("fails closed when projection metadata disagrees with canonical digest", async () => {
		const reader: CtfDashboardProjectionReader = {
			async readCanonicalMetadata() {
				return {
					status: "available",
					metadata: { competitionId: "competition-1", canonicalRevision: 2, canonicalDigest: DIGEST_A },
				};
			},
			async readProjectionMetadata() {
				return { status: "available", metadata: { projectionRevision: 2, projectionDigest: DIGEST_B } };
			},
			async readCompetition() {
				return { ready: true };
			},
		};
		const snapshot = await readCtfDashboardSnapshot(reader, { competitionId: "competition-1" });
		expect(snapshot.projectionStatus).toBe("integrity_error");
		const handler = createCtfDashboardApiHandler({ projectionReader: reader, now: NOW });
		const response = await handler(new Request("https://ctf.test/api/ctf/v1/competition/competition-1"));
		const body = await json(response);
		const error = body.error as Record<string, unknown>;
		expect(response.status).toBe(503);
		expect(body.canonicalRevision).toBe(2);
		expect(body.canonicalDigest).toBe(DIGEST_A);
		expect(body.projectionRevision).toBe(2);
		expect(body.projectionDigest).toBe(DIGEST_B);
		expect(error.code).toBe("projection_integrity_error");
		expect(body.data).toBeUndefined();
	});

	it("distinguishes current and lagging projections without allowing a stale projection to claim current", () => {
		const canonical = { status: "available" as const, metadata: { canonicalRevision: 3, canonicalDigest: DIGEST_A } };
		expect(
			deriveCtfDashboardProjectionStatus(canonical, {
				status: "available",
				metadata: { projectionRevision: 3, projectionDigest: DIGEST_A },
			}),
		).toBe("current");
		expect(
			deriveCtfDashboardProjectionStatus(canonical, {
				status: "available",
				metadata: { projectionRevision: 2, projectionDigest: DIGEST_A },
			}),
		).toBe("lagging");
		expect(
			deriveCtfDashboardProjectionStatus(canonical, {
				status: "available",
				metadata: { projectionRevision: 3, projectionDigest: DIGEST_B },
			}),
		).toBe("integrity_error");
	});
	it("refuses challenge routes for unregistered challenge IDs", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-dashboard-"));
		try {
			const workspace = (await initCtfWorkspace(root, "dashboard-test", { skill: SKILL })).workspace;
			const reader = createCtfWorkspaceDashboardProjectionReader(workspace);
			const route = await readCtfDashboardRoute(reader, {
				kind: "challenge-graph",
				challengeId: "unknown-challenge",
			});
			expect(route).toMatchObject({
				status: "unavailable",
				code: "challenge_not_registered",
			});
			const handler = createCtfDashboardApiHandler({ projectionReader: reader, now: NOW });
			const response = await handler(new Request("https://ctf.test/api/ctf/v1/challenges/unknown-challenge/status"));
			const body = await json(response);
			expect(response.status).toBe(503);
			expect(body.error).toMatchObject({
				code: "challenge_not_registered",
			});
			expect(body.data).toBeUndefined();
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("accepts a rooted explicit challenge projection only for its event-log identity", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-dashboard-"));
		try {
			let workspace = (await initCtfWorkspace(root, "dashboard-test", { skill: SKILL })).workspace;
			workspace = await registerChallenge(workspace, makeDescriptor("challenge-a"));
			const competitionId = workspace.manifest.competitionId;
			const eventLog = new CanonicalEventLog(workspace.stateRoot, {
				competitionId,
				challengeId: "challenge-a",
			});
			await eventLog.appendDraft(
				{
					eventId: "event-challenge-a",
					eventType: "node_transition",
					competitionId,
					challengeId: "challenge-a",
					runId: "run-challenge-a",
					idempotencyKey: "challenge-a-run",
					actor: "dashboard-test",
					occurredAt: FIXED_TIME,
					payload: {
						fencingToken: 0,
						after: {
							nodeId: "node-challenge-a",
							type: "Action",
							state: "planned",
							confidence: 1,
							evidenceRefs: [EVIDENCE_DIGEST],
							provenance: {
								challengeId: "challenge-a",
								source: "dashboard-test",
								actor: "dashboard-test",
								digest: DIGEST_A,
							},
							createdRevision: 1,
							updatedRevision: 1,
						},
					},
					evidenceRefs: [EVIDENCE_DIGEST],
				},
				undefined,
				undefined,
				createFixtureGraphEventWriterCapability({
					competitionId,
					challengeId: "challenge-a",
					runId: "run-challenge-a",
					actor: "dashboard-test",
				}),
			);
			const explicit = new CtfGraphProjection(workspace.stateRoot, {
				identity: { competitionId, challengeId: "challenge-a" },
			});
			const reader = createCtfWorkspaceDashboardProjectionReader(workspace, explicit);
			const snapshot = await readCtfDashboardSnapshot(reader, { challengeId: "challenge-a" });
			expect(snapshot.projectionStatus).toBe("current");
			const wrongIdentity = new CtfGraphProjection(workspace.stateRoot, {
				identity: { competitionId: "other-competition", challengeId: "challenge-a" },
			});
			const mismatched = createCtfWorkspaceDashboardProjectionReader(workspace, wrongIdentity);
			await expect(mismatched.readCanonicalMetadata({ challengeId: "challenge-a" })).resolves.toMatchObject({
				status: "integrity_error",
				code: "projection_identity_mismatch",
			});
			expect(JSON.stringify(await mismatched.readCanonicalMetadata({ challengeId: "challenge-a" }))).not.toContain(
				workspace.stateRoot,
			);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("rejects graph edges whose provenance belongs to another challenge", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-dashboard-"));
		try {
			const provenance = (challengeId: string) => ({
				challengeId,
				source: "dashboard-test",
				actor: "dashboard-test",
				digest: DIGEST_A,
			});
			const source: GraphNode = {
				nodeId: "action-one",
				type: "Action",
				state: "planned",
				confidence: 1,
				evidenceRefs: [EVIDENCE_DIGEST],
				provenance: provenance("challenge-one"),
				createdRevision: 1,
				updatedRevision: 1,
			};
			const target: GraphNode = {
				nodeId: "goal-one",
				type: "Goal",
				state: "open",
				confidence: 1,
				evidenceRefs: [EVIDENCE_DIGEST],
				provenance: provenance("challenge-one"),
				createdRevision: 1,
				updatedRevision: 1,
			};
			const mixedEdge: GraphEdge = {
				edgeId: "action-one-goal-one",
				type: "enables",
				state: "proposed",
				sourceNodeId: source.nodeId,
				targetNodeId: target.nodeId,
				evidenceRefs: [EVIDENCE_DIGEST],
				provenance: provenance("challenge-two"),
				createdRevision: 1,
				updatedRevision: 1,
			};
			const graph = { revision: 1, nodes: [source, target], edges: [mixedEdge] } as never;
			const projection = new CtfGraphProjection(root, { identity: { competitionId: "competition-1" } });
			projection.refresh = async () =>
				({
					canonicalRevision: 1,
					canonicalDigest: DIGEST_A,
					projectionRevision: 1,
					projectionDigest: DIGEST_A,
					projectionStatus: "current",
					stateDigest: DIGEST_A,
					graph,
				}) as never;
			await expect(projection.readGraph("challenge-one")).rejects.toMatchObject({
				code: "cross_challenge_reference",
			});
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("uses challenge-scoped journals for default workspace projections without changing competition fallback", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-dashboard-"));
		try {
			let workspace = (await initCtfWorkspace(root, "dashboard-test", { skill: SKILL })).workspace;
			workspace = await registerChallenge(workspace, makeDescriptor("challenge-a"));
			workspace = await registerChallenge(workspace, makeDescriptor("challenge-b"));
			const competitionId = workspace.manifest.competitionId;
			const appendRun = async (challengeId: string, idempotencyKey: string) => {
				const log = new CanonicalEventLog(workspace.stateRoot, { competitionId, challengeId });
				return log.appendDraft(
					{
						eventId: `event-${idempotencyKey}`,
						eventType: "node_transition",
						competitionId,
						challengeId,
						runId: `run-${challengeId}`,
						idempotencyKey,
						actor: "dashboard-test",
						occurredAt: FIXED_TIME,
						payload: {
							fencingToken: 0,
							after: {
								nodeId: `node-${challengeId}`,
								type: "Action",
								state: "planned",
								confidence: 1,
								evidenceRefs: [EVIDENCE_DIGEST],
								provenance: {
									challengeId,
									source: "dashboard-test",
									actor: "dashboard-test",
									digest: DIGEST_A,
								},
								createdRevision: 1,
								updatedRevision: 1,
							},
						},
						evidenceRefs: [EVIDENCE_DIGEST],
					},
					undefined,
					undefined,
					createFixtureGraphEventWriterCapability({
						competitionId,
						challengeId,
						runId: `run-${challengeId}`,
						actor: "dashboard-test",
					}),
				);
			};
			await appendRun("challenge-a", "challenge-a-run");
			await appendRun("challenge-b", "challenge-b-run");
			const competitionLog = new CanonicalEventLog(workspace.stateRoot, { competitionId });
			await competitionLog.appendDraft(
				{
					eventId: "event-competition-run",
					eventType: "node_transition",
					competitionId,
					challengeId: "challenge-a",
					runId: "run-competition",
					idempotencyKey: "competition-run",
					actor: "dashboard-test",
					occurredAt: FIXED_TIME,
					payload: {
						fencingToken: 0,
						after: {
							nodeId: "node-challenge-a",
							type: "Action",
							state: "planned",
							confidence: 1,
							evidenceRefs: [EVIDENCE_DIGEST],
							provenance: {
								challengeId: "challenge-a",
								source: "dashboard-test",
								actor: "dashboard-test",
								digest: DIGEST_A,
							},
							createdRevision: 1,
							updatedRevision: 1,
						},
					},
					evidenceRefs: [EVIDENCE_DIGEST],
				},
				undefined,
				undefined,
				createFixtureGraphEventWriterCapability({
					competitionId,
					challengeId: "challenge-a",
					runId: "run-competition",
					actor: "dashboard-test",
				}),
			);

			const reader = createCtfWorkspaceDashboardProjectionReader(workspace);
			const challengeA = await readCtfDashboardSnapshot(reader, { challengeId: "challenge-a" });
			const challengeB = await readCtfDashboardSnapshot(reader, { challengeId: "challenge-b" });
			expect(challengeA.projectionStatus).toBe("current");
			expect(challengeB.projectionStatus).toBe("current");
			expect(challengeA.canonical).toMatchObject({
				status: "available",
				metadata: { competitionId, challengeId: "challenge-a", canonicalRevision: 1 },
			});
			expect(challengeB.canonical).toMatchObject({
				status: "available",
				metadata: { competitionId, challengeId: "challenge-b", canonicalRevision: 1 },
			});
			expect((challengeA.canonical as { metadata: { canonicalDigest: string } }).metadata.canonicalDigest).not.toBe(
				(challengeB.canonical as { metadata: { canonicalDigest: string } }).metadata.canonicalDigest,
			);
			expect(challengeA.projection).toMatchObject({ status: "available", metadata: { projectionRevision: 1 } });
			expect(challengeB.projection).toMatchObject({ status: "available", metadata: { projectionRevision: 1 } });
			const challengeRoute = await readCtfDashboardRoute(reader, {
				kind: "challenge-graph",
				challengeId: "challenge-b",
			});
			expect(challengeRoute).toMatchObject({ graph: { nodes: [{ provenance: { challengeId: "challenge-b" } }] } });
			expect(
				(challengeA.projection as { metadata: { projectionDigest: string } }).metadata.projectionDigest,
			).not.toBe((challengeB.projection as { metadata: { projectionDigest: string } }).metadata.projectionDigest);

			const competition = await readCtfDashboardSnapshot(reader);
			expect(competition.projectionStatus).toBe("current");
			expect(competition.canonical).toMatchObject({
				status: "available",
				metadata: { competitionId, canonicalRevision: 1 },
			});
			expect((competition.canonical as { metadata: { challengeId?: string } }).metadata.challengeId).toBeUndefined();
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
