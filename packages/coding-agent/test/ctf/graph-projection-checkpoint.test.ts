import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createFixtureGraphEventWriterCapability } from "../../src/ctf/contracts/event";
import { CtfGraphProjection } from "../../src/ctf/graph/projection";
import { type CheckpointV1, checkpointDigestOf } from "../../src/ctf/state/checkpoint";
import { CanonicalEventLog } from "../../src/ctf/state/event-log";
import { DIGEST_A, EVIDENCE_DIGEST, FIXED_TIME } from "./fixtures";

async function temporaryStore(): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-graph-checkpoint-"));
}

async function appendGraphEvent(log: CanonicalEventLog): Promise<void> {
	await log.appendDraft(
		{
			eventId: "graph-event-1",
			eventType: "node_transition",
			competitionId: "competition-1",
			challengeId: "challenge-one",
			runId: "run-1",
			idempotencyKey: "graph-event-key-1",
			actor: "graph-writer",
			occurredAt: FIXED_TIME,
			payload: {
				fencingToken: 0,
				after: {
					nodeId: "action-one",
					type: "Action",
					state: "planned",
					confidence: 1,
					evidenceRefs: [EVIDENCE_DIGEST],
					provenance: {
						challengeId: "challenge-one",
						source: "graph-test",
						actor: "graph-writer",
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
			competitionId: "competition-1",
			challengeId: "challenge-one",
			runId: "run-1",
			actor: "graph-writer",
		}),
	);
}

describe("CTF graph checkpoint durability", () => {
	it("restarts from a durable checkpoint without exposing an in-memory checkpoint", async () => {
		const root = await temporaryStore();
		try {
			const identity = { competitionId: "competition-1", challengeId: "challenge-one" } as const;
			const log = new CanonicalEventLog(root, identity);
			await appendGraphEvent(log);
			const first = new CtfGraphProjection(log);
			const initial = first.snapshot();
			expect(initial.checkpoint).toBeUndefined();
			expect(initial.projectionStatus).toBe("rebuilding");

			const persisted = await first.refresh();
			expect(persisted.projectionStatus).toBe("current");
			expect(persisted.graph).toBeDefined();
			expect(persisted.checkpoint).toMatchObject({ canonicalRevision: 1 });
			const checkpoint = await first.checkpointStore.read();
			expect(checkpoint).toMatchObject({
				canonicalRevision: 1,
				projectionDigest: persisted.canonicalDigest,
				graphDigest: persisted.graph?.digest,
			});

			const restarted = new CtfGraphProjection(root, { identity });
			const restartSnapshot = await restarted.refresh();
			expect(restartSnapshot.projectionStatus).toBe("current");
			expect(restartSnapshot.graph?.digest).toBe(persisted.graph?.digest);
			expect(restartSnapshot.checkpoint).toMatchObject({
				canonicalRevision: 1,
				canonicalDigest: persisted.canonicalDigest,
			});
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("fails closed when the persisted graph digest is corrupt", async () => {
		const root = await temporaryStore();
		try {
			const identity = { competitionId: "competition-1", challengeId: "challenge-one" } as const;
			const log = new CanonicalEventLog(root, identity);
			await appendGraphEvent(log);
			const projection = new CtfGraphProjection(log);
			await projection.refresh();
			const checkpoint = await projection.checkpointStore.read();
			expect(checkpoint).toBeDefined();
			const { checkpointDigest: _digest, ...base } = checkpoint as CheckpointV1;
			const forgedBase = { ...base, graphDigest: DIGEST_A };
			const forged = JSON.stringify({
				...forgedBase,
				checkpointDigest: checkpointDigestOf(forgedBase),
			});
			await fs.writeFile(projection.checkpointStore.store.resolve(projection.checkpointStore.path), forged);

			const failed = new CtfGraphProjection(root, { identity });
			await expect(failed.refresh()).rejects.toMatchObject({ code: "digest_mismatch" });
			expect(failed.snapshot().projectionStatus).toBe("integrity_error");
			expect(failed.snapshot().checkpoint).toBeUndefined();
			expect(
				await fs.readFile(projection.checkpointStore.store.resolve(projection.checkpointStore.path), "utf8"),
			).toBe(forged);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
