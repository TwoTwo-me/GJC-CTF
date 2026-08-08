import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { CheckpointStore, type CheckpointV1, checkpointDigestOf } from "../../src/ctf/state/checkpoint";
import { CanonicalEventLog } from "../../src/ctf/state/event-log";
import type { CtfStateStore } from "../../src/ctf/state/storage";
import type { RootedStoreOperationOptions } from "../../src/gjc-runtime/storage/rooted-store";
import { createRootedStore } from "../../src/gjc-runtime/storage/rooted-store";
import { DIGEST_A, DIGEST_B, DIGEST_C, EVIDENCE_DIGEST, FIXED_TIME } from "./fixtures";

async function temporaryStore(): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-checkpoints-"));
}

async function eventLog(root: string): Promise<CanonicalEventLog> {
	const log = new CanonicalEventLog(root, { competitionId: "competition-1", challengeId: "challenge-one" });
	await log.appendDraft({
		eventId: "event-1",
		eventType: "run_created",
		competitionId: "competition-1",
		challengeId: "challenge-one",
		runId: "run-1",
		idempotencyKey: "event-key-1",
		actor: "worker-one",
		occurredAt: FIXED_TIME,
		payload: { status: "created" },
		evidenceRefs: [EVIDENCE_DIGEST],
	});
	return log;
}

function withoutDigest(checkpoint: CheckpointV1): Omit<CheckpointV1, "checkpointDigest"> {
	const { checkpointDigest: _checkpointDigest, ...base } = checkpoint;
	return base;
}

describe("CTF checkpoint integrity", () => {
	it("rejects a forged canonical prefix without mutating the checkpoint file", async () => {
		const root = await temporaryStore();
		try {
			const log = await eventLog(root);
			const checkpoints = new CheckpointStore(root, log);
			const checkpoint = await checkpoints.checkpointHead();
			const target = checkpoints.store.resolve(checkpoints.path);
			const forgedBase = {
				...withoutDigest(checkpoint),
				canonicalDigest: DIGEST_A,
				lastEventDigest: DIGEST_A,
			};
			const forged = JSON.stringify({ ...forgedBase, checkpointDigest: checkpointDigestOf(forgedBase) });
			await fs.writeFile(target, forged);

			await expect(checkpoints.read()).rejects.toMatchObject({ code: "digest_mismatch" });
			expect(await fs.readFile(target, "utf8")).toBe(forged);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("rejects a forged journal byte offset", async () => {
		const root = await temporaryStore();
		try {
			const log = await eventLog(root);
			const checkpoints = new CheckpointStore(root, log);
			const checkpoint = await checkpoints.checkpointHead();
			const forgedBase = {
				...withoutDigest(checkpoint),
				journalByteOffset: checkpoint.journalByteOffset + 1,
			};
			const forged = JSON.stringify({ ...forgedBase, checkpointDigest: checkpointDigestOf(forgedBase) });
			await fs.writeFile(checkpoints.store.resolve(checkpoints.path), forged);

			await expect(checkpoints.read()).rejects.toMatchObject({ code: "integrity_error" });
			expect(await fs.readFile(checkpoints.store.resolve(checkpoints.path), "utf8")).toBe(forged);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects a forged checkpoint identity", async () => {
		const root = await temporaryStore();
		try {
			const log = await eventLog(root);
			const checkpoints = new CheckpointStore(root, log);
			const checkpoint = await checkpoints.checkpointHead();
			const forgedBase = { ...withoutDigest(checkpoint), competitionId: "competition-forged" };
			await fs.writeFile(
				checkpoints.store.resolve(checkpoints.path),
				JSON.stringify({ ...forgedBase, checkpointDigest: checkpointDigestOf(forgedBase) }),
			);

			await expect(checkpoints.read()).rejects.toMatchObject({ code: "cross_challenge_reference" });
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects same-revision graph and projection drift", async () => {
		const root = await temporaryStore();
		try {
			const log = await eventLog(root);
			const checkpoints = new CheckpointStore(root, log);
			const head = await log.read();
			const base = {
				competitionId: "competition-1",
				challengeId: "challenge-one",
				canonicalRevision: head.revision,
				canonicalDigest: head.digest,
				eventCount: head.eventCount,
				journalByteOffset: head.journalByteOffset!,
				graphDigest: DIGEST_A,
				projectionDigest: DIGEST_B,
				createdAt: FIXED_TIME,
			};
			await checkpoints.write(base);

			await expect(checkpoints.write({ ...base, graphDigest: DIGEST_C })).rejects.toMatchObject({
				code: "integrity_error",
			});
			await expect(checkpoints.write({ ...base, projectionDigest: DIGEST_C })).rejects.toMatchObject({
				code: "integrity_error",
			});
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("forces CTF durability over caller downgrade options", async () => {
		const root = await temporaryStore();
		try {
			const backing = createRootedStore(root);
			const calls: Array<RootedStoreOperationOptions | undefined> = [];
			const store: CtfStateStore = {
				root: backing.root,
				resolve: target => backing.resolve(target),
				writeJsonAtomic: (target, value, options) => {
					calls.push(options);
					return backing.writeJsonAtomic(target, value, options);
				},
				appendJsonl: (target, value, options) => {
					calls.push(options);
					return backing.appendJsonl(target, value, options);
				},
				withLock: (target, callback, options) => {
					calls.push(options);
					return backing.withLock(target, callback, options);
				},
			};
			const log = new CanonicalEventLog(store, { competitionId: "competition-1", challengeId: "challenge-one" });
			await log.appendDraft({
				eventId: "event-1",
				eventType: "run_created",
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-1",
				idempotencyKey: "event-key-1",
				actor: "worker-one",
				occurredAt: FIXED_TIME,
				payload: { status: "created" },
				evidenceRefs: [EVIDENCE_DIGEST],
			});
			const checkpoints = new CheckpointStore(store, log);
			await checkpoints.checkpointHead({ durability: "default" });
			const checkpointCalls = calls.filter(options => options?.durability !== undefined);
			expect(checkpointCalls.length).toBeGreaterThanOrEqual(2);
			expect(checkpointCalls.every(options => options?.durability === "ctf")).toBe(true);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects a checkpoint event log bound to a different storage root", async () => {
		const firstRoot = await temporaryStore();
		const secondRoot = await temporaryStore();
		try {
			const log = new CanonicalEventLog(firstRoot, { competitionId: "competition-1", challengeId: "challenge-one" });
			expect(() => new CheckpointStore(secondRoot, log)).toThrow("same root");
		} finally {
			await fs.rm(firstRoot, { recursive: true, force: true });
			await fs.rm(secondRoot, { recursive: true, force: true });
		}
	});
});
