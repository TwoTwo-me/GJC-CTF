import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { CanonicalEventLog, readCanonicalEvents } from "../../src/ctf/state/event-log";
import { DIGEST_A, EVIDENCE_DIGEST, FIXED_TIME } from "./fixtures";

async function temporaryStore(): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-events-"));
}

function runDraft(idempotencyKey: string, payload: Record<string, unknown> = { status: "created" }) {
	return {
		eventId: `event-${idempotencyKey}`,
		eventType: "run_created" as const,
		competitionId: "competition-1",
		challengeId: "challenge-one",
		runId: "run-1",
		idempotencyKey,
		actor: "worker-one",
		occurredAt: FIXED_TIME,
		payload,
		evidenceRefs: [EVIDENCE_DIGEST],
	};
}

describe("canonical CTF event log", () => {
	it("returns an existing event for duplicate idempotency and rejects conflicting payloads", async () => {
		const root = await temporaryStore();
		try {
			const log = new CanonicalEventLog(root, { competitionId: "competition-1", challengeId: "challenge-one" });
			const first = await log.appendDraft(runDraft("run-create-1"));
			expect(first.appended).toBe(true);
			expect(first.metadata).toMatchObject({ revision: 1, eventCount: 1, complete: true });
			const firstRaw = await fs.readFile(log.store.resolve(log.path), "utf8");
			expect(first.metadata.journalByteOffset).toBe(Buffer.byteLength(firstRaw, "utf8"));

			const duplicate = await log.appendDraft(runDraft("run-create-1"));
			expect(duplicate.appended).toBe(false);
			expect(duplicate.event.eventId).toBe(first.event.eventId);
			expect(duplicate.digest).toBe(first.digest);
			expect(duplicate.metadata.eventCount).toBe(1);

			await expect(log.appendDraft(runDraft("run-create-1", { status: "different" }))).rejects.toMatchObject({
				code: "idempotency_conflict",
			});
			await expect(
				log.appendDraft({ ...runDraft("run-create-2"), eventId: first.event.eventId }),
			).rejects.toMatchObject({
				code: "integrity_error",
			});

			const second = await log.appendDraft({
				...runDraft("run-start-1", { status: "started", label: "π" }),
				eventId: "event-run-start-1",
				eventType: "run_started",
			});
			expect(second.appended).toBe(true);
			const secondRaw = await fs.readFile(log.store.resolve(log.path), "utf8");
			expect(second.metadata.journalByteOffset).toBe(Buffer.byteLength(secondRaw, "utf8"));
			expect(second.event.revision).toBe(2);
			const replay = await readCanonicalEvents(root, {
				competitionId: "competition-1",
				challengeId: "challenge-one",
			});
			expect(replay.events.map(event => event.idempotencyKey)).toEqual(["run-create-1", "run-start-1"]);
			expect(replay.revision).toBe(2);
			expect(replay.digest).toBe(second.digest);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("isolates challenge journals within one workspace", async () => {
		const root = await temporaryStore();
		try {
			const challengeA = new CanonicalEventLog(root, {
				competitionId: "competition-1",
				challengeId: "challenge-one",
			});
			const challengeB = new CanonicalEventLog(root, {
				competitionId: "competition-1",
				challengeId: "challenge-two",
			});
			await challengeA.appendDraft(runDraft("run-a"));
			await challengeB.appendDraft({ ...runDraft("run-b"), challengeId: "challenge-two", runId: "run-2" });
			expect((await challengeA.read()).events).toHaveLength(1);
			expect((await challengeB.read()).events).toHaveLength(1);
			expect(challengeA.path).not.toBe(challengeB.path);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("refuses replay after the persisted hash chain is tampered with", async () => {
		const root = await temporaryStore();
		try {
			const log = new CanonicalEventLog(root, { competitionId: "competition-1", challengeId: "challenge-one" });
			await log.appendDraft(runDraft("run-create-1"));
			const second = await log.appendDraft({
				...runDraft("run-start-1", { status: "started" }),
				eventId: "event-run-start-1",
				eventType: "run_started",
			});
			const raw = await fs.readFile(log.store.resolve(log.path), "utf8");
			const lines = raw.trimEnd().split("\n");
			const tampered = JSON.parse(lines[1]) as Record<string, unknown>;
			tampered.previousEventDigest = DIGEST_A;
			await fs.writeFile(log.store.resolve(log.path), `${lines[0]}\n${JSON.stringify(tampered)}\n`);

			await expect(log.read()).rejects.toMatchObject({ code: "integrity_error" });
			expect(second.event.revision).toBe(2);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects a partial tail rather than silently repairing the event log", async () => {
		const root = await temporaryStore();
		try {
			const log = new CanonicalEventLog(root, { competitionId: "competition-1", challengeId: "challenge-one" });
			await log.appendDraft(runDraft("run-create-1"));
			const target = log.store.resolve(log.path);
			const raw = await fs.readFile(target, "utf8");
			await fs.writeFile(target, `${raw}{"partial":true}`);
			await expect(log.read()).rejects.toMatchObject({ code: "integrity_error" });
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
