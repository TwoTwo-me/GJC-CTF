import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { CheckpointStore } from "../../src/ctf/state/checkpoint";
import { CanonicalEventLog } from "../../src/ctf/state/event-log";
import { CanonicalIntentStore } from "../../src/ctf/state/intent-store";
import { makeIntent } from "./fixtures";

async function temporaryStore(): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-state-paths-"));
}

describe("challenge-scoped CTF state paths", () => {
	it("isolates event, intent, and checkpoint state for two challenges", async () => {
		const root = await temporaryStore();
		try {
			const eventA = new CanonicalEventLog(root, { competitionId: "competition-1", challengeId: "challenge-one" });
			const eventB = new CanonicalEventLog(root, { competitionId: "competition-1", challengeId: "challenge-two" });
			const intentA = new CanonicalIntentStore(root, eventA);
			const intentB = new CanonicalIntentStore(root, eventB);

			await intentA.submit(makeIntent());
			await intentB.submit(
				makeIntent({
					intentId: "intent-2",
					challengeId: "challenge-two",
					idempotencyKey: "intent-key-2",
				}),
			);

			expect(eventA.path).not.toBe(eventB.path);
			expect((await eventA.read()).events.map(event => event.challengeId)).toEqual(["challenge-one"]);
			expect((await eventB.read()).events.map(event => event.challengeId)).toEqual(["challenge-two"]);
			expect(intentA.outcomePath).not.toBe(intentB.outcomePath);
			expect((await intentA.readOutcomes()).map(outcome => outcome.intentId)).toEqual(["intent-1"]);
			expect((await intentB.readOutcomes()).map(outcome => outcome.intentId)).toEqual(["intent-2"]);

			const checkpointA = new CheckpointStore(root, eventA);
			const checkpointB = new CheckpointStore(root, eventB);
			await checkpointA.checkpointHead();
			await checkpointB.checkpointHead();
			expect(checkpointA.path).not.toBe(checkpointB.path);
			expect((await checkpointA.read())?.challengeId).toBe("challenge-one");
			expect((await checkpointB.read())?.challengeId).toBe("challenge-two");
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
