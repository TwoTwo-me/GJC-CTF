import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { claimProofDigest } from "../../src/ctf/contracts/intent";
import {
	CanonicalIntentStore,
	type ClaimVerificationInput,
	type ClaimVerificationResult,
} from "../../src/ctf/state/intent-store";
import { RunLeaseStore } from "../../src/ctf/state/lease";
import { makeIntent } from "./fixtures";

async function temporaryStore(): Promise<string> {
	return fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-intent-"));
}

describe("canonical CTF intent store", () => {
	it("records a typed rejection when claim proof is unavailable and replays it idempotently", async () => {
		const root = await temporaryStore();
		try {
			const store = new CanonicalIntentStore(root);
			const intent = makeIntent();
			const first = await store.submit(intent);
			expect(first.duplicate).toBe(false);
			expect(first.outcome.accepted).toBe(false);
			expect(first.outcome.rejectionCode).toBe("stale_claim");
			expect(first.event.eventType).toBe("intent_rejected");
			expect(first.event.payload).toMatchObject({ rejectionCode: "stale_claim", intentId: intent.intentId });
			expect(first.outcome.canonicalRevision).toBe(1);

			const repeated = await store.submit(intent);
			expect(repeated.duplicate).toBe(true);
			expect(repeated.outcome).toEqual(first.outcome);
			expect(repeated.event).toEqual(first.event);
			expect(await store.readOutcomes()).toHaveLength(1);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects a conflicting idempotency payload instead of creating a second outcome", async () => {
		const root = await temporaryStore();
		try {
			const store = new CanonicalIntentStore(root);
			await store.submit(makeIntent());
			const conflicting = makeIntent({ payload: { action: "different" } });
			await expect(store.submit(conflicting)).rejects.toMatchObject({ code: "idempotency_conflict" });
			expect((await store.readOutcomes()).length).toBe(1);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("rejects a duplicate whose immutable claim identity changed", async () => {
		const root = await temporaryStore();
		try {
			const store = new CanonicalIntentStore(root);
			const original = makeIntent();
			await store.submit(original);
			const changedClaim = makeIntent({ claimToken: "claim-two" });
			await expect(store.submit(changedClaim)).rejects.toMatchObject({ code: "idempotency_conflict" });
			expect(await store.readOutcomes()).toHaveLength(1);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("rejects malformed intents with a typed contract error before writing state", async () => {
		const root = await temporaryStore();
		try {
			const store = new CanonicalIntentStore(root);
			await expect(store.submit({ intentId: "malformed" })).rejects.toMatchObject({ code: "invalid_registration" });
			expect(await store.readOutcomes()).toEqual([]);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
	it("accepts an intent with a current claim proof and fenced team run", async () => {
		const root = await temporaryStore();
		try {
			const leaseStore = new RunLeaseStore(root, { competitionId: "competition-1", challengeId: "challenge-one" });
			const owner = await leaseStore.acquire({
				competitionId: "competition-1",
				challengeId: "challenge-one",
				runId: "run-1",
				ownerId: "team-owner",
				teamName: "team-one",
				state: "running",
				processIdentity: { pid: 1, hostFingerprint: "fixture-host" },
				leaseDurationMs: 60_000,
			});
			const observedAt = new Date().toISOString();
			const expiresAt = new Date(Date.now() + 30_000).toISOString();
			const proof = {
				teamName: "team-one",
				taskId: "task-one",
				workerId: "worker-one",
				claimToken: "claim-one",
				lane: "lane-one",
				requiredRole: "solver",
				teamStateRevision: 1,
				lifecycleState: "running" as const,
				startupAckDigest: "a".repeat(64),
				claimDigest: "b".repeat(64),
				observedAt,
				expiresAt,
				source: "gjc-team-api" as const,
			};
			const intent = makeIntent({
				runFencingToken: owner.fencingToken,
				claimExpiresAt: expiresAt,
				claimProofDigest: claimProofDigest(proof),
			});
			const currentSnapshot: ClaimVerificationResult = {
				teamName: proof.teamName,
				taskId: proof.taskId,
				workerId: proof.workerId,
				claimToken: proof.claimToken,
				lane: proof.lane,
				requiredRole: proof.requiredRole,
				teamStateRevision: proof.teamStateRevision,
				runFencingToken: owner.fencingToken,
				expiresAt: proof.expiresAt,
			};
			const claimVerifier = {
				verifyCurrentClaim: async (_input: ClaimVerificationInput) => currentSnapshot,
			};
			const store = new CanonicalIntentStore(root, undefined, leaseStore, { claimVerifier });
			const result = await store.submit(intent, proof);
			expect(result.outcome.accepted).toBe(true);
			expect(result.event.eventType).toBe("intent_accepted");
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
