import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { Digest } from "../../src/ctf/contracts/digest";
import { evaluationLineageDigest, verifiedEvaluationEvidenceDigest } from "../../src/ctf/contracts/evaluation";
import { oracleResultDigestV2 } from "../../src/ctf/contracts/oracle";
import { effectiveSkillDigest } from "../../src/ctf/contracts/skill";
import {
	createUnavailableRun,
	prepareCtfSolverRun,
	recordVerifiedEvaluationEvidence,
	resumeUnavailableRun,
} from "../../src/ctf/runtime/run-orchestrator";
import { loadCtfSkillIdentity } from "../../src/ctf/skills/identity-loader";
import { CanonicalEventLog } from "../../src/ctf/state/event-log";
import { RunLeaseStore } from "../../src/ctf/state/lease";
import { initCtfWorkspace, registerChallenge } from "../../src/ctf/workspace";
import { makeDescriptor, SKILL } from "./fixtures";

const roots: string[] = [];

async function tempRoot(): Promise<string> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-run-"));
	roots.push(root);
	return root;
}

afterEach(async () => {
	await Promise.all(roots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});
const DIGEST_A = "a".repeat(64) as Digest;
const DIGEST_B = "b".repeat(64) as Digest;
const DIGEST_C = "c".repeat(64) as Digest;

function anchoredEvidence(input: {
	competitionId: string;
	runId: string;
	challengeId: string;
	fencingToken: number;
	evaluationId?: string;
}) {
	const identity = {
		evaluationId: input.evaluationId ?? "evaluation-receipt",
		competitionId: input.competitionId,
		runId: input.runId,
		challengeId: input.challengeId,
		nonce: "nonce-receipt",
		candidateDigest: DIGEST_A,
		inputDigest: DIGEST_B,
		instanceCommitmentDigest: DIGEST_C,
	};
	const oracleResult = {
		schemaVersion: "ctf-oracle-result-2" as const,
		oracleId: "oracle-v2",
		identity,
		verdict: "pass" as const,
		verifierVersion: "v2",
		outputDigest: DIGEST_A,
		sanitizedSummary: "pass" as const,
		signature: "synthetic-signature",
	};
	const lineageUnsigned = {
		schemaVersion: "ctf-evaluation-lineage-1" as const,
		runId: input.runId,
		challengeId: input.challengeId,
		descriptorDigest: DIGEST_A,
		specDigest: DIGEST_A,
		corpusDigest: DIGEST_A,
		sourceDigest: DIGEST_A,
		visiblePolicyDigest: DIGEST_A,
		toolDigest: DIGEST_A,
		backendDigest: DIGEST_A,
		runtimeDigest: DIGEST_A,
		safetyDigest: DIGEST_A,
		limitsDigest: DIGEST_A,
		calibrationDigest: DIGEST_A,
		preflightDigest: DIGEST_A,
		candidateDigest: identity.candidateDigest,
		inputDigest: identity.inputDigest,
		instanceCommitmentDigest: identity.instanceCommitmentDigest,
		verifiedOracleDigest: oracleResultDigestV2(oracleResult),
	};
	const lineage = { ...lineageUnsigned, lineageDigest: evaluationLineageDigest(lineageUnsigned) };
	const evidenceUnsigned = {
		schemaVersion: "ctf-verified-evaluation-evidence-1" as const,
		kind: "evidence" as const,
		evaluationId: identity.evaluationId,
		competitionId: input.competitionId,
		runId: input.runId,
		challengeId: input.challengeId,
		lineage,
		oracleResult,
		oracleRegistryDigest: DIGEST_A,
		registrySignerFingerprint: DIGEST_B,
		resultSignerFingerprint: DIGEST_C,
		fencingToken: input.fencingToken,
	};
	return { ...evidenceUnsigned, receiptDigest: verifiedEvaluationEvidenceDigest(evidenceUnsigned) };
}

describe("CTF blocked run lifecycle", () => {
	it("persists a fenced blocked run and reads it during resume", async () => {
		const root = await tempRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());

		const result = await createUnavailableRun(workspace, "challenge-one", "competition");
		const resumed = await resumeUnavailableRun(workspace, result.runId);
		expect(result.status).toBe("unavailable");
		expect(resumed).toMatchObject({ runId: result.runId, challengeId: "challenge-one", status: "unavailable" });

		const events = await new CanonicalEventLog(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(events.events.map(event => event.eventType)).toEqual(["run_created", "run_started", "run_terminal"]);
		expect(events.events.at(-1)?.payload).toMatchObject({ state: "blocked" });
	});

	it("persists a prepared solver run and seals candidates pending oracle review", async () => {
		const root = await tempRoot();
		const effectiveSkill = await loadCtfSkillIdentity({ competitionRoot: root });
		const initialized = await initCtfWorkspace(root, "test-tool", {
			skill: {
				id: effectiveSkill.id,
				version: effectiveSkill.version,
				digest: effectiveSkillDigest(effectiveSkill),
			},
		});
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const prepared = await prepareCtfSolverRun(workspace, {
			challengeId: "challenge-one",
			runId: "solver-run-one",
			mode: "competition",
			backendId: "backend-local",
		});

		expect(prepared.authority).toMatchObject({
			fencingToken: 1,
			intentId: "solver-run-one:leader-execution",
		});
		await prepared.finalize({ status: "candidate", artifacts: ["candidate.txt"] });

		const events = await new CanonicalEventLog(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(events.events.map(event => event.eventType)).toEqual(["run_created", "run_started", "run_terminal"]);
		expect(events.events.at(-1)?.payload).toMatchObject({
			state: "blocked",
			reason: "candidate_pending_trusted_oracle",
			backendId: "backend-local",
		});
		const owner = await new RunLeaseStore(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(owner).toMatchObject({ runId: "solver-run-one", state: "blocked", fencingToken: 1 });
	});
	it("terminalizes a prepared solver run as cancelled when the deadline signal aborts", async () => {
		const root = await tempRoot();
		const effectiveSkill = await loadCtfSkillIdentity({ competitionRoot: root });
		const initialized = await initCtfWorkspace(root, "test-tool", {
			skill: {
				id: effectiveSkill.id,
				version: effectiveSkill.version,
				digest: effectiveSkillDigest(effectiveSkill),
			},
		});
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const controller = new AbortController();
		const prepared = await prepareCtfSolverRun(workspace, {
			challengeId: "challenge-one",
			runId: "solver-run-cancelled",
			mode: "competition",
			backendId: "backend-local",
			signal: controller.signal,
		});
		controller.abort("deadline");
		await expect(prepared.finalize({ status: "candidate" }, { signal: controller.signal })).resolves.toMatchObject({
			status: "cancelled",
		});
		const events = await new CanonicalEventLog(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(events.events.at(-1)?.payload).toMatchObject({
			state: "aborted",
			reason: "solver_run_cancelled",
		});
		const owner = await new RunLeaseStore(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(owner).toMatchObject({ runId: "solver-run-cancelled", state: "aborted" });
	});
	it("makes prepared-run termination idempotent and prevents later candidate finalization", async () => {
		const root = await tempRoot();
		const effectiveSkill = await loadCtfSkillIdentity({ competitionRoot: root });
		const initialized = await initCtfWorkspace(root, "test-tool", {
			skill: {
				id: effectiveSkill.id,
				version: effectiveSkill.version,
				digest: effectiveSkillDigest(effectiveSkill),
			},
		});
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const prepared = await prepareCtfSolverRun(workspace, {
			challengeId: "challenge-one",
			runId: "solver-run-terminated",
			mode: "competition",
			backendId: "backend-local",
		});
		const request = {
			runId: "solver-run-terminated",
			challengeId: "challenge-one",
			ownerId: "solver-run-terminated",
			competitionId: workspace.manifest.competitionId,
			fencingToken: prepared.authority.fencingToken,
			reason: "budget_exhausted" as const,
		};
		await Promise.all([prepared.terminate!(request), prepared.terminate!(request)]);
		await expect(prepared.finalize({ status: "candidate" })).resolves.toMatchObject({ status: "cancelled" });
		const events = await new CanonicalEventLog(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(events.events.filter(event => event.eventType === "run_terminal")).toHaveLength(1);
		expect(events.events.at(-1)?.payload).toMatchObject({ state: "aborted" });
	});
	it("rejects an already-cancelled preparation before creating durable run state", async () => {
		const root = await tempRoot();
		const effectiveSkill = await loadCtfSkillIdentity({ competitionRoot: root });
		const initialized = await initCtfWorkspace(root, "test-tool", {
			skill: {
				id: effectiveSkill.id,
				version: effectiveSkill.version,
				digest: effectiveSkillDigest(effectiveSkill),
			},
		});
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const controller = new AbortController();
		controller.abort("deadline");
		await expect(
			prepareCtfSolverRun(workspace, {
				challengeId: "challenge-one",
				runId: "solver-run-never-started",
				mode: "competition",
				backendId: "backend-local",
				signal: controller.signal,
			}),
		).rejects.toMatchObject({ code: "invalid_transition" });
		const owner = await new RunLeaseStore(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(owner).toBeUndefined();
	});
	it("rejects renewal and takeover after a run is terminal", async () => {
		const root = await tempRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const result = await createUnavailableRun(workspace, "challenge-one", "competition");
		const lease = new RunLeaseStore(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		});
		const owner = await lease.read();
		expect(owner).toMatchObject({ runId: result.runId, state: "blocked" });
		if (!owner) throw new Error("expected blocked lease");
		await expect(
			lease.renew({
				runId: owner.runId,
				expectedFencingToken: owner.fencingToken,
				ownerId: owner.ownerId,
			}),
		).rejects.toMatchObject({ code: "invalid_transition" });
		await expect(
			lease.acquire({
				competitionId: owner.competitionId,
				challengeId: owner.challengeId,
				ownerId: "takeover-owner",
				takeoverOf: owner.runId,
				processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
				now: "2099-01-01T00:00:00.000Z",
			}),
		).rejects.toMatchObject({ code: "invalid_transition" });
	});
	it("records immutable anchored receipts only under the live run fence and leaves them unscored", async () => {
		const root = await tempRoot();
		const effectiveSkill = await loadCtfSkillIdentity({ competitionRoot: root });
		const initialized = await initCtfWorkspace(root, "test-tool", {
			skill: {
				id: effectiveSkill.id,
				version: effectiveSkill.version,
				digest: effectiveSkillDigest(effectiveSkill),
			},
		});
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const prepared = await prepareCtfSolverRun(workspace, {
			challengeId: "challenge-one",
			runId: "receipt-run",
			mode: "competition",
			backendId: "backend-local",
		});
		const receipt = anchoredEvidence({
			competitionId: workspace.manifest.competitionId,
			runId: "receipt-run",
			challengeId: "challenge-one",
			fencingToken: prepared.authority.fencingToken,
		});
		const request = {
			runId: "receipt-run",
			challengeId: "challenge-one",
			fencingToken: prepared.authority.fencingToken,
			evidence: receipt,
		};
		await expect(
			recordVerifiedEvaluationEvidence(workspace, {
				...request,
				evidence: anchoredEvidence({
					competitionId: "other-competition",
					runId: "receipt-run",
					challengeId: "challenge-one",
					fencingToken: prepared.authority.fencingToken,
				}),
			}),
		).rejects.toMatchObject({ code: "cross_challenge_reference" });
		await expect(
			recordVerifiedEvaluationEvidence(workspace, { ...request, runId: "other-run" }),
		).rejects.toMatchObject({
			code: "cross_challenge_reference",
		});
		await expect(
			recordVerifiedEvaluationEvidence(workspace, { ...request, challengeId: "other-challenge" }),
		).rejects.toMatchObject({ code: "cross_challenge_reference" });
		await expect(
			recordVerifiedEvaluationEvidence(workspace, {
				...request,
				fencingToken: prepared.authority.fencingToken + 1,
				evidence: anchoredEvidence({
					competitionId: workspace.manifest.competitionId,
					runId: "receipt-run",
					challengeId: "challenge-one",
					fencingToken: prepared.authority.fencingToken + 1,
				}),
			}),
		).rejects.toMatchObject({ code: "stale_run_fence" });
		await expect(
			recordVerifiedEvaluationEvidence(workspace, {
				...request,
				evidence: { ...receipt, receiptDigest: DIGEST_C },
			}),
		).rejects.toMatchObject({ code: "digest_mismatch" });

		const blocked = await recordVerifiedEvaluationEvidence(workspace, request);
		expect(blocked).toMatchObject({ state: "blocked", fencingToken: prepared.authority.fencingToken });
		const receiptPath = path.join(
			workspace.stateRoot,
			"runs",
			"receipt-run",
			"evidence",
			`${receipt.receiptDigest}.json`,
		);
		const persisted = await fs.readFile(receiptPath, "utf8");
		const retried = await recordVerifiedEvaluationEvidence(workspace, request);
		expect(retried).toEqual(blocked);
		expect(await fs.readFile(receiptPath, "utf8")).toBe(persisted);

		const events = await new CanonicalEventLog(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		}).read();
		expect(events.events.map(event => event.eventType)).toEqual([
			"run_created",
			"run_started",
			"run_heartbeat",
			"run_terminal",
		]);
		expect(events.events.at(-1)?.payload).toEqual({
			mode: "competition",
			state: "blocked",
			reason: "verified_evidence_pending_score_authority",
			fencingToken: prepared.authority.fencingToken,
		});
		expect(events.events.at(-1)?.evidenceRefs).toEqual([receipt.receiptDigest]);
		expect(JSON.stringify(events)).not.toMatch(/solved|passed|scored|denominator/i);
	});
	it("rejects stale fencing after an expired lease is taken over", async () => {
		const root = await tempRoot();
		const initialized = await initCtfWorkspace(root, "test-tool", { skill: SKILL });
		const workspace = await registerChallenge(initialized.workspace, makeDescriptor());
		const lease = new RunLeaseStore(workspace.stateRoot, {
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
		});
		const first = await lease.acquire({
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
			runId: "run-first",
			ownerId: "owner-first",
			processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
			leaseDurationMs: 1,
			now: "2026-01-01T00:00:00.000Z",
		});
		const second = await lease.acquire({
			competitionId: workspace.manifest.competitionId,
			challengeId: "challenge-one",
			runId: "run-second",
			ownerId: "owner-second",
			takeoverOf: first.runId,
			processIdentity: { pid: process.pid, hostFingerprint: os.hostname() },
			now: "2026-01-01T00:00:00.010Z",
		});
		expect(second.fencingToken).toBe(first.fencingToken + 1);
		await expect(
			lease.renew({
				runId: first.runId,
				expectedFencingToken: first.fencingToken,
				ownerId: first.ownerId,
				now: "2026-01-01T00:00:01.000Z",
			}),
		).rejects.toMatchObject({ code: "stale_run_fence" });
	});
});
