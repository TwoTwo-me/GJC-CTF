import { afterEach, describe, expect, it, setSystemTime, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { CTF_CAMPAIGN_HARD_STOP, runCtfCampaign } from "../../src/ctf/campaign/controller";
import { canonicalDigest, sha256Hex } from "../../src/ctf/contracts/digest";
import type { CorpusEntry, MaterializedCorpus } from "../../src/ctf/corpus";
import { LACTF_2026_CORPUS_SOURCES } from "../../src/ctf/corpus";
import type { CtfSolverBackend, CtfTerminationRequest } from "../../src/ctf/runtime/scheduler";

const roots: string[] = [];
const digest = sha256Hex("campaign-fixture");
const producerDigest = sha256Hex("campaign-producer");
const routeDigest = sha256Hex("campaign-route");

function corpusEntry(): CorpusEntry {
	const source = LACTF_2026_CORPUS_SOURCES[0];
	if (source === undefined) throw new Error("fixture source missing");
	return {
		source,
		provenance: {
			repositoryUrl: source.repositoryUrl,
			sourceCommit: source.sourceCommit,
			challengePath: source.challengePath,
			files: source.visibleFiles.map(relativePath => ({ relativePath, sha256: digest })),
		},
	};
}

async function fixture(): Promise<Readonly<{ root: string; corpus: MaterializedCorpus }>> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-ctf-campaign-"));
	roots.push(root);
	const entry = corpusEntry();
	const materializedRoot = path.join(root, "materialized", entry.source.challengeId);
	await Promise.all(
		entry.source.visibleFiles.map(async relativePath => {
			const file = path.join(materializedRoot, relativePath);
			await fs.mkdir(path.dirname(file), { recursive: true });
			await fs.writeFile(file, "campaign-fixture", "utf8");
		}),
	);
	return {
		root,
		corpus: {
			challengeId: entry.source.challengeId,
			root: materializedRoot,
			provenance: entry.provenance,
			scored: false,
		},
	};
}

afterEach(async () => {
	vi.useRealTimers();
	setSystemTime();
	await Promise.all(roots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});

function authorityFor() {
	return Promise.resolve({
		fencingToken: 1,
		intentId: "intent-1",
		skillDigest: "b".repeat(64),
		sandboxPolicyDigest: "c".repeat(64),
	});
}

function options(
	root: string,
	corpus: MaterializedCorpus,
	backend: CtfSolverBackend,
	maxAttempts: number,
	additional: Partial<Parameters<typeof runCtfCampaign>[0]> = {},
): Parameters<typeof runCtfCampaign>[0] {
	return {
		campaignId: "campaign-1",
		competitionId: "competition-1",
		challenges: [corpusEntry()],
		store: root,
		backend: {
			...backend,
			terminate: backend.terminate ?? (async () => {}),
			solve: async request => {
				const outcome = await backend.solve(request);
				return outcome.status === "candidate" ? { ...outcome, producerDigest, routeDigest } : outcome;
			},
		},
		authorityFor,
		candidateLineageFor: async () => ({ producerDigest, routeDigest }),
		terminateAuthority: async ({ ownerId }) => ({ ownerId }),
		concurrency: 1,
		maxAttempts,
		materialize: Object.assign(async () => corpus, { terminate: async () => {} }),
		...additional,
	};
}
async function rewriteCampaignState(root: string, mutate: (challenge: Record<string, unknown>) => void): Promise<void> {
	const target = path.join(root, "campaigns", "campaign-1.json");
	const state = JSON.parse(await fs.readFile(target, "utf8")) as Record<string, unknown>;
	if (!Array.isArray(state.challenges) || !state.challenges[0] || typeof state.challenges[0] !== "object")
		throw new Error("campaign fixture state is invalid");
	mutate(state.challenges[0] as Record<string, unknown>);
	const { stateDigest: _stateDigest, ...basis } = state;
	state.stateDigest = canonicalDigest(basis);
	await fs.writeFile(target, JSON.stringify(state), "utf8");
}

describe("durable CTF campaign", () => {
	it("binds materialized provenance and resumes without rerunning a candidate", async () => {
		const { root, corpus } = await fixture();
		let calls = 0;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async request => {
				calls += 1;
				expect(request.materialized?.root).toBe(corpus.root);
				expect(request.materialized?.provenanceDigest).toHaveLength(64);
				return {
					status: "candidate",
					artifacts: ["candidate.txt"],
					artifactEvidence: [{ path: "candidate.txt", digest: "d".repeat(64), size: 42 }],
				};
			},
		};
		const first = await runCtfCampaign(options(root, corpus, backend, 2));
		expect(first.state.challenges[0]).toMatchObject({ status: "candidate" });
		expect(first.state.challenges[0]?.attempts).toHaveLength(1);
		expect(first.state.challenges[0]?.attempts[0]?.artifactEvidence).toEqual([
			{ path: "candidate.txt", digest: "d".repeat(64), size: 42 },
		]);
		expect(first.state.challenges[0]?.attempts[0]).toMatchObject({ producerDigest, routeDigest });
		const resumed = await runCtfCampaign(options(root, corpus, backend, 2));
		expect(resumed.state.stateDigest).toBe(first.state.stateDigest);
		expect(calls).toBe(1);
	});

	it("retains failures and uses monotonic attempt numbers across restart", async () => {
		const { root, corpus } = await fixture();
		let calls = 0;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async () => {
				calls += 1;
				return calls === 1 ? { status: "failed", reason: "first failure" } : { status: "candidate" };
			},
		};
		const failed = await runCtfCampaign(options(root, corpus, backend, 1));
		expect(failed.state.challenges[0]?.attempts.map(attempt => attempt.attempt)).toEqual([1]);
		const recovered = await runCtfCampaign(options(root, corpus, backend, 2));
		expect(recovered.state.challenges[0]?.attempts.map(attempt => attempt.attempt)).toEqual([1, 2]);
		expect(recovered.state.challenges[0]?.attempts.map(attempt => attempt.status)).toEqual(["failure", "candidate"]);
	});

	it("stops at the exact UTC deadline without invoking materialization or backend", async () => {
		setSystemTime(new Date(CTF_CAMPAIGN_HARD_STOP));
		const { root, corpus } = await fixture();
		let invoked = false;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async () => {
				invoked = true;
				return { status: "candidate" };
			},
		};
		const result = await runCtfCampaign(options(root, corpus, backend, 1));
		expect(result.stopped).toBe(true);
		expect(result.runs).toEqual([]);
		expect(invoked).toBe(false);
	});

	it("races never-resolving materialization against the hard deadline", async () => {
		vi.useFakeTimers({ now: new Date("2026-08-08T23:59:59.999Z") });
		const { root, corpus } = await fixture();
		let backendCalls = 0;
		const started = Promise.withResolvers<void>();
		let materializerSignal: AbortSignal | undefined;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async () => {
				backendCalls += 1;
				return { status: "candidate" };
			},
		};
		const result = runCtfCampaign(
			options(root, corpus, backend, 1, {
				materialize: Object.assign(
					async ({ signal }: Readonly<{ signal: AbortSignal }>) => {
						materializerSignal = signal;
						started.resolve();
						return await new Promise<MaterializedCorpus>(() => {});
					},
					{ terminate: async () => {} },
				),
			}),
		);
		await started.promise;
		vi.advanceTimersByTime(1);
		await Promise.resolve();
		const stopped = await result;
		expect(materializerSignal?.aborted).toBe(true);
		expect(backendCalls).toBe(0);
		expect(stopped.runs).toEqual([]);
		expect(stopped.state.challenges[0]?.attempts).toEqual([]);
		expect(stopped.stopped).toBe(true);
	});
	it("waits for materializer termination acknowledgment and rejects its late artifact", async () => {
		const { root, corpus } = await fixture();
		const controller = new AbortController();
		const started = Promise.withResolvers<void>();
		const acknowledge = Promise.withResolvers<void>();
		const lateMaterialization = Promise.withResolvers<MaterializedCorpus>();
		let ownerId: string | undefined;
		const lateWrites: string[] = [];
		const materialize = Object.assign(
			async (input: Readonly<{ challengeId: string; attempt: number; ownerId: string; signal: AbortSignal }>) => {
				ownerId = input.ownerId;
				started.resolve();
				const materialized = await lateMaterialization.promise;
				lateWrites.push("late.txt");
				return materialized;
			},
			{
				terminate: async (request: CtfTerminationRequest) => {
					if (ownerId === undefined) throw new Error("materializer owner was not captured");
					expect(request.ownerId).toBe(ownerId);
					expect(request.runId).toBe(ownerId);
					await acknowledge.promise;
				},
			},
		);
		const result = runCtfCampaign(
			options(root, corpus, { id: "fixture-backend", solve: async () => ({ status: "candidate" }) }, 1, {
				materialize,
				signal: controller.signal,
			}),
		);
		await started.promise;
		controller.abort("cancel");
		await Promise.resolve();
		lateMaterialization.resolve(corpus);
		expect(lateWrites).toEqual([]);
		acknowledge.resolve();
		const stopped = await result;
		expect(stopped.runs).toEqual([]);
		expect(stopped.state.challenges[0]?.attempts).toEqual([]);
	});
	it("threads preparation termination through cancellable campaign scheduling", async () => {
		const { root, corpus } = await fixture();
		const controller = new AbortController();
		const started = Promise.withResolvers<void>();
		let preparationOwnerId: string | undefined;
		let terminatedOwnerId: string | undefined;
		let terminationAttempts = 0;
		const result = runCtfCampaign(
			options(root, corpus, { id: "fixture-backend", solve: async () => ({ status: "candidate" }) }, 1, {
				signal: controller.signal,
				prepareRun: async ({ preparationOwnerId: ownerId }) => {
					preparationOwnerId = ownerId;
					started.resolve();
					return await new Promise<never>(() => {});
				},
				terminatePreparation: async request => {
					terminationAttempts += 1;
					terminatedOwnerId = request.ownerId;
				},
			}),
		);
		await started.promise;
		controller.abort("cancel");
		const stopped = await result;
		expect(terminatedOwnerId).toBe(preparationOwnerId);
		expect(terminationAttempts).toBe(1);
		expect(stopped.runs[0]?.results[0]).toMatchObject({ status: "cancelled" });
	});

	it("aborts never-resolving backend work at the hard deadline and persists stopped state", async () => {
		vi.useFakeTimers({ now: new Date("2026-08-08T23:59:59.999Z") });
		const { root, corpus } = await fixture();
		const started = Promise.withResolvers<void>();
		let backendSignal: AbortSignal | undefined;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async request => {
				backendSignal = request.signal;
				started.resolve();
				return await new Promise(() => {});
			},
		};
		const result = runCtfCampaign(options(root, corpus, backend, 1));
		await started.promise;
		vi.advanceTimersByTime(1);
		await Promise.resolve();
		const stopped = await result;
		expect(backendSignal?.aborted).toBe(true);
		expect(stopped.runs[0]?.status).toBe("cancelled");
		expect(stopped.state.challenges[0]?.attempts[0]?.status).toBe("unknown");
		expect(stopped.stopped).toBe(true);
	});

	it("rejects public frozen-clock bypass attempts", async () => {
		const { root, corpus } = await fixture();
		const backend: CtfSolverBackend = { id: "fixture-backend", solve: async () => ({ status: "candidate" }) };
		const bypass: Parameters<typeof runCtfCampaign>[0] & { now: () => Date } = {
			...options(root, corpus, backend, 1),
			now: () => new Date("2026-08-08T00:00:00.000Z"),
		};
		await expect(runCtfCampaign(bypass)).rejects.toThrow(/clock control/);
	});

	it("rejects corrupt durable state without overwriting it", async () => {
		const { root, corpus } = await fixture();
		const target = path.join(root, "campaigns", "campaign-1.json");
		await fs.mkdir(path.dirname(target), { recursive: true });
		await fs.writeFile(target, "{corrupt", "utf8");
		const backend: CtfSolverBackend = { id: "fixture-backend", solve: async () => ({ status: "candidate" }) };
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toThrow(/corrupt/);
		expect(await fs.readFile(target, "utf8")).toBe("{corrupt");
	});

	it("rejects a materializer that changes challenge identity", async () => {
		const { root, corpus } = await fixture();
		const backend: CtfSolverBackend = { id: "fixture-backend", solve: async () => ({ status: "candidate" }) };
		await expect(
			runCtfCampaign(
				options(root, corpus, backend, 1, {
					materialize: async () => ({ ...corpus, challengeId: "other-challenge" }),
				}),
			),
		).rejects.toThrow(/not pinned/);
	});
	it("rejects same-ID substituted provenance or bytes before backend invocation", async () => {
		const { root, corpus } = await fixture();
		let backendCalls = 0;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async () => {
				backendCalls += 1;
				return { status: "candidate" };
			},
		};
		await expect(
			runCtfCampaign(
				options(root, corpus, backend, 1, {
					materialize: async () => ({
						...corpus,
						provenance: {
							...corpus.provenance,
							files: corpus.provenance.files.map(file => ({
								...file,
								sha256: sha256Hex("substituted-provenance"),
							})),
						},
					}),
				}),
			),
		).rejects.toMatchObject({ code: "missing_provenance" });
		await fs.writeFile(path.join(corpus.root, "chall.txt"), "substituted bytes", "utf8");
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toMatchObject({
			code: "integrity_error",
		});
		expect(backendCalls).toBe(0);
	});
	it("rejects resume when a same-ID corpus or backend producer changes", async () => {
		const { root, corpus } = await fixture();
		let calls = 0;
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			solve: async () => {
				calls += 1;
				return { status: "candidate" };
			},
		};
		await runCtfCampaign(options(root, corpus, backend, 1));
		const substitutedEntry: CorpusEntry = {
			...corpusEntry(),
			provenance: {
				...corpusEntry().provenance,
				files: corpusEntry().provenance.files.map(file => ({
					...file,
					sha256: sha256Hex("same-id-substituted-corpus"),
				})),
			},
		};
		await expect(
			runCtfCampaign(options(root, corpus, backend, 1, { challenges: [substitutedEntry] })),
		).rejects.toMatchObject({ code: "integrity_error" });
		await expect(
			runCtfCampaign(options(root, corpus, { ...backend, id: "substituted-producer" }, 1)),
		).rejects.toMatchObject({ code: "integrity_error" });
		expect(calls).toBe(1);
	});

	it("rejects tampered serialized materialization routes and digests", async () => {
		const { root, corpus } = await fixture();
		const backend: CtfSolverBackend = { id: "fixture-backend", solve: async () => ({ status: "candidate" }) };
		await runCtfCampaign(options(root, corpus, backend, 1));
		const target = path.join(root, "campaigns", "campaign-1.json");
		const originalState = await fs.readFile(target, "utf8");
		await rewriteCampaignState(root, challenge => {
			const materialized = challenge.materialized as Record<string, unknown>;
			materialized.root = "relative-substitution";
		});
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toMatchObject({
			code: "integrity_error",
		});

		await fs.writeFile(target, originalState, "utf8");
		await rewriteCampaignState(root, challenge => {
			const materialized = challenge.materialized as Record<string, unknown>;
			materialized.provenanceDigest = "e".repeat(64);
		});
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toMatchObject({
			code: "integrity_error",
		});
		await fs.writeFile(target, originalState, "utf8");
		await rewriteCampaignState(root, challenge => {
			const materialized = challenge.materialized as Record<string, unknown>;
			const visibleFileDigests = materialized.visibleFileDigests as Record<string, unknown>;
			visibleFileDigests["chall.txt"] = "f".repeat(64);
		});
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toMatchObject({
			code: "integrity_error",
		});
	});
	it("rejects resumed candidates with missing, tampered, or mismatched route lineage", async () => {
		const { root, corpus } = await fixture();
		const backend: CtfSolverBackend = { id: "fixture-backend", solve: async () => ({ status: "candidate" }) };
		await runCtfCampaign(options(root, corpus, backend, 1));
		const target = path.join(root, "campaigns", "campaign-1.json");
		const originalState = await fs.readFile(target, "utf8");

		await rewriteCampaignState(root, challenge => {
			delete (challenge.attempts as Record<string, unknown>[])[0]?.routeDigest;
		});
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toMatchObject({
			code: "integrity_error",
		});

		await fs.writeFile(target, originalState, "utf8");
		await rewriteCampaignState(root, challenge => {
			(challenge.attempts as Record<string, unknown>[])[0]!.producerDigest = "c".repeat(64);
		});
		await expect(runCtfCampaign(options(root, corpus, backend, 1))).rejects.toMatchObject({
			code: "integrity_error",
		});

		await fs.writeFile(target, originalState, "utf8");
		await expect(
			runCtfCampaign(
				options(root, corpus, backend, 1, {
					candidateLineageFor: async () => ({ producerDigest, routeDigest: sha256Hex("mismatched-route") }),
				}),
			),
		).rejects.toMatchObject({ code: "integrity_error" });
	});
	it("rejects candidate outcomes without a complete lineage pair", async () => {
		const { root, corpus } = await fixture();
		const backend: CtfSolverBackend = {
			id: "fixture-backend",
			terminate: async () => {},
			solve: async () => ({ status: "candidate", producerDigest }),
		};
		await expect(runCtfCampaign(options(root, corpus, backend, 1, { backend }))).rejects.toMatchObject({
			code: "integrity_error",
		});
	});
});
