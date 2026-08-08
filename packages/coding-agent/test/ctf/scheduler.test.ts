import { describe, expect, it } from "bun:test";
import { CtfError } from "../../src/ctf/contracts/errors";
import {
	type CtfRunAuthority,
	type CtfRunTerminationRequest,
	type CtfSolverBackend,
	type CtfSolverOutcome,
	scheduleCtfRuns,
} from "../../src/ctf/runtime/scheduler";

const authority = {
	fencingToken: 1,
	intentId: "intent-1",
	skillDigest: "a".repeat(64),
	sandboxPolicyDigest: "b".repeat(64),
};

function unavailable(challengeId: string, mode: "competition" | "benchmark") {
	return Promise.resolve({
		schemaVersion: "ctf-run-result-1" as const,
		status: "unavailable" as const,
		runId: `run-${challengeId}`,
		competitionId: "competition-1",
		challengeId,
		mode,
		reason: "unavailable",
	});
}

describe("bounded CTF scheduler", () => {
	it("orders independent results canonically and limits concurrency", async () => {
		let active = 0;
		let maximum = 0;
		const backend: CtfSolverBackend = {
			id: "backend-1",
			async solve(request) {
				active += 1;
				maximum = Math.max(maximum, active);
				await Bun.sleep(request.challengeId === "alpha" ? 10 : 1);
				active -= 1;
				return { status: "candidate", artifacts: [request.challengeId] };
			},
		};
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["zeta", "alpha"],
			mode: "competition",
			concurrency: 1,
			backend,
			authorityFor: async () => authority,
			createUnavailable: unavailable,
		});
		expect(maximum).toBe(1);
		expect(result.status).toBe("complete");
		expect(result.results.map(item => item.challengeId)).toEqual(["alpha", "zeta"]);
		expect(result.aggregationDigest).toMatch(/^[a-f0-9]{64}$/);
	});
	it("rejects malformed or path-mismatched artifact evidence", async () => {
		const execute = (outcome: CtfSolverOutcome) =>
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				backend: { id: "backend-1", solve: async () => outcome },
				authority,
				createUnavailable: unavailable,
			});
		const malformed = await execute({
			status: "candidate",
			artifacts: ["alpha.txt"],
			artifactEvidence: [{ path: "alpha.txt", digest: "bad", size: 1 }],
		});
		expect(malformed.results[0]).toMatchObject({
			status: "failed",
			reason: "backend_invalid_artifact_evidence",
		});
		const mismatched = await execute({
			status: "candidate",
			artifacts: ["alpha.txt"],
			artifactEvidence: [{ path: "other.txt", digest: "d".repeat(64), size: 1 }],
		});
		expect(mismatched.results[0]).toMatchObject({
			status: "failed",
			reason: "backend_result_mismatch",
		});
	});
	it("validates transient retry terminal kinds without expanding durable reasons", async () => {
		const execute = (outcome: CtfSolverOutcome) =>
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				backend: { id: "backend-1", solve: async () => outcome },
				authority,
				createUnavailable: unavailable,
			});
		const exhausted = await execute({ status: "failed", terminalKind: "safe_exhaustion" });
		expect(exhausted.results[0]).toMatchObject({ status: "failed", reason: "solver_failed" });
		expect(JSON.stringify(exhausted.results[0])).not.toContain("terminalKind");
		const refused = await execute({ status: "blocked", terminalKind: "terminal_refusal" });
		expect(refused.results[0]).toMatchObject({ status: "blocked", reason: "solver_failed" });
		expect(JSON.stringify(refused.results[0])).not.toContain("terminalKind");
		const invalid = await execute({ status: "blocked", terminalKind: "safe_exhaustion" });
		expect(invalid.results[0]).toMatchObject({ status: "failed", reason: "backend_invalid_result" });
	});

	it("fails closed when run authority is missing", async () => {
		const backend: CtfSolverBackend = { id: "backend-1", solve: async () => ({ status: "candidate" }) };
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			backend,
			createUnavailable: unavailable,
		});
		expect(result.results[0]).toMatchObject({ status: "blocked", reason: "authority_unavailable" });
	});

	it("keeps unavailable mode auditable when no backend is admitted", async () => {
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["zeta", "alpha"],
			mode: "competition",
			concurrency: 2,
			createUnavailable: unavailable,
		});
		expect(result.results.map(item => item.challengeId)).toEqual(["alpha", "zeta"]);
		expect(result.results.every(item => item.status === "unavailable")).toBe(true);
	});
	it("refuses a budgeted production backend without termination acknowledgment", async () => {
		const backend: CtfSolverBackend = {
			id: "stuck-backend",
			solve: async () => new Promise<CtfSolverOutcome>(() => {}),
		};
		await expect(
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				budgetMs: 10,
				backend,
				authority,
				createUnavailable: unavailable,
			}),
		).rejects.toThrow(/termination acknowledgment/);
	});
	it("fences a budget-expired authority acquisition until its owner acknowledges termination", async () => {
		const started = Promise.withResolvers<void>();
		const acknowledge = Promise.withResolvers<void>();
		let authorityOwnerId: string | undefined;
		let ownerId: string | undefined;
		let completed = false;
		const scheduled = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			budgetMs: 1,
			backend: { id: "backend-1", solve: async () => ({ status: "candidate" }), terminate: async () => {} },
			authorityFor: async input => {
				authorityOwnerId = input.authorityOwnerId;
				started.resolve();
				return await new Promise<CtfRunAuthority>(() => {});
			},
			terminateAuthority: async request => {
				ownerId = request.ownerId;
				await acknowledge.promise;
				return { ownerId: request.ownerId };
			},
			createUnavailable: unavailable,
		}).then(value => {
			completed = true;
			return value;
		});
		await started.promise;
		await Bun.sleep(5);
		expect(completed).toBe(false);
		expect(ownerId).toBe(authorityOwnerId);
		acknowledge.resolve();
		await expect(scheduled).resolves.toMatchObject({ results: [{ status: "cancelled", reason: "cancelled" }] });
	});
	it("rejects an authority termination acknowledgment from a different owner", async () => {
		const controller = new AbortController();
		const started = Promise.withResolvers<void>();
		const scheduled = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: controller.signal,
			backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
			authorityFor: async () => {
				started.resolve();
				return await new Promise<CtfRunAuthority>(() => {});
			},
			terminateAuthority: async () => ({ ownerId: "wrong-owner" }),
			createUnavailable: unavailable,
		});
		await started.promise;
		controller.abort("deadline");
		await expect(scheduled).rejects.toThrow(/owner mismatch/);
	});
	it("does not persist backend diagnostic text as a run reason", async () => {
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			backend: {
				id: "backend-1",
				solve: async () => ({ status: "failed", reason: "private token: abc123" }),
			},
			authority,
			createUnavailable: unavailable,
		});
		expect(result.results[0]).toMatchObject({ status: "failed", reason: "solver_failed" });
		expect(JSON.stringify(result.results[0])).not.toContain("private token");
	});
	it("waits for owned termination acknowledgment and discards a late solver result", async () => {
		const started = Promise.withResolvers<void>();
		const acknowledge = Promise.withResolvers<void>();
		const lateResult = Promise.withResolvers<CtfSolverOutcome>();
		let terminal = false;
		let terminationRequest: CtfRunTerminationRequest | undefined;
		const backend: CtfSolverBackend = {
			id: "owned-backend",
			solve: async () => {
				started.resolve();
				return await lateResult.promise;
			},
			terminate: async request => {
				terminationRequest = request;
				await acknowledge.promise;
			},
		};
		const result = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			budgetMs: 1,
			backend,
			authority,
			createUnavailable: unavailable,
		}).then(value => {
			terminal = true;
			return value;
		});
		await started.promise;
		await Bun.sleep(5);
		expect(terminal).toBe(false);
		lateResult.resolve({ status: "candidate", artifacts: ["late.txt"] });
		expect(terminal).toBe(false);
		acknowledge.resolve();
		expect(terminationRequest).toMatchObject({
			competitionId: "competition-1",
			challengeId: "alpha",
			fencingToken: authority.fencingToken,
			reason: "budget_exhausted",
		});
		expect(terminationRequest?.ownerId).toBe(terminationRequest?.runId);
		await expect(result).resolves.toMatchObject({
			results: [{ status: "cancelled" }],
		});
	});
	it("waits for finalizer termination acknowledgment and discards its late artifact", async () => {
		const controller = new AbortController();
		const finalizerStarted = Promise.withResolvers<void>();
		const acknowledge = Promise.withResolvers<void>();
		const lateFinalization = Promise.withResolvers<CtfSolverOutcome | undefined>();
		const lateArtifacts: string[] = [];
		let terminal = false;
		let terminationRequest: CtfRunTerminationRequest | undefined;
		const result = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			budgetMs: 1_000,
			signal: controller.signal,
			backend: {
				id: "owned-backend",
				solve: async () => ({ status: "candidate", artifacts: ["solver.txt"] }),
				terminate: async () => {},
			},
			authority,
			prepareRun: async () => ({
				authority,
				finalize: async () => {
					finalizerStarted.resolve();
					const outcome = await lateFinalization.promise;
					lateArtifacts.push("late.txt");
					return outcome;
				},
				terminate: async request => {
					terminationRequest = request;
					await acknowledge.promise;
				},
			}),
			terminatePreparation: async () => {},
			createUnavailable: unavailable,
		}).then(value => {
			terminal = true;
			return value;
		});
		await finalizerStarted.promise;
		controller.abort("cancel");
		await Promise.resolve();
		expect(terminal).toBe(false);
		lateFinalization.resolve({ status: "candidate", artifacts: ["late.txt"] });
		expect(lateArtifacts).toEqual([]);
		acknowledge.resolve();
		expect(terminationRequest).toMatchObject({
			competitionId: "competition-1",
			challengeId: "alpha",
			fencingToken: authority.fencingToken,
			reason: "cancelled",
		});
		expect(terminationRequest?.ownerId).toBe(terminationRequest?.runId);
		const completed = await result;
		expect(completed.results[0]).toMatchObject({ status: "cancelled" });
		expect("artifacts" in completed.results[0]!).toBe(false);
	});

	it("keeps aggregate identity stable across fresh run ids", async () => {
		const backend: CtfSolverBackend = {
			id: "backend-1",
			solve: async request => ({ status: "candidate", artifacts: [request.challengeId] }),
		};
		const execute = (prefix: string) =>
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha", "zeta"],
				mode: "competition",
				concurrency: 2,
				backend,
				authorityFor: async () => authority,
				runIdFactory: ({ index }) => `${prefix}-${index}`,
				createUnavailable: unavailable,
			});
		const [first, second] = await Promise.all([execute("first"), execute("second")]);
		expect(first.aggregationDigest).toBe(second.aggregationDigest);
	});

	it("finalizes each prepared run with the backend outcome", async () => {
		const finalized: Array<{ challengeId: string; outcome: CtfSolverOutcome }> = [];
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha", "zeta"],
			mode: "competition",
			concurrency: 2,
			backend: {
				id: "backend-1",
				solve: async request => ({ status: "candidate", artifacts: [`${request.challengeId}.txt`] }),
			},
			prepareRun: async ({ challengeId }) => ({
				authority: { ...authority, intentId: `${challengeId}-intent` },
				finalize: async outcome => {
					finalized.push({ challengeId, outcome });
					return undefined;
				},
			}),
			createUnavailable: unavailable,
		});

		expect(result.results.every(run => run.status === "candidate")).toBe(true);
		expect(finalized.sort((a, b) => a.challengeId.localeCompare(b.challengeId))).toEqual([
			{ challengeId: "alpha", outcome: { status: "candidate", artifacts: ["alpha.txt"] } },
			{ challengeId: "zeta", outcome: { status: "candidate", artifacts: ["zeta.txt"] } },
		]);
	});
	it("finalizes a durable run once when authority setup fails", async () => {
		const finalized: CtfSolverOutcome[] = [];
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			backend: {
				id: "backend-1",
				solve: async () => ({ status: "candidate" }),
			},
			prepareRun: async () => ({
				get authority(): CtfRunAuthority {
					throw new Error("authority lookup failed");
				},
				finalize: async outcome => {
					finalized.push(outcome);
					return undefined;
				},
			}),
			createUnavailable: unavailable,
		});
		expect(result.results).toMatchObject([{ challengeId: "alpha", status: "failed", reason: "setup_failed" }]);
		expect(finalized).toEqual([{ status: "failed", reason: "solver setup failed" }]);
	});
	it("finalizes a durable run once when materialization fails", async () => {
		const finalized: CtfSolverOutcome[] = [];
		const result = await scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			backend: {
				id: "backend-1",
				solve: async () => ({ status: "candidate" }),
			},
			prepareRun: async () => ({
				authority,
				finalize: async outcome => {
					finalized.push(outcome);
					return undefined;
				},
			}),
			materializedFor: async () => {
				throw new Error("materialization failed");
			},
			terminateMaterialization: async () => {},
			createUnavailable: unavailable,
		});
		expect(result.results).toMatchObject([{ challengeId: "alpha", status: "failed", reason: "setup_failed" }]);
		expect(finalized).toEqual([{ status: "failed", reason: "solver setup failed" }]);
	});
	it("waits for materialization termination acknowledgment before finalizing cancellation", async () => {
		const finalized: CtfSolverOutcome[] = [];
		const controller = new AbortController();
		const materializationStarted = Promise.withResolvers<void>();
		const acknowledge = Promise.withResolvers<void>();
		const lateMaterialization = Promise.withResolvers<never>();
		let terminal = false;
		const result = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: controller.signal,
			backend: {
				id: "backend-1",
				solve: async () => ({ status: "candidate" }),
			},
			prepareRun: async () => ({
				authority,
				finalize: async outcome => {
					finalized.push(outcome);
					return undefined;
				},
				terminate: async () => {},
			}),
			materializedFor: async () => {
				materializationStarted.resolve();
				return await lateMaterialization.promise;
			},
			terminateMaterialization: async () => await acknowledge.promise,
			terminatePreparation: async () => {},
			createUnavailable: unavailable,
		}).then(value => {
			terminal = true;
			return value;
		});
		await materializationStarted.promise;
		controller.abort("deadline");
		await Promise.resolve();
		expect(terminal).toBe(false);
		expect(finalized).toEqual([]);
		acknowledge.resolve();
		const completed = await result;
		expect(completed.results).toMatchObject([{ challengeId: "alpha", status: "cancelled", reason: "cancelled" }]);
		expect(finalized).toEqual([{ status: "cancelled", reason: "run cancelled or budget exhausted" }]);
	});
	it("refuses competition materialization without termination acknowledgment", async () => {
		await expect(
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
				authority,
				materializedFor: async () => ({
					root: "fixture",
					provenanceDigest: "a".repeat(64),
				}),
				createUnavailable: unavailable,
			}),
		).rejects.toThrow(/materialization requires termination acknowledgment/);
	});
	it("propagates rejected termination acknowledgments after attempting every owner", async () => {
		const controller = new AbortController();
		const started = Promise.withResolvers<void>();
		let finalizerTerminationAttempts = 0;
		const scheduled = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: controller.signal,
			budgetMs: 1_000,
			backend: {
				id: "backend-1",
				solve: async () => {
					started.resolve();
					return await new Promise<CtfSolverOutcome>(() => {});
				},
				terminate: () => {
					throw new Error("backend termination rejected");
				},
			},
			authority,
			prepareRun: async () => ({
				authority,
				finalize: async outcome => outcome,
				terminate: async () => {
					finalizerTerminationAttempts += 1;
				},
			}),
			terminatePreparation: async () => {},
			createUnavailable: unavailable,
		});
		await started.promise;
		controller.abort("deadline");
		await expect(scheduled).rejects.toMatchObject({ code: "invalid_api_request" });
		expect(finalizerTerminationAttempts).toBe(1);
	});
	it("propagates an already-aborted prepared-finalizer rejection", async () => {
		const controller = new AbortController();
		const finalizerStarted = Promise.withResolvers<void>();
		const finalizerRelease = Promise.withResolvers<CtfSolverOutcome>();
		const scheduled = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: controller.signal,
			budgetMs: 1_000,
			backend: {
				id: "backend-1",
				solve: async () => ({ status: "candidate" }),
				terminate: async () => {},
			},
			authority,
			prepareRun: async () => ({
				authority,
				finalize: async () => {
					finalizerStarted.resolve();
					return await finalizerRelease.promise;
				},
				terminate: async () => {
					throw new Error("finalizer termination rejected");
				},
			}),
			terminatePreparation: async () => {},
			createUnavailable: unavailable,
		});
		await finalizerStarted.promise;
		controller.abort("deadline");
		await expect(scheduled).rejects.toMatchObject({ code: "invalid_api_request" });
	});
	it("fails closed before preparation when cancellable competition work lacks preparation termination", async () => {
		let preparations = 0;
		await expect(
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				signal: new AbortController().signal,
				backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
				authority,
				prepareRun: async () => {
					preparations += 1;
					return { authority, finalize: async outcome => outcome };
				},
				createUnavailable: unavailable,
			}),
		).rejects.toThrow(/preparation requires termination acknowledgment/);
		expect(preparations).toBe(0);
	});
	it("waits for preparation termination, fences late completion, and does not terminate twice", async () => {
		const controller = new AbortController();
		const started = Promise.withResolvers<void>();
		const acknowledge = Promise.withResolvers<void>();
		const latePreparation = Promise.withResolvers<{
			authority: CtfRunAuthority;
			finalize: (outcome: CtfSolverOutcome) => Promise<CtfSolverOutcome>;
			terminate: () => Promise<void>;
		}>();
		let preparationOwnerId: string | undefined;
		let terminationAttempts = 0;
		let finalizerTerminationAttempts = 0;
		let writesAllowed = true;
		const lateWrites: string[] = [];
		const scheduled = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: controller.signal,
			backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
			authority,
			prepareRun: async ({ preparationOwnerId: ownerId }) => {
				preparationOwnerId = ownerId;
				started.resolve();
				const prepared = await latePreparation.promise;
				if (writesAllowed) lateWrites.push("late-preparation-write");
				return prepared;
			},
			terminatePreparation: async request => {
				terminationAttempts += 1;
				if (preparationOwnerId === undefined) throw new Error("preparation owner was not captured");
				expect(request.ownerId).toBe(preparationOwnerId);
				expect(request.ownerId).not.toBe(request.runId);
				writesAllowed = false;
				await acknowledge.promise;
			},
			createUnavailable: unavailable,
		});
		await started.promise;
		controller.abort("deadline");
		await Promise.resolve();
		latePreparation.resolve({
			authority,
			finalize: async outcome => outcome,
			terminate: async () => {
				finalizerTerminationAttempts += 1;
			},
		});
		expect(lateWrites).toEqual([]);
		acknowledge.resolve();
		await expect(scheduled).resolves.toMatchObject({ results: [{ status: "cancelled" }] });
		expect(terminationAttempts).toBe(1);
		expect(finalizerTerminationAttempts).toBe(0);
	});
	it("waits for cooperative preparation and finalization cancellation", async () => {
		const preparationController = new AbortController();
		let preparationSignal: AbortSignal | undefined;
		const preparationStarted = Promise.withResolvers<void>();
		const preparationRun = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: preparationController.signal,
			backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
			prepareRun: async ({ signal }) => {
				preparationSignal = signal;
				preparationStarted.resolve();
				const cancelled = Promise.withResolvers<never>();
				signal.addEventListener("abort", () => cancelled.reject(new Error("cancelled")), { once: true });
				return await cancelled.promise;
			},
			terminatePreparation: async () => {},
			createUnavailable: unavailable,
		});
		await preparationStarted.promise;
		preparationController.abort("deadline");
		const preparation = await preparationRun;
		expect(preparation.results[0]).toMatchObject({ status: "cancelled" });
		expect(preparationSignal?.aborted).toBe(true);

		const finalizationController = new AbortController();
		let finalizationSignal: AbortSignal | undefined;
		const finalizationStarted = Promise.withResolvers<void>();
		const finalizationRun = scheduleCtfRuns({
			competitionId: "competition-1",
			challengeIds: ["alpha"],
			mode: "competition",
			concurrency: 1,
			signal: finalizationController.signal,
			backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
			prepareRun: async () => ({
				authority,
				finalize: async (_outcome, context) => {
					finalizationSignal = context?.signal;
					finalizationStarted.resolve();
					const cancelled = Promise.withResolvers<CtfSolverOutcome>();
					context?.signal.addEventListener(
						"abort",
						() => cancelled.resolve({ status: "cancelled", reason: "run cancelled or budget exhausted" }),
						{ once: true },
					);
					return await cancelled.promise;
				},
				terminate: async () => {},
			}),
			terminatePreparation: async () => {},
			createUnavailable: unavailable,
		});
		await finalizationStarted.promise;
		finalizationController.abort("deadline");
		const finalization = await finalizationRun;
		expect(finalizationSignal?.aborted).toBe(true);
		expect(finalization.results[0]).toMatchObject({ status: "cancelled" });
	});
	it("does not hide terminal persistence failure behind cancellation", async () => {
		const controller = new AbortController();
		await expect(
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				signal: controller.signal,
				backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
				prepareRun: async () => {
					controller.abort("deadline");
					throw new CtfError("integrity_error", "terminal persistence interrupted");
				},
				terminatePreparation: async () => {},
				createUnavailable: unavailable,
			}),
		).rejects.toMatchObject({ code: "integrity_error" });
	});
	it("propagates terminal finalization errors", async () => {
		await expect(
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				backend: {
					id: "backend-1",
					solve: async () => ({ status: "candidate" }),
				},
				prepareRun: async () => ({
					authority,
					finalize: async () => {
						throw new Error("terminal persistence failed");
					},
				}),
				createUnavailable: unavailable,
			}),
		).rejects.toThrow("terminal persistence failed");
	});
	it("rejects invalid or duplicate run ids before preparation", async () => {
		let preparations = 0;
		const execute = (runIdFactory: Parameters<typeof scheduleCtfRuns>[0]["runIdFactory"]) =>
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha", "zeta"],
				mode: "competition",
				concurrency: 2,
				backend: { id: "backend-1", solve: async () => ({ status: "candidate" }) },
				authorityFor: async () => authority,
				runIdFactory,
				prepareRun: async () => {
					preparations += 1;
					return { authority, finalize: async outcome => outcome };
				},
				createUnavailable: unavailable,
			});
		await expect(execute(() => "same-run")).rejects.toThrow(/run ids must be valid and unique/);
		await expect(execute(() => "../invalid")).rejects.toThrow(/run ids must be valid and unique/);
		expect(preparations).toBe(0);
	});
	it("rejects duplicate and noncanonical artifact evidence", async () => {
		const execute = (artifacts: string[], artifactEvidence: Array<{ path: string; digest: string; size: number }>) =>
			scheduleCtfRuns({
				competitionId: "competition-1",
				challengeIds: ["alpha"],
				mode: "competition",
				concurrency: 1,
				backend: { id: "backend-1", solve: async () => ({ status: "candidate", artifacts, artifactEvidence }) },
				authority,
				createUnavailable: unavailable,
			});
		await expect(
			execute(["./artifact.txt"], [{ path: "./artifact.txt", digest: "a".repeat(64), size: 1 }]),
		).resolves.toMatchObject({ results: [{ status: "failed" }] });
		await expect(
			execute(
				["artifact.txt", "artifact.txt"],
				[
					{ path: "artifact.txt", digest: "a".repeat(64), size: 1 },
					{ path: "artifact.txt", digest: "a".repeat(64), size: 1 },
				],
			),
		).resolves.toMatchObject({ results: [{ status: "failed" }] });
	});
});
