import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { sha256Hex } from "../../src/ctf/contracts/digest";
import { createLocalCtfSolverBackend } from "../../src/ctf/solver/local-backend";
import {
	type LocalEvaluationAcquisition,
	type LocalEvaluationAdapterProvider,
	openLocalEvaluationAdapter,
} from "../../src/ctf/solver/local-evaluation-adapter";
import { solverRouteFor } from "../../src/ctf/solver/router";
import { makeDescriptor } from "./fixtures";

const processRoute = solverRouteFor("lactf-2026-pwn-tic-tac-no");
const browserRoute = solverRouteFor("lactf-2026-web-single-trust");
const binding = Object.freeze({
	competitionId: "competition-1",
	runId: "run-1",
	challengeId: processRoute.challengeId,
	fencingToken: 1,
});
function isAcquisition(value: unknown): value is LocalEvaluationAcquisition {
	return (
		value !== null &&
		typeof value === "object" &&
		"service" in value &&
		value.service instanceof Promise &&
		"terminate" in value &&
		typeof value.terminate === "function"
	);
}

function processProvider(
	overrides: Partial<Omit<LocalEvaluationAdapterProvider, "open">> & {
		open?: (
			input: Parameters<LocalEvaluationAdapterProvider["open"]>[0],
		) => LocalEvaluationAcquisition | Promise<Awaited<LocalEvaluationAcquisition["service"]>>;
	} = {},
): LocalEvaluationAdapterProvider {
	const { open, ...identity } = overrides;
	return {
		challengeId: processRoute.challengeId,
		routeDigest: processRoute.routeDigest,
		adapterKind: "process-service",
		open: input => {
			const acquired =
				open?.(input) ??
				Promise.resolve({
					send: async () => undefined,
					receive: async () => new Uint8Array([1]),
					restart: async () => undefined,
					close: async () => undefined,
					observation: { status: "exited", exitCode: 0 },
				});
			if (isAcquisition(acquired)) return acquired;
			return { service: Promise.resolve(acquired), terminate: async () => undefined };
		},
		...identity,
	};
}

function request(challengeId: string, root: string, signal = new AbortController().signal) {
	return {
		runId: "run-1",
		challengeId,
		mode: "benchmark" as const,
		backendId: "local-gjc-agent",
		signal,
		materialized: {
			root,
			provenanceDigest: sha256Hex("materialized"),
			visibleFileDigests: { "answer.txt": sha256Hex("visible") },
		},
		authority: {
			competitionId: "competition-1",
			fencingToken: 1,
			intentId: "intent-1",
			skillDigest: sha256Hex("skill"),
			sandboxPolicyDigest: sha256Hex("policy"),
		},
	};
}

describe("local evaluation adapters", () => {
	it("requires one exact provider and keeps provider observations out of candidate evidence", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-local-adapter-"));
		const artifacts = path.join(root, "artifacts");
		await fs.mkdir(artifacts);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const base = {
			root,
			artifactRoot: artifacts,
			challenges: new Map([
				[
					processRoute.challengeId,
					makeDescriptor({ id: processRoute.challengeId, visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			createSession: async () => ({ solve: async () => ({}) }),
		};
		for (const providers of [
			[],
			[processProvider({ routeDigest: sha256Hex("wrong") })],
			[processProvider(), processProvider()],
		]) {
			const backend = createLocalCtfSolverBackend({ ...base, adapterProviders: providers });
			await expect(backend.solve(request(processRoute.challengeId, root))).resolves.toMatchObject({
				status: "blocked",
			});
		}
		let sessionInput: unknown;
		const backend = createLocalCtfSolverBackend({
			...base,
			adapterProviders: [processProvider()],
			createSession: async () => ({
				solve: async input => {
					sessionInput = input.evaluationAdapter;
					return {};
				},
			}),
		});
		await expect(backend.solve(request(processRoute.challengeId, root))).resolves.toMatchObject({
			status: "failed",
			reason: "agent produced no candidate",
		});
		expect(sessionInput).toMatchObject({ observation: { status: "exited", exitCode: 0 } });
	});
	it("closes provider ownership before rejecting a hung session acquisition", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-local-adapter-"));
		const artifacts = path.join(root, "artifacts");
		await fs.mkdir(artifacts);
		await fs.writeFile(path.join(root, "answer.txt"), "visible");
		const opened = Promise.withResolvers<void>();
		const sessionStarted = Promise.withResolvers<void>();
		const never = new Promise<never>(() => undefined);
		let serviceCloses = 0;
		let acquisitionTerminations = 0;
		const backend = createLocalCtfSolverBackend({
			root,
			artifactRoot: artifacts,
			challenges: new Map([
				[
					processRoute.challengeId,
					makeDescriptor({ id: processRoute.challengeId, visibleArtifactAllowlist: ["answer.txt"] }),
				],
			]),
			adapterProviders: [
				processProvider({
					open: () => {
						opened.resolve();
						return {
							service: Promise.resolve({
								send: async () => undefined,
								receive: async () => new Uint8Array(),
								restart: async () => undefined,
								close: async () => {
									serviceCloses++;
								},
							}),
							terminate: async () => {
								acquisitionTerminations++;
							},
						};
					},
				}),
			],
			createSession: async () => {
				sessionStarted.resolve();
				return await never;
			},
		});
		void backend.solve(request(processRoute.challengeId, root));
		await opened.promise;
		await sessionStarted.promise;
		await expect(
			backend.terminate?.({
				competitionId: "competition-1",
				runId: "run-1",
				challengeId: processRoute.challengeId,
				ownerId: "run-1",
				fencingToken: 1,
				reason: "cancelled",
			}),
		).rejects.toThrow(/session readiness/);
		expect(serviceCloses).toBe(1);
		expect(acquisitionTerminations).toBe(1);
	});

	it("bounds process actions and closes a provider exactly once after cancellation", async () => {
		let sent = 0;
		let closed = 0;
		const controller = new AbortController();
		const adapter = await openLocalEvaluationAdapter(
			processProvider({
				open: async () => ({
					send: async content => {
						sent += content.byteLength;
					},
					receive: async () => new Uint8Array(64 * 1024 + 1),
					restart: async () => undefined,
					close: async () => {
						closed++;
					},
				}),
			}),
			processRoute,
			controller.signal,
			binding,
		);
		if (adapter.adapterKind !== "process-service") throw new Error("expected process adapter");
		await adapter.process.send(new Uint8Array(8));
		expect(sent).toBe(8);
		await expect(adapter.process.send(new Uint8Array(64 * 1024 + 1))).rejects.toThrow(/byte bound/);
		await expect(adapter.process.receive()).rejects.toThrow(/byte bound/);
		controller.abort();
		await expect(adapter.process.restart()).rejects.toThrow(/cancelled/);
		await Promise.all([adapter.close(), adapter.close()]);
		expect(closed).toBe(1);
	});

	it("bounds acquisition and requires authoritative cancellation acknowledgement", async () => {
		const timeoutRoute = {
			...processRoute,
			attemptLimits: { ...processRoute.attemptLimits, wallClockMs: 1 },
		};
		const never = Promise.withResolvers<never>();
		let timedOutTerminations = 0;
		await expect(
			openLocalEvaluationAdapter(
				processProvider({
					open: () => ({
						service: never.promise,
						terminate: async () => {
							timedOutTerminations++;
						},
					}),
				}),
				timeoutRoute,
				new AbortController().signal,
				binding,
			),
		).rejects.toThrow(/time limit/);
		expect(timedOutTerminations).toBe(1);

		let cancelledTerminations = 0;
		const controller = new AbortController();
		const pending = openLocalEvaluationAdapter(
			processProvider({
				open: () => ({
					service: never.promise,
					terminate: async () => {
						cancelledTerminations++;
					},
				}),
			}),
			processRoute,
			controller.signal,
			binding,
		);
		controller.abort();
		await expect(pending).rejects.toThrow(/cancelled/);
		expect(cancelledTerminations).toBe(1);
	});
	it("cancels never-settling process operations and closes each service once", async () => {
		for (const method of ["send", "receive", "restart"] as const) {
			let closed = 0;
			const controller = new AbortController();
			const never = new Promise<never>(() => undefined);
			const adapter = await openLocalEvaluationAdapter(
				processProvider({
					open: async () => ({
						send: async () => never,
						receive: async () => never,
						restart: async () => never,
						close: async () => {
							closed++;
						},
					}),
				}),
				processRoute,
				controller.signal,
				{ ...binding, runId: `run-${method}` },
			);
			if (adapter.adapterKind !== "process-service") throw new Error("expected process adapter");
			const pending =
				method === "send"
					? adapter.process.send(new Uint8Array())
					: method === "receive"
						? adapter.process.receive()
						: adapter.process.restart();
			controller.abort();
			await expect(pending).rejects.toThrow(/cancelled/);
			expect(closed).toBe(1);
			await adapter.close();
			expect(closed).toBe(1);
		}
	});

	it("does not execute browser actions from a structural provider", async () => {
		let executed = false;
		let closed = 0;
		let terminated = 0;
		const provider: LocalEvaluationAdapterProvider = {
			challengeId: browserRoute.challengeId,
			routeDigest: browserRoute.routeDigest,
			adapterKind: "browser-session",
			open: () => ({
				service: Promise.resolve({
					action: async () => {
						executed = true;
					},
					close: async () => {
						closed++;
					},
					networkAuthority: {
						origin: "http://localhost:8080",
						intercepts: {
							navigation: true,
							redirect: true,
							popup: true,
							websocket: true,
							subresource: true,
						},
					},
				}),
				terminate: async () => {
					terminated++;
				},
			}),
		};
		await expect(
			openLocalEvaluationAdapter(provider, browserRoute, new AbortController().signal, {
				...binding,
				runId: "browser-disabled",
				challengeId: browserRoute.challengeId,
			}),
		).rejects.toThrow(/browser sessions are disabled/);
		expect(executed).toBe(false);
		expect(closed).toBe(1);
		expect(terminated).toBe(1);
	});

	it("fails terminal cleanup when close rejects or does not settle", async () => {
		for (const [index, close] of [
			async () => {
				throw new Error("close rejected");
			},
			async () => new Promise<never>(() => undefined),
		].entries()) {
			const adapter = await openLocalEvaluationAdapter(
				processProvider({
					open: async () => ({
						send: async () => undefined,
						receive: async () => new Uint8Array(),
						restart: async () => undefined,
						close,
					}),
				}),
				processRoute,
				new AbortController().signal,
				{ ...binding, runId: `close-${index}` },
			);
			await expect(adapter.close()).rejects.toThrow(/close|time limit/);
		}
	});

	it("requires acquisition termination rather than late-service cleanup", async () => {
		let terminated = 0;
		const provider = processProvider({
			open: () => ({
				service: new Promise<never>(() => undefined),
				terminate: async () => {
					terminated++;
				},
			}),
		});
		const controller = new AbortController();
		const pending = openLocalEvaluationAdapter(provider, processRoute, controller.signal, {
			...binding,
			runId: "late-failure",
		});
		controller.abort();
		await expect(pending).rejects.toThrow(/cancelled/);
		expect(terminated).toBe(1);
	});
	it("fails closed for structural browser providers", async () => {
		const provider: LocalEvaluationAdapterProvider = {
			challengeId: browserRoute.challengeId,
			routeDigest: browserRoute.routeDigest,
			adapterKind: "browser-session",
			open: () => ({
				service: Promise.resolve({
					action: async () => undefined,
					close: async () => undefined,
					networkAuthority: {
						origin: "http://127.0.0.1:3000",
						intercepts: {
							navigation: true,
							redirect: true,
							popup: true,
							websocket: true,
							subresource: true,
						},
					},
				}),
				terminate: async () => undefined,
			}),
		};
		await expect(
			openLocalEvaluationAdapter(provider, browserRoute, new AbortController().signal, {
				...binding,
				challengeId: browserRoute.challengeId,
			}),
		).rejects.toThrow(/browser sessions are disabled/);
	});

	it("rejects concurrent reuse and binds provider acquisition to the run", async () => {
		const service = {
			send: async () => undefined,
			receive: async () => new Uint8Array(),
			restart: async () => undefined,
			close: async () => undefined,
		};
		const bindings: unknown[] = [];
		const provider = processProvider({
			open: async input => {
				bindings.push(input.binding);
				return service;
			},
		});
		const first = await openLocalEvaluationAdapter(provider, processRoute, new AbortController().signal, binding);
		await expect(
			openLocalEvaluationAdapter(provider, processRoute, new AbortController().signal, {
				...binding,
				runId: "run-2",
			}),
		).rejects.toThrow(/quarantined service/);
		expect(bindings).toEqual([binding, { ...binding, runId: "run-2" }]);
		await first.close();
		await expect(
			openLocalEvaluationAdapter(provider, processRoute, new AbortController().signal, {
				...binding,
				runId: "run-3",
			}),
		).rejects.toThrow(/quarantined service/);
	});
	it("uses a cleanup deadline independent from the expired attempt deadline", async () => {
		let closed = 0;
		const timeoutRoute = {
			...processRoute,
			attemptLimits: { ...processRoute.attemptLimits, wallClockMs: 25 },
		};
		const adapter = await openLocalEvaluationAdapter(
			processProvider({
				open: async () => ({
					send: async () => new Promise<never>(() => undefined),
					receive: async () => new Uint8Array(),
					restart: async () => undefined,
					close: async () => {
						closed++;
					},
				}),
			}),
			timeoutRoute,
			new AbortController().signal,
			{ ...binding, runId: "cleanup-after-timeout" },
		);
		if (adapter.adapterKind !== "process-service") throw new Error("expected process adapter");
		await expect(adapter.process.send(new Uint8Array())).rejects.toThrow(/time limit/);
		expect(closed).toBe(1);
	});
	it("uses acquisition termination as the authoritative cleanup for an unresolving service", async () => {
		let terminated = 0;
		const controller = new AbortController();
		const adapter = openLocalEvaluationAdapter(
			processProvider({
				open: () => ({
					service: new Promise<never>(() => undefined),
					terminate: async () => {
						terminated++;
					},
				}),
			}),
			processRoute,
			controller.signal,
			{ ...binding, runId: "owned-acquisition" },
		);
		controller.abort();
		await expect(adapter).rejects.toThrow(/cancelled/);
		expect(terminated).toBe(1);
	});
});
