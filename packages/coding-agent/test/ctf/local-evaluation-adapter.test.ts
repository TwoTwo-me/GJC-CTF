import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { sha256Hex } from "../../src/ctf/contracts/digest";
import { createLocalCtfSolverBackend } from "../../src/ctf/solver/local-backend";
import {
	type LocalEvaluationAdapterProvider,
	matchingLocalEvaluationProviders,
	openLocalEvaluationAdapter,
} from "../../src/ctf/solver/local-evaluation-adapter";
import { solverRouteFor } from "../../src/ctf/solver/router";
import { makeDescriptor } from "./fixtures";

const processRoute = solverRouteFor("lactf-2026-pwn-tic-tac-no");
const browserRoute = solverRouteFor("lactf-2026-web-single-trust");

function processProvider(overrides: Partial<LocalEvaluationAdapterProvider> = {}): LocalEvaluationAdapterProvider {
	return {
		challengeId: processRoute.challengeId,
		routeDigest: processRoute.routeDigest,
		adapterKind: "process-service",
		open: async () => ({
			send: async () => undefined,
			receive: async () => new Uint8Array([1]),
			restart: async () => undefined,
			close: async () => undefined,
			observation: { status: "exited", exitCode: 0 },
		}),
		...overrides,
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

	it("bounds acquisition and closes a service that resolves after cancellation", async () => {
		const timeoutRoute = {
			...processRoute,
			attemptLimits: { ...processRoute.attemptLimits, wallClockMs: 1 },
		};
		const never = Promise.withResolvers<never>();
		await expect(
			openLocalEvaluationAdapter(
				processProvider({ open: async () => never.promise }),
				timeoutRoute,
				new AbortController().signal,
			),
		).rejects.toThrow(/time limit/);

		const deferred = Promise.withResolvers<Awaited<ReturnType<LocalEvaluationAdapterProvider["open"]>>>();
		let closed = 0;
		const controller = new AbortController();
		const pending = openLocalEvaluationAdapter(
			processProvider({ open: async () => deferred.promise }),
			processRoute,
			controller.signal,
		);
		controller.abort();
		await expect(pending).rejects.toThrow(/cancelled/);
		deferred.resolve({
			send: async () => undefined,
			receive: async () => new Uint8Array(),
			restart: async () => undefined,
			close: async () => {
				closed++;
			},
		});
		await deferred.promise;
		await Bun.sleep(0);
		expect(closed).toBe(1);
	});
	it("permits only bounded local browser actions and rejects external navigation", async () => {
		const actions: unknown[] = [];
		const provider: LocalEvaluationAdapterProvider = {
			challengeId: browserRoute.challengeId,
			routeDigest: browserRoute.routeDigest,
			adapterKind: "browser-session",
			open: async () => ({
				action: async action => {
					actions.push(action);
				},
				close: async () => undefined,
			}),
		};
		expect(matchingLocalEvaluationProviders([provider], browserRoute)).toEqual([provider]);
		const adapter = await openLocalEvaluationAdapter(provider, browserRoute, new AbortController().signal);
		if (adapter.adapterKind !== "browser-session") throw new Error("expected browser adapter");
		await adapter.browser.action({ type: "navigate", path: "challenge?step=1" });
		await expect(adapter.browser.action({ type: "navigate", path: "https://example.invalid/" })).rejects.toThrow(
			/not local/,
		);
		await expect(adapter.browser.action({ type: "navigate", path: "../secret" })).rejects.toThrow(/not local/);
		expect(actions).toEqual([{ type: "navigate", path: "challenge?step=1" }]);
		await adapter.close();
	});
});
