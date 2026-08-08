import { describe, expect, it } from "bun:test";
import { ThinkingLevel as AgentThinkingLevel } from "@gajae-code/agent-core";
import type { AssistantMessage } from "@gajae-code/ai";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import { createGjcLocalSolverSessionFactory, type LocalAgentSessionFactory } from "../../src/ctf/solver/gjc-session";
import type { LocalSolverSessionInput } from "../../src/ctf/solver/local-backend";
import { solverRouteFor } from "../../src/ctf/solver/router";
import type { CreateAgentSessionOptions } from "../../src/sdk/session";

function assistant(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "anthropic-messages",
		provider: "test",
		model: "test-model",
		stopReason: "stop",
		timestamp: Date.now(),
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
	};
}
function challElf(): Uint8Array {
	const bytes = new Uint8Array(64);
	const view = new DataView(bytes.buffer);
	bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
	view.setUint16(16, 3, true);
	view.setUint16(18, 62, true);
	view.setUint32(20, 1, true);
	view.setBigUint64(32, 0n, true);
	view.setUint16(52, 64, true);
	view.setUint16(54, 56, true);
	return bytes;
}

function input(
	challengeId = "lactf-2026-misc-endians",
	signal = new AbortController().signal,
): LocalSolverSessionInput {
	const route = solverRouteFor(challengeId);
	const toolProfile: readonly string[] = [];
	return {
		challengeId: route.challengeId,
		runId: "run-1",
		routeDigest: route.routeDigest,
		analyzerIds: route.analyzerIds,
		toolProfile,
		toolProfileDigest: canonicalDigest(toolProfile),
		adapterKind: route.adapterKind,
		modelPattern: route.modelPattern,
		thinkingLevel: route.thinkingLevel,
		attemptLimits: route.attemptLimits,
		visibleFiles: [{ path: "main.c", content: new TextEncoder().encode("int main(void) { return 0; }") }],
		runCapability: {
			writeScratch: async () => {},
			readScratch: async () => undefined,
			publish: async () => {},
		},
		network: "off",
		credentials: "none",
		allowedTools: toolProfile,
		signal,
	};
}

describe("GJC local solver AgentSession adapter", () => {
	it("passes exact reviewed model and thinking authority to a tool-free session", async () => {
		let options: CreateAgentSessionOptions | undefined;
		let observedCwd: string | undefined;
		let disposed = false;
		const createSession: LocalAgentSessionFactory = async value => {
			options = value;
			observedCwd = value.cwd;
			return {
				session: {
					abort: async () => {},
					dispose: async () => {
						disposed = true;
					},
					getLastAssistantMessage: () => assistant('{"candidate":"candidate-value","notes":"derived locally"}'),
					prompt: async () => {},
				},
			};
		};
		const lifecycle = createGjcLocalSolverSessionFactory({ createSession })({});
		const session = await lifecycle.session;
		const reviewed = input();
		await expect(session.solve(reviewed)).resolves.toEqual({
			candidate: "candidate-value",
			artifacts: [{ path: "analysis.txt", content: new TextEncoder().encode("derived locally") }],
		});
		expect(options?.toolNames).toEqual([]);
		expect(options?.customTools).toEqual([]);
		expect(options?.modelPattern).toBe(reviewed.modelPattern);
		expect(options?.thinkingLevel).toBe(
			reviewed.thinkingLevel === "high" ? AgentThinkingLevel.High : AgentThinkingLevel.Medium,
		);
		expect(options?.skills).toEqual([]);
		expect(options?.rules).toEqual([]);
		expect(options?.contextFiles).toEqual([]);
		expect(options?.disableExtensionDiscovery).toBe(true);
		// SDK maps strictToolIsolation to AgentSession file/background isolation.
		expect(options?.strictToolIsolation).toBe(true);
		expect(options?.workspaceTree?.rendered).toBe("");
		expect(options?.sessionManager?.getSessionFile()).toBeUndefined();
		expect(observedCwd).toMatch(/gjc-local-solver-/u);
		expect(observedCwd).not.toBe(process.cwd());
		expect(options?.workspaceTree?.rootPath).toBe(observedCwd);
		expect(options?.sessionManager?.getCwd()).toBe(observedCwd);
		expect(options?.enableLsp).toBe(false);
		expect(options?.settings?.get("goal.enabled")).toBe(false);
		expect(options?.settings?.get("tools.discoveryMode")).toBe("off");
		expect(disposed).toBe(true);
		await expect(lifecycle.quiesced).resolves.toBeUndefined();
	});

	it("refuses conflicting caller authority before session creation", async () => {
		let creations = 0;
		const lifecycle = createGjcLocalSolverSessionFactory({
			createSession: async () => {
				creations++;
				throw new Error("must not create");
			},
			modelPattern: "unreviewed-model",
		})({});
		const session = await lifecycle.session;
		await expect(session.solve(input())).rejects.toThrow("conflicts with the reviewed route");
		expect(creations).toBe(0);
	});

	it("exposes strict canonical base64 process capabilities without sharing binary buffers", async () => {
		let options: CreateAgentSessionOptions | undefined;
		const calls: string[] = [];
		const sent: Uint8Array[] = [];
		const received = Uint8Array.from([0, 255, 1, 2]);
		const visibleElf = challElf();
		const processInput = {
			...input("lactf-2026-pwn-tic-tac-no"),
			visibleFiles: [{ path: "chall", content: visibleElf }],
			evaluationAdapter: {
				adapterKind: "process-service" as const,
				process: {
					send: async (content: Uint8Array) => {
						sent.push(content);
					},
					receive: async () => {
						calls.push("receive");
						return received;
					},
					restart: async () => {
						calls.push("restart");
					},
				},
				close: async () => {
					calls.push("close");
				},
			},
		};
		const lifecycle = createGjcLocalSolverSessionFactory({
			createSession: async value => {
				options = value;
				return {
					session: {
						abort: async () => {},
						dispose: async () => {},
						getLastAssistantMessage: () => assistant('{"candidate":"candidate","notes":""}'),
						prompt: async () => {
							const tools = options?.customTools ?? [];
							const send = tools[0] as any;
							const receive = tools[1] as any;
							const restart = tools[2] as any;
							const inspect = tools[3] as any;
							await expect(send.execute("send", { contentBase64: "" })).resolves.toMatchObject({
								content: [{ text: "sent" }],
							});
							await expect(send.execute("send", { contentBase64: "AP8=" })).resolves.toMatchObject({
								content: [{ text: "sent" }],
							});
							const allBytes = Uint8Array.from({ length: 256 }, (_, index) => index);
							await send.execute("send", { contentBase64: Buffer.from(allBytes).toString("base64") });
							const boundary = new Uint8Array(64 * 1024);
							await send.execute("send", { contentBase64: Buffer.from(boundary).toString("base64") });
							await expect(
								send.execute("send", {
									contentBase64: Buffer.from(new Uint8Array(64 * 1024 + 1)).toString("base64"),
								}),
							).rejects.toThrow("byte bound");
							await expect(send.execute("send", { contentBase64: "AP8" })).rejects.toThrow(/canonical base64/);
							await expect(send.execute("send", { contentBase64: "AP8=\n" })).rejects.toThrow(
								/canonical base64/,
							);
							await expect(send.execute("send", { contentBase64: "AP_=" })).rejects.toThrow(/canonical base64/);
							await expect(send.execute("send", { content: "AP8=" })).rejects.toThrow();
							await expect(
								send.execute("send", { contentBase64: "A".repeat(4 * Math.ceil((64 * 1024) / 3) + 1) }),
							).rejects.toThrow(/base64 bound/);
							const firstReceive = await receive.execute("receive", {});
							expect(firstReceive.content[0]?.text).toBe("AP8BAg==");
							received[0] = 42;
							expect(firstReceive.content[0]?.text).toBe("AP8BAg==");
							const receiveBoundary = new Uint8Array(64 * 1024);
							processInput.evaluationAdapter.process.receive = async () => {
								calls.push("receive");
								return receiveBoundary;
							};
							const boundaryReceive = await receive.execute("receive", {});
							expect(boundaryReceive.content[0]?.text).toHaveLength(4 * Math.ceil((64 * 1024) / 3));
							receiveBoundary[0] = 42;
							expect(boundaryReceive.content[0]?.text).not.toContain("Kg");
							await expect(receive.execute("receive", { unexpected: true })).rejects.toThrow();
							processInput.evaluationAdapter.process.receive = async () => {
								calls.push("receive");
								return new Uint8Array(64 * 1024 + 1);
							};
							await expect(receive.execute("receive", {})).rejects.toThrow("byte bound");
							await restart.execute("restart", {});
							visibleElf.fill(0);
							const inspection = await inspect.execute("inspect", {});
							expect(JSON.parse(inspection.content[0]?.text ?? "")).toMatchObject({
								class: "ELF64",
								machine: "x86-64",
								mitigations: { pie: "unknown" },
							});
							await expect(inspect.execute("inspect", { extra: true })).rejects.toThrow();
						},
					},
				};
			},
		})({});
		const session = await lifecycle.session;
		await expect(session.solve(processInput)).resolves.toEqual({ candidate: "candidate", artifacts: [] });
		expect(options?.toolNames).toEqual([]);
		expect(options?.customTools?.map(tool => tool.name)).toEqual([
			"ctf_process_send_base64",
			"ctf_process_receive_base64",
			"ctf_process_restart",
			"ctf_elf_inspect",
		]);
		expect(sent.map(content => [...content])).toEqual([
			[],
			[0, 255],
			[...Uint8Array.from({ length: 256 }, (_, index) => index)],
			Array(64 * 1024).fill(0),
		]);
		expect(sent[1]).not.toBe(sent[2]);
		expect(calls).toEqual(["receive", "receive", "receive", "restart"]);
	});

	it("fails closed for missing process adapters and leaves adapter cleanup to the backend", async () => {
		let creations = 0;
		const missing = createGjcLocalSolverSessionFactory({
			createSession: async () => {
				creations++;
				throw new Error("must not create");
			},
		})({});
		await expect((await missing.session).solve(input("lactf-2026-pwn-tic-tac-no"))).rejects.toThrow(
			"requires its matching evaluation adapter",
		);
		expect(creations).toBe(0);

		let closes = 0;
		const cleanup = createGjcLocalSolverSessionFactory({
			createSession: async () => ({
				session: {
					abort: async () => {},
					dispose: async () => {},
					getLastAssistantMessage: () => assistant('{"candidate":"late","notes":""}'),
					prompt: async () => {},
				},
			}),
		})({});
		const cleanupInput = {
			...input("lactf-2026-pwn-tic-tac-no"),
			visibleFiles: [{ path: "chall", content: challElf() }],
			evaluationAdapter: {
				adapterKind: "process-service" as const,
				process: { send: async () => {}, receive: async () => new Uint8Array(), restart: async () => {} },
				close: async () => {
					closes++;
				},
			},
		};
		await expect((await cleanup.session).solve(cleanupInput)).resolves.toEqual({ candidate: "late", artifacts: [] });
		expect(closes).toBe(0);
	});
	it("disposes an acquired session without prompting when cancellation races acquisition", async () => {
		const controller = new AbortController();
		let prompted = false;
		let disposed = false;
		const lifecycle = createGjcLocalSolverSessionFactory({
			createSession: async () => {
				controller.abort(new Error("cancelled during acquisition"));
				return {
					session: {
						abort: async () => {},
						dispose: async () => {
							disposed = true;
						},
						getLastAssistantMessage: () => assistant('{"candidate":"late","notes":""}'),
						prompt: async () => {
							prompted = true;
						},
					},
				};
			},
		})({});
		await expect(
			(await lifecycle.session).solve(input("lactf-2026-misc-endians", controller.signal)),
		).rejects.toThrow("cancelled");
		expect(prompted).toBe(false);
		expect(disposed).toBe(true);
	});

	it("termination aborts active work and quiesces the lifecycle", async () => {
		const release = Promise.withResolvers<void>();
		const started = Promise.withResolvers<void>();
		let aborts = 0;
		let disposed = false;
		const lifecycle = createGjcLocalSolverSessionFactory({
			createSession: async () => ({
				session: {
					abort: async () => {
						aborts++;
						release.resolve();
					},
					dispose: async () => {
						disposed = true;
					},
					getLastAssistantMessage: () => assistant('{"candidate":"late","notes":""}'),
					prompt: async () => {
						started.resolve();
						await release.promise;
					},
				},
			}),
		})({});
		const solving = (await lifecycle.session).solve(input());
		await started.promise;
		await lifecycle.terminate({} as never);
		await expect(solving).rejects.toThrow("cancelled");
		await expect(lifecycle.quiesced).resolves.toBeUndefined();
		expect(aborts).toBe(1);
		expect(disposed).toBe(true);
	});
});
