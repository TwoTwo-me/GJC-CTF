import { describe, expect, it } from "bun:test";
import { ThinkingLevel } from "@gajae-code/agent-core";
import type { AssistantMessage } from "@gajae-code/ai";
import { createGjcLocalSolverSessionFactory, type LocalAgentSessionFactory } from "../../src/ctf/solver/gjc-session";
import type { LocalSolverSessionInput } from "../../src/ctf/solver/local-backend";
import type { CreateAgentSessionOptions } from "../../src/sdk/session";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import { solverRouteFor } from "../../src/ctf/solver/router";

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

function input(signal = new AbortController().signal): LocalSolverSessionInput {
	const route = solverRouteFor("lactf-2026-misc-endians");
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
	it("creates a tool-free isolated session and parses a candidate", async () => {
		let options: CreateAgentSessionOptions | undefined;
		let prompt = "";
		let disposed = false;
		const createSession: LocalAgentSessionFactory = async value => {
			options = value;
			return {
				session: {
					abort: async () => {},
					dispose: async () => {
						disposed = true;
					},
					getLastAssistantMessage: () => assistant('{"candidate":"candidate-value","notes":"derived locally"}'),
					prompt: async text => {
						prompt = text;
					},
				},
			};
		};
		const factory = createGjcLocalSolverSessionFactory({
			createSession,
			modelPattern: "fallback-model",
			modelPatternFor: value => (value.challengeId.endsWith("endians") ? "endians-model" : undefined),
			thinkingLevel: ThinkingLevel.Medium,
			thinkingLevelFor: value => (value.challengeId.endsWith("endians") ? ThinkingLevel.Low : undefined),
		});
		const session = await factory({});
		await expect(session.solve(input())).resolves.toEqual({
			candidate: "candidate-value",
			artifacts: [{ path: "analysis.txt", content: new TextEncoder().encode("derived locally") }],
		});
		expect(options?.toolNames).toEqual([]);
		expect(options?.modelPattern).toBe("endians-model");
		expect(options?.thinkingLevel).toBe(ThinkingLevel.Low);
		expect(options?.skills).toEqual([]);
		expect(options?.rules).toEqual([]);
		expect(options?.contextFiles).toEqual([]);
		expect(options?.disableExtensionDiscovery).toBe(true);
		expect(options?.enableLsp).toBe(false);
		expect(options?.settings?.get("goal.enabled")).toBe(false);
		expect(options?.settings?.get("tools.discoveryMode")).toBe("off");
		expect(prompt).toContain('challengeId: "lactf-2026-misc-endians"');
		expect(prompt).toContain("int main(void)");
		expect(prompt).not.toContain("challenge.yaml");
		expect(disposed).toBe(true);
	});

	it("rejects malformed output and always disposes the session", async () => {
		let disposed = false;
		const factory = createGjcLocalSolverSessionFactory({
			createSession: async () => ({
				session: {
					abort: async () => {},
					dispose: async () => {
						disposed = true;
					},
					getLastAssistantMessage: () => assistant("candidate-value"),
					prompt: async () => {},
				},
			}),
		});
		const session = await factory({});
		await expect(session.solve(input())).rejects.toThrow("not valid JSON");
		expect(disposed).toBe(true);
	});

	it("aborts an active AgentSession and disposes it", async () => {
		const controller = new AbortController();
		const release = Promise.withResolvers<void>();
		let aborts = 0;
		let disposed = false;
		const factory = createGjcLocalSolverSessionFactory({
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
					prompt: async () => await release.promise,
				},
			}),
		});
		const session = await factory({});
		const solving = session.solve(input(controller.signal));
		controller.abort(new Error("budget exhausted"));
		await expect(solving).rejects.toThrow("cancelled");
		expect(aborts).toBe(1);
		expect(disposed).toBe(true);
	});
});
