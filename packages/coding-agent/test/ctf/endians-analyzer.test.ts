import { describe, expect, test } from "bun:test";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import { analyzeEndiansSource, createEndiansAnalyzer } from "../../src/ctf/solver/analyzers/endians";
import { solverRouteFor } from "../../src/ctf/solver/router";

const fixtureCandidate = "lactf{synthetic-endians-fixture}";
const source = new TextEncoder().encode(
	Array.from(fixtureCandidate, character => {
		const unit = character.charCodeAt(0);
		return String.fromCharCode(((unit & 0xff) << 8) | (unit >>> 8));
	}).join(""),
);

describe("Endians analyzer", () => {
	test("decodes the reviewed visible challenge without exposing it in evidence", () => {
		const analysis = analyzeEndiansSource(source);
		expect(analysis.ok).toBe(true);
		if (!analysis.ok) return;
		expect(analysis.candidate.startsWith("lactf{")).toBe(true);
		expect(analysis.candidate.endsWith("}")).toBe(true);
	});

	test("fails closed for malformed input", () => {
		expect(analyzeEndiansSource(new Uint8Array())).toMatchObject({ ok: false, reason: "source-too-large" });
		expect(analyzeEndiansSource(new Uint8Array([0xff]))).toMatchObject({ ok: false, reason: "invalid-encoding" });
	});

	test("runs through the local analyzer interface", async () => {
		const analyzer = createEndiansAnalyzer({ visiblePath: "chall.txt" });
		const route = solverRouteFor("lactf-2026-misc-endians");
		const toolProfile: readonly string[] = [];
		const lifecycle = analyzer.analyze({
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
			visibleFiles: [{ path: "chall.txt", content: source }],
			runCapability: {
				writeScratch: async () => {},
				readScratch: async () => undefined,
				publish: async () => {},
			},
			network: "off",
			credentials: "none",
			allowedTools: toolProfile,
			signal: new AbortController().signal,
		});
		const result = await lifecycle.result;
		await lifecycle.quiesced;
		expect(result.status).toBe("candidate");
	});
});
