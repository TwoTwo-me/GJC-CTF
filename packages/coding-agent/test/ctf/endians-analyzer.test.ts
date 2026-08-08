import { describe, expect, test } from "bun:test";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import { analyzeEndiansSource, createEndiansAnalyzer } from "../../src/ctf/solver/analyzers/endians";
import { solverRouteFor } from "../../src/ctf/solver/router";

const fixtureCandidate = "lactf{synthetic-endians-fixture}";

function encodeCandidate(candidate: string): Uint8Array {
	return new TextEncoder().encode(
		Array.from(candidate, character => {
			const unit = character.charCodeAt(0);
			return String.fromCharCode(((unit & 0xff) << 8) | (unit >>> 8));
		}).join(""),
	);
}

const source = encodeCandidate(fixtureCandidate);

describe("Endians analyzer", () => {
	test("decodes the reviewed visible challenge without exposing it in evidence", () => {
		const analysis = analyzeEndiansSource(source);
		expect(analysis.ok).toBe(true);
		if (!analysis.ok) return;
		expect(analysis.candidate.startsWith("lactf{")).toBe(true);
		expect(analysis.candidate.endsWith("}")).toBe(true);
	});

	test("accepts the maximum fresh-fixture ASCII payload", () => {
		const candidate = `lactf{${"a".repeat(4096 - "lactf{}".length)}}`;
		const encoded = encodeCandidate(candidate);

		expect(encoded.byteLength).toBe(4096 * 3);
		const analysis = analyzeEndiansSource(encoded);
		expect(analysis.ok).toBe(true);
		if (analysis.ok) expect(analysis.candidate).toBe(candidate);
	});

	test("refuses decoded candidates beyond the fresh-fixture secret budget", () => {
		const candidate = `lactf{${"é".repeat(2045)}}`;
		expect(new TextEncoder().encode(candidate).byteLength).toBeGreaterThan(4096);
		expect(analyzeEndiansSource(encodeCandidate(candidate))).toMatchObject({
			ok: false,
			reason: "invalid-candidate",
		});
	});

	test("refuses encoded input beyond the fresh-fixture bound", () => {
		expect(analyzeEndiansSource(new Uint8Array(4096 * 3 + 1))).toMatchObject({
			ok: false,
			reason: "source-too-large",
		});
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
			attempt: 1,
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
