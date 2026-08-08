import { describe, expect, test } from "bun:test";
import { analyzeOooRecurrenceSource, createOooRecurrenceAnalyzer } from "../../src/ctf/solver/analyzers/ooo-recurrence";
import { canonicalDigest } from "../../src/ctf/contracts/digest";
import type { LocalSolverSessionInput } from "../../src/ctf/solver/local-backend";
import { solverRouteFor } from "../../src/ctf/solver/router";

const OPERATIONS = [
	"def о(a, b):\n    return a+b",
	"def ο(a, b):\n    return a-b",
	"def օ(a, b):\n    return a*b",
	"def ỏ(a, b):\n    return a//b",
	"def ơ(a, b):\n    return a^b",
	"def ó(a, b):\n    return a|b",
	"def ὀ(a, b):\n    return a&b",
	"def ὸ(a, b):\n    return b-a",
	"def ὄ(a, b):\n    return a",
	"def ὂ(a, b):\n    return b",
	"def ȯ(a, b):\n    return a % b",
].join("\n");
const CHECKER_SUFFIX = [
	"",
	"",
	`guess = input("What's the flag? ") # remember, flags start with lactf{`,
	"",
	"if (len(guess) < len(ὁ)):",
	'    print("That\'s too short :(")',
	"    exit()",
	"    ",
	"for ö in range(len(ὁ)-1):",
	"    ό = ord(guess[ö])",
	"    ὃ = ord(guess[ö+1])",
	"    if (о(ὄ(ό,ὃ),ὂ(ό,ὃ)) != ὁ[ơ(ö,ȯ(օ(ό,ὃ),ό))]):",
	'        print("That\'s not the flag :(")',
	"        exit()",
	"    ",
	'print("That\'s the flag! :)")',
	"",
].join("\n");
const fixtureCandidate = "lactf{synthetic-ooo-fixture}";
const fixtureCodePoints = Array.from(fixtureCandidate, character => character.codePointAt(0) as number);
const fixtureConstants = [
	...fixtureCodePoints.slice(0, -1).map((value, index) => value + (fixtureCodePoints[index + 1] as number)),
	0,
];
const source = `${OPERATIONS}\n    \n\nὁ = [${fixtureConstants.join(", ")}]${CHECKER_SUFFIX}`;

describe("OOO recurrence analyzer", () => {
	test("derives a candidate from the exact reviewed visible checker", () => {
		const analysis = analyzeOooRecurrenceSource(source);
		expect(analysis.ok).toBe(true);
		if (!analysis.ok) return;
		expect(analysis.candidate.startsWith("lactf{")).toBe(true);
		expect(analysis.candidate).toBe(fixtureCandidate);
	});

	test("fails closed when checker semantics drift", () => {
		const analysis = analyzeOooRecurrenceSource(source.replace("return a+b", "return a-b"));
		expect(analysis).toMatchObject({ ok: false, reason: "unsupported-source" });
	});

	test("runs through the local analyzer interface and honors cancellation", async () => {
		const analyzer = createOooRecurrenceAnalyzer({ visiblePath: "ooo.py" });
		const controller = new AbortController();
		const route = solverRouteFor("lactf-2026-rev-ooo");
		const toolProfile: readonly string[] = [];
		const input: LocalSolverSessionInput = {
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
			visibleFiles: [{ path: "ooo.py", content: new TextEncoder().encode(source) }],
			runCapability: {
				writeScratch: async () => {},
				readScratch: async () => undefined,
				publish: async () => {},
			},
			network: "off",
			credentials: "none",
			allowedTools: toolProfile,
			signal: controller.signal,
		};
		const result = await analyzer.analyze(input);
		expect(result.status).toBe("candidate");
		controller.abort();
		expect(await analyzer.analyze(input)).toEqual({ status: "cancelled", reason: "run cancelled" });
	});
});
