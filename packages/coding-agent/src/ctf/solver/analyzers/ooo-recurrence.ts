import type { LocalSolverAnalyzer } from "../local-backend";

const MAX_SOURCE_BYTES = 256 * 1024;
const FLAG_PREFIX = "lactf{";

const OPERATION_LINES = [
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

const CONSTANT_PREFIX = `${OPERATION_LINES}\n    \n\nὁ = [`;
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

export type OooRecurrenceAnalysis =
	| Readonly<{ ok: true; candidate: string; diagnostics: readonly string[] }>
	| Readonly<{
			ok: false;
			reason: "source-too-large" | "unsupported-source" | "unsatisfied-prefix" | "invalid-codepoint";
			diagnostics: readonly string[];
	  }>;

function failure(
	reason: Extract<OooRecurrenceAnalysis, { ok: false }>["reason"],
	detail: string,
): OooRecurrenceAnalysis {
	return { ok: false, reason, diagnostics: [detail] };
}

function parseConstants(source: string): readonly number[] | undefined {
	const marker = "ὁ = [";
	const start = source.indexOf(marker);
	if (start === -1) return undefined;
	const end = source.indexOf("]", start + marker.length);
	if (end === -1) return undefined;
	const constantsText = source.slice(start + marker.length, end);
	if (source !== `${CONSTANT_PREFIX}${constantsText}]${CHECKER_SUFFIX}`) return undefined;
	if (!/^(?:0|[1-9]\d*)(?:, (?:0|[1-9]\d*))*$/u.test(constantsText)) return undefined;
	const constants = constantsText.split(", ").map(Number);
	if (constants.length < FLAG_PREFIX.length + 1) return undefined;
	return constants.every(value => Number.isSafeInteger(value) && value >= 0) ? constants : undefined;
}

function validCodePoint(value: number): boolean {
	return Number.isSafeInteger(value) && value > 0 && value <= 0x10ffff && (value < 0xd800 || value > 0xdfff);
}

/** Solves only the reviewed adjacent-codepoint recurrence embedded in the pinned OOO checker. */
export function analyzeOooRecurrenceSource(source: string): OooRecurrenceAnalysis {
	if (new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES) {
		return failure("source-too-large", "checker source exceeds the reviewed byte limit");
	}
	const constants = parseConstants(source);
	if (constants === undefined)
		return failure("unsupported-source", "checker source is outside the reviewed OOO grammar");

	const codePoints = [FLAG_PREFIX.codePointAt(0) as number];
	for (let index = 0; index < constants.length - 1; index += 1) {
		const next = constants[index] - codePoints[index];
		if (!validCodePoint(next)) return failure("invalid-codepoint", `derived code point ${index + 1} is invalid`);
		codePoints.push(next);
	}
	const candidate = String.fromCodePoint(...codePoints);
	if (!candidate.startsWith(FLAG_PREFIX))
		return failure("unsatisfied-prefix", "derived recurrence contradicts the visible flag prefix");
	return { ok: true, candidate, diagnostics: ["solved reviewed adjacent-codepoint recurrence"] };
}

export function createOooRecurrenceAnalyzer(options: Readonly<{ visiblePath: string }>): LocalSolverAnalyzer {
	return {
		id: "ooo-recurrence",
		async analyze(input) {
			if (input.signal.aborted) return { status: "cancelled", reason: "run cancelled" };
			const visible = input.visibleFiles.find(file => file.path === options.visiblePath);
			if (visible === undefined) return { status: "not-applicable" };
			let source: string;
			try {
				source = new TextDecoder("utf-8", { fatal: true }).decode(visible.content);
			} catch {
				return { status: "refused", reason: "checker source is not valid UTF-8" };
			}
			const analysis = analyzeOooRecurrenceSource(source);
			if (!analysis.ok) return { status: "refused", reason: analysis.reason };
			return { status: "candidate", result: { candidate: analysis.candidate } };
		},
	};
}
